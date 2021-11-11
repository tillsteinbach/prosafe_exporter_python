#!/usr/local/bin/python3

import sys
import time
import socket
import hashlib
import json
import os
import threading
from datetime import datetime, timedelta
import logging
import logging.config
from multiprocessing import Lock
import argparse
import yaml
from lxml import html  # nosec risk is accepted, prosafe_exporter will be run mainly in private environments
import requests
import flask
from werkzeug.serving import make_server

from ._version import __version__

LOG_LEVELS = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
DEFAULT_LOG_LEVEL = "ERROR"

LOG = logging.getLogger("ProSafeExporter")

mutex = Lock()
speedmap = {'Nicht verbunden': '0', 'No Speed': '0', '10M': '10', '100M': '100', '1000M': '1000'}


class ProSafeExporter:
    def __init__(self, retrievers=None, retrieveInterval=20.0):
        self.retrievers = retrievers
        self.retrieveInterval = retrieveInterval
        self.lastRetrieve = None

        self.app = flask.Flask('ProSafeExporter')
        self.app.add_url_rule('/<path>', '/<path:path>',
                              self.__probe, methods=['POST', 'GET'])
        self.app.add_url_rule('/', '/', self.__probe, methods=['POST', 'GET'])

    def run(self, host="0.0.0.0", port=9493, loglevel=logging.INFO, endless=True):  # nosec
        os.environ['WERKZEUG_RUN_MAIN'] = 'true'
        log = logging.getLogger('werkzeug')
        log.setLevel(loglevel)

        server = make_server(host, port, self.app)

        webthread = threading.Thread(target=server.serve_forever)
        webthread.start()
        LOG.info('ProSafeExporter is listening on %s:%s for request on /metrics endpoint'
                 ' (but you can also use any other path)', host, port)

        try:
            self.__retrieve()
            while endless:  # pragma: no cover
                time.sleep(self.retrieveInterval)
                self.__retrieve()
        except KeyboardInterrupt:  # pragma: no cover
            pass
        server.shutdown()
        webthread.join()
        LOG.info('ProSafeExporter was stopped')

    def __probe(self, path=None):
        if self.lastRetrieve is not None \
                and self.lastRetrieve > datetime.now() - timedelta(seconds=(self.retrieveInterval * 5)):
            result = "# Exporter output\n\n"
            for retriever in self.retrievers:
                result += retriever.result + '\n\n'
            LOG.debug('Request on endpoint /%s \n%s', path, result)
            return flask.Response(result, status=200, headers={})
        return flask.Response('', status=503, headers={'Retry-After': self.retrieveInterval})

    def __retrieve(self):
        LOG.info('Retrieving data from all devies')
        for retriever in self.retrievers:
            try:
                retriever.retrieve()
            except (ConnectionRefusedError, requests.exceptions.ConnectionError):
                LOG.error(
                    'Failed to refrieve for host %s', retriever.hostname)
            self.lastRetrieve = datetime.now()
            retriever.writeResult()
        LOG.info('Retrieving done')


class ProSafeRetrieve:
    # pylint: disable=too-many-instance-attributes
    # 13 is reasonable in this case.

    def __init__(self,
                 hostname,
                 password,
                 cookiefile=None,
                 retries=10,
                 requestTimeout=10.0):
        self.retries = retries
        self.requestTimeout = requestTimeout
        self.hostname = hostname
        self.password = password
        self.__session = requests.Session()
        self.loggedIn = False
        self.cookieFile = None
        self.__infos = None
        self.__status = None
        self.__statistics = None
        self.result = ""
        self.error = ""

        if cookiefile:
            try:
                try:
                    with open(cookiefile, 'r', encoding='utf-8') as file:
                        cookies = requests.utils.cookiejar_from_dict(json.load(file))
                    self.__session.cookies.update(cookies)
                    self.loggedIn = True
                except json.JSONDecodeError as err:
                    LOG.info('Created retriever for host %s'
                             ' but could not use cookiefile %s (%s)', self.hostname, cookiefile, err.msg)
                except FileNotFoundError as err:
                    LOG.info('Created retriever for host %s'
                             ' but could not use cookiefile %s (%s)', self.hostname, cookiefile, err)
                self.cookieFile = cookiefile
                LOG.info('Created retriever for host %s using cookiefile %s', self.hostname, cookiefile)
            except OSError:  # pragma: no cover
                LOG.info('Created retriever for host %s'
                         ' but could not use cookiefile %s', self.hostname, cookiefile)
        else:
            LOG.info('Created retriever for host %s', self.hostname)

    def __del__(self):
        if self.cookieFile:
            try:
                with open(self.cookieFile, 'w', encoding='utf-8') as file:
                    json.dump(requests.utils.dict_from_cookiejar(self.__session.cookies), file)
                LOG.info('Writing cookiefile %s', self.cookieFile)
                self.__cookiefd = None
            except ValueError as err:  # pragma: no cover
                LOG.info('Could not write cookiefile %s for host %s (%s)',
                         self.__cookiefd.name, self.hostname, err)

    def __login(self):
        if self.loggedIn:
            indexPageRequest = self.__session.get(
                f'http://{self.hostname}/index.htm', timeout=self.requestTimeout)
            if 'RedirectToLoginPage' not in indexPageRequest.text:
                LOG.info('Already logged in for %s', self.hostname)
                return
            # lets start with a new session
            self.__session = requests.Session()
            self.loggedIn = False
            LOG.info('Have to login again for %s due to inactive session', self.hostname)
        loginPageRequest = self.__session.get(
            f'http://{self.hostname}/login.htm', timeout=self.requestTimeout)
        loginPageRequest.raise_for_status()

        tree = html.fromstring(loginPageRequest.content)
        rand = tree.xpath('//input[@id="rand"]/@value[1]')
        payload = None
        if len(rand) != 1:
            # looks like an old firmware without seed
            LOG.warning('Your switch %s uses an old firmware which sends your password'
                        ' unencrypted while retrieving data. Please conscider updating', self.hostname)

            payload = {
                'password': self.password,
            }
        else:
            rand = rand[0]

            merged = ProSafeRetrieve.__merge(self.password, rand)
            password = hashlib.md5(str.encode(merged))  # nosec unaviodable as demanded by firmware

            payload = {
                'password': password.hexdigest(),
            }

        loginRequest = self.__session.post(
            f'http://{self.hostname}/login.cgi', data=payload, timeout=self.requestTimeout)
        loginRequest.raise_for_status()

        tree = html.fromstring(loginRequest.content)
        errorMsg = tree.xpath('//input[@id="err_msg"]/@value[1]')
        if errorMsg and errorMsg[0]:
            self.error = f'I could not login at the switch {self.hostname} due to: {errorMsg[0]}'
            LOG.error(self.error)
            raise ConnectionRefusedError(self.error)
        self.loggedIn = True

    def __retrieveInfos(self):  # noqa: C901  pylint: disable=too-many-branches
        retries = self.retries
        while retries > 0:
            noProblem = True
            try:
                infoRequest = self.__session.get(f'http://{self.hostname}/switch_info.htm', timeout=self.requestTimeout)
                infoRequest.raise_for_status()
            except socket.timeout:
                noProblem = False

            if noProblem:
                if 'RedirectToLoginPage' in infoRequest.text:
                    self.error = 'Login failed for ' + self.hostname
                    LOG.error(self.error)
                    raise ConnectionRefusedError(self.error)
                tree = html.fromstring(infoRequest.content)
                allinfos = tree.xpath('//table[@class="tableStyle"]//td[@nowrap=""]')
                allinfos = [allinfos[x: x + 2] for x in range(0, len(allinfos), 2)]
                self.__infos = {}
                for info in allinfos:
                    if len(info) < 2:
                        noProblem = False
                        break
                    attribute = info[0].text

                    if attribute in {'Produktname', 'Product Name'}:
                        self.__infos['product_name'] = info[1].text
                    elif attribute in {'Switch-Name', 'Switch Name'}:
                        value = info[1].xpath('.//input[@type="text"]/@value')
                        if len(value) == 1:
                            self.__infos['switch_name'] = value[0]
                        else:
                            noProblem = False
                            break
                    elif attribute in {'Seriennummer', 'Serial Number'}:
                        self.__infos['serial_number'] = info[1].text
                    elif attribute in {'MAC-Adresse', 'MAC Address'}:
                        self.__infos['mac_adresse'] = info[1].text
                    elif attribute in {'Bootloader-Version'}:
                        self.__infos['bootloader_version'] = info[1].text
                    elif attribute in {'Firmwareversion', 'Firmware Version'}:
                        self.__infos['firmware_version'] = info[1].text
                    elif attribute in {'DHCP-Modus', 'DHCP Mode'}:
                        value = info[1].xpath('.//input[@name="dhcp_mode"]/@value')
                        if len(value) == 1:
                            self.__infos['dhcp_mode'] = value[0]
                        else:
                            noProblem = False
                            break
                    elif attribute in {'IP-Adresse', 'IP Address'}:
                        value = info[1].xpath('.//input[@type="text"]/@value')
                        if len(value) == 1:
                            self.__infos['ip_adresse'] = value[0]
                        else:
                            noProblem = False
                            break
                    elif attribute in {'Subnetzmaske', 'Subnet Mask'}:
                        value = info[1].xpath('.//input[@type="text"]/@value')
                        if len(value) == 1:
                            self.__infos['subnetmask'] = value[0]
                        else:
                            noProblem = False
                            break
                    elif attribute in {'Gateway-Adresse', 'Gateway Address'}:
                        value = info[1].xpath('.//input[@type="text"]/@value')
                        if len(value) == 1:
                            self.__infos['gateway_adresse'] = value[0]
                        else:
                            noProblem = False
                            break
                if noProblem:
                    return True
            retries -= 1
        self.__infos = None
        self.error = f'Could not retrieve correct switch_info for {self.hostname} after {self.retries}' \
                     ' retries. This can happen when there is much traffic on the device'
        LOG.error(self.error)
        return False

    def __retrieveStatus(self):  # noqa: C901
        retries = self.retries
        while retries > 0:
            noProblem = True
            try:
                statusRequest = self.__session.get(f'http://{self.hostname}/status.htm', timeout=self.requestTimeout)
                statusRequest.raise_for_status()
            except socket.timeout:
                noProblem = False

            if noProblem:
                if 'RedirectToLoginPage' in statusRequest.text:
                    self.error = 'Login failed for ' + self.hostname
                    LOG.error(self.error)
                    self.__infos = None
                    raise ConnectionRefusedError(self.error)

                tree = html.fromstring(statusRequest.content)
                allports = tree.xpath('//tr[@class="portID"]/td[@sel="text"]/text()')
                allports = [x.strip() for x in allports]
                self.__status = [allports[x: x + 4] for x in range(0, len(allports), 4)]

                for num, portStatus in enumerate(self.__status, start=1):
                    if len(portStatus) == 4:
                        # Check that number matches location in list
                        portCheck = portStatus[0].isnumeric() and int(portStatus[0]) == num
                        stateCheck = portStatus[1] in ['Aktiv', 'Inaktiv', 'Up', 'Down']
                        speedCheck = portStatus[2] in speedmap
                        # Conscider MTU always below 10k
                        mtuCheck = portStatus[3].isnumeric() and int(portStatus[3]) < 10000
                        noProblem = noProblem and portCheck and stateCheck and speedCheck and mtuCheck
                    else:
                        noProblem = False
                if noProblem:
                    # Rewrite speed
                    self.__status = [[speedmap[n] if i == 2 else n for i,
                                     n in enumerate(portStatus)] for portStatus in self.__status]
                    break
                # This might be a firmware that does not expose mtu. Try again with 3 fields:
                self.__status = [allports[x: x + 3] for x in range(0, len(allports), 3)]
                noProblem = True
                for num, portStatus in enumerate(self.__status, start=1):
                    if len(portStatus) == 3:
                        # Check that number matches location in list
                        portCheck = portStatus[0].isnumeric() and int(
                            portStatus[0]) == num
                        stateCheck = portStatus[1] in ['Aktiv', 'Inaktiv', 'Up', 'Down']
                        speedCheck = portStatus[2] in speedmap

                        noProblem = noProblem and portCheck and stateCheck and speedCheck
                    else:
                        noProblem = False
                if noProblem:
                    # Rewrite speed
                    self.__status = [[speedmap[n] if i == 2 else n for i,
                                     n in enumerate(portStatus)] for portStatus in self.__status]
                    break
            LOG.info('Problem while retrieving status for %s'
                     ' this can happen when there is much traffic on the device', self.hostname)
            retries -= 1
        if retries == 0:
            self.__status = None
            self.error = f'Could not retrieve correct status for {self.hostname} after {self.retries}' \
                ' retries. This can happen when there is much traffic on the device, but it is more likely' \
                ' that the firmware is not understood'
            LOG.error(self.error)
            return False
        return True

    def __retrieveStatistics(self):  # noqa: C901
        retries = self.retries
        while retries > 0:
            noProblem = True
            try:
                statisticsRequest = self.__session.get(
                    f'http://{self.hostname}/port_statistics.htm', timeout=self.requestTimeout)
                statisticsRequest.raise_for_status()
            # Retry on different URL
            except (requests.exceptions.ConnectionError, requests.exceptions.HTTPError):
                statisticsRequest = self.__session.get(
                    f'http://{self.hostname}/portStats.htm', timeout=self.requestTimeout)
                statisticsRequest.raise_for_status()
            except socket.timeout:
                noProblem = False

            if noProblem:
                if 'RedirectToLoginPage' in statisticsRequest.text:
                    self.error = f'Login failed for {self.hostname}'
                    LOG.error(self.error)
                    self.__infos = None
                    self.__status = None
                    raise ConnectionRefusedError(self.error)

                tree = html.fromstring(statisticsRequest.content)
                allports = tree.xpath('//tr[@class="portID"]/input[@type="hidden"]/@value')
                try:
                    allports = [str(int(x, 16)) for x in allports]
                except ValueError:
                    allports = []
                    noProblem = False

                # Some older firmware does not use the input fields
                if not allports and noProblem:
                    allports = tree.xpath('//tr[@class="portID"]/td[@class="def" and @sel="text"]/text()')
                    # In this case the value is not in hex, still casting to be sure we have a number
                    try:
                        allports = [str(int(x)) for x in allports]
                    except ValueError:
                        allports = []
                        noProblem = False

                self.__statistics = [allports[x: x + 3] for x in range(0, len(allports), 3)]

                for _, portStatistics in enumerate(self.__statistics, start=1):
                    if len(portStatistics) != 3:
                        noProblem = False
                if noProblem:
                    break
            LOG.info('Problem while retrieving statistics for %s'
                     ' this can happen when there is much traffic on the device', self.hostname)
            retries -= 1
        if retries == 0:
            self.__statistics = None
            self.error = f'Could not retrieve correct statistics for {self.hostname} after {self.retries} retries.' \
                ' This can happen when there is much traffic on the device'
            LOG.error(self.error)
            return False
        return True

    def retrieve(self):
        LOG.info('Start retrieval for %s', self.hostname)

        with mutex:
            self.error = ""
            self.__infos = None
            self.__status = None
            self.__statistics = None

            try:
                self.__login()
                hasInfos = self.__retrieveInfos()
                if not hasInfos:
                    return
                hasStatus = self.__retrieveStatus()
                if not hasStatus:
                    return
                hasStatistics = self.__retrieveStatistics()
                if not hasStatistics:
                    return

                # Check plausibility
                if len(self.__status) != len(self.__statistics) or not self.__status:
                    self.__status = None
                    self.__statistics = None
                    self.error = f'Result is not  plausible for {self.hostname}' \
                        ' Different number of ports for statistics and status. This can happen when there is much' \
                        ' traffic on the device'
                    LOG.error(self.error)
                    return

                LOG.info('Retrieval for %s done', self.hostname)

            except (requests.exceptions.ConnectionError, requests.exceptions.HTTPError):
                self.__infos = None
                self.__status = None
                self.__statistics = None
                self.error = f'Connection Error with host {self.hostname}'
                LOG.error(self.error)

    def writeResult(self):  # noqa: C901
        result = ""
        with mutex:
            if self.error:
                result += f'# ERROR: {self.error}\n'
            if self.__infos and self.__status and self.__statistics:
                result += '\n# HELP prosafe_switch_info All configuration items collected. This is always 1 and only' \
                    ' used to collect labels\n'
                result += '# TYPE prosafe_switch_info gauge\n'
                result += f'prosafe_switch_info{{hostname="{self.hostname}", ' \
                    + ", ".join([f'{key}="{value}"' for key, value in self.__infos.items()]) \
                    + '} 1\n'
                result += '\n# HELP prosafe_link_speed Link speed of the port in MBit, 0 means unconnected\n'
                result += '# TYPE prosafe_link_speed gauge\n'
                result += '# UNIT prosafe_link_speed megabit per second\n'
                for status in self.__status:
                    if len(status) >= 3:
                        result += f'prosafe_link_speed{{hostname="{self.hostname}", port="{status[0]}"}} {status[2]}\n'
                result += '\n# HELP prosafe_max_mtu Maximum MTU set for the port in Byte\n'
                result += '# TYPE prosafe_max_mtu gauge\n'
                result += '# UNIT prosafe_max_mtu bytes\n'
                for status in self.__status:
                    if len(status) >= 4:
                        result += f'prosafe_max_mtu{{hostname="{self.hostname}", port="{status[0]}"}} {status[3]}\n'
                result += '\n# HELP prosafe_receive_bytes_total Received bytes at port\n'
                result += '# TYPE prosafe_receive_bytes_total counter\n'
                result += '# UNIT prosafe_receive_bytes_total bytes\n'
                for port, statistic in enumerate(self.__statistics, start=1):
                    if len(statistic) >= 1:
                        result += f'prosafe_receive_bytes_total{{hostname="{self.hostname}", port="{port}"}}' \
                            f' {statistic[0]}\n'
                result += '\n# HELP prosafe_transmit_bytes_total Transmitted bytes at port\n'
                result += '# TYPE prosafe_transmit_bytes_total counter\n'
                result += '# UNIT prosafe_transmit_bytes_total bytes\n'
                for port, statistic in enumerate(self.__statistics, start=1):
                    if len(statistic) >= 2:
                        result += f'prosafe_transmit_bytes_total{{hostname="{self.hostname}", port="{port}"}}' \
                            f' {statistic[1]}\n'
                result += '\n# HELP prosafe_error_packets_total Error bytes at port\n'
                result += '# TYPE prosafe_error_packets_total counter\n'
                result += '# UNIT prosafe_error_packets_total bytes\n'
                for port, statistic in enumerate(self.__statistics, start=1):
                    if len(statistic) >= 3:
                        result += f'prosafe_error_packets_total{{hostname="{self.hostname}", port="{port}"}}' \
                            f' {statistic[2]}\n'
            self.result = result

    @staticmethod
    def __merge(str1, str2):
        arr1 = list(str1)
        arr2 = list(str2)
        result = ""
        index1 = 0
        index2 = 0
        while (index1 < len(arr1) or index2 < len(arr2)):
            if index1 < len(arr1):
                result += arr1[index1]
                index1 += 1
            if index2 < len(arr2):
                result += arr2[index2]
                index2 += 1
        return result


def main(endless=True, always_early_timeout=False):  # noqa: C901
    parser = argparse.ArgumentParser(
        prog='prosafe_exporter',
        description='Query Netgear ProSafe Switches using the web interface to provide statistics for Prometheus')
    parser.add_argument('config', type=argparse.FileType(
        'r'), help='configuration')
    parser.add_argument('-v', '--verbose', action="append_const", const=-1,)
    parser.add_argument('--version', action='version', version=f'%(prog)s {__version__}')
    args = parser.parse_args()

    logLevel = LOG_LEVELS.index(DEFAULT_LOG_LEVEL)
    for adjustment in args.verbose or ():
        logLevel = min(len(LOG_LEVELS) - 1, max(logLevel + adjustment, 0))

    logging.basicConfig(level=LOG_LEVELS[logLevel])

    config = yaml.load(args.config, Loader=yaml.SafeLoader)
    if not config:
        LOG.error('Config empty or cannot be parsed')
        sys.exit(3)

    if 'global' not in config:
        config['global'] = {}
    if 'host' not in config['global']:
        config['global']['host'] = '0.0.0.0'  # nosec
    if 'port' not in config['global']:
        config['global']['port'] = 9493
    if 'retrieve_interval' not in config['global']:
        config['global']['retrieve_interval'] = 20.0
    if 'retrieve_timeout' not in config['global']:
        config['global']['retrieve_timeout'] = 10.0
    if 'retries' not in config['global']:
        config['global']['retries'] = 10

    if 'switches' not in config or not config['switches']:
        LOG.error(
            'You have to define switches in the switches: section of your configuration')
        sys.exit(4)

    if always_early_timeout:  # pragma: no cover
        config['global']['retrieve_timeout'] = 0.001

    retrievers = []
    for switch in config['switches']:
        if 'hostname' not in switch:
            LOG.error(
                'You have to define the hostname for the switch, ignoring this switch entry')
            continue
        if 'password' not in switch:
            LOG.error(
                'You have to define the password for the switch, ignoring this switch entry')
            continue
        if 'cookiefile' not in switch:
            switch['cookiefile'] = None
        retrievers.append(
            ProSafeRetrieve(
                hostname=switch['hostname'],
                password=switch['password'],
                retries=config['global']['retries'],
                requestTimeout=config['global']['retrieve_timeout'],
                cookiefile=switch['cookiefile']))
    exporter = ProSafeExporter(retrievers=retrievers, retrieveInterval=config['global']['retrieve_interval'])
    exporter.run(host=config['global']['host'], port=config['global']['port'],
                 loglevel=LOG_LEVELS[logLevel], endless=endless)
    # Cleanup
    del exporter
    retrievers.clear()
    sys.exit(0)
