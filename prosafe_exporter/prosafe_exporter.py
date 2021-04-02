import flask
import time
import requests
from lxml import html
import hashlib
import json
import os
import threading
import logging
import yaml
import argparse
import logging.config


class ProSafeExporter:
    def __init__(self, retrievers=[], logger=logging.getLogger()):
        self.logger = logger
        self.retrievers = retrievers

        self.app = flask.Flask('ProSafeExporter')
        self.app.add_url_rule('/probe', '/probe', self.__probe, methods=['POST', 'GET'])

    def run(self, host="0.0.0.0", port=9493, retrieveInterval=20.0, debug=False):
        if not debug:
            os.environ['WERKZEUG_RUN_MAIN'] = 'true'
            log = logging.getLogger('werkzeug')
            log.disabled = True

        webthread = threading.Thread(target=self.app.run, kwargs={'debug': debug, 'use_reloader': False, 'host': host, 'port': port})
        webthread.daemon = True
        webthread.start()
        self.logger.info('ProSafeExporter is listening on %s:%d for request on /probe endpoint', host, port)

        while True:
            self.__retrieve()
            time.sleep(retrieveInterval)

    def __probe(self):
        result = "# Exporter output\n\n"
        for retriever in self.retrievers:
            if retriever.error:
                result += '# ERROR: ' + retriever.error + '\n'
            else:
                result += retriever.result + '\n\n'
        self.logger.info('Request on endpoint /probe \n%s', result)
        return flask.Response(result, status=200, headers={})

    def __retrieve(self):
        self.logger.info('Retrieving data from all devies')
        for retriever in self.retrievers:
            try:
                retriever.retrieve()
                retriever.writeResult()
            except (ConnectionRefusedError, requests.exceptions.ConnectionError):
                pass
        self.logger.info('Retrieving done')


class ProSafeRetrieve:
    def __init__(self, hostname, password, cookiefile=None, logger=logging.getLogger()):
        self.logger = logger
        self.hostname = hostname
        self.password = password
        self.session = requests.Session()
        self.cookie = None
        self.cookiefile = cookiefile
        self.infos = None
        self.status = None
        self.statistics = None
        self.result = ""
        self.error = ""
        self.logger.info('Created retriever for host %s using cookiefile %s', self.hostname, self.cookiefile)

        if self.cookiefile:
            if os.path.isfile(self.cookiefile):
                with open(self.cookiefile, 'r') as f:
                    cookies = requests.utils.cookiejar_from_dict(json.load(f))
                    self.cookie = cookies
                    self.session.cookies.update(cookies)
                    self.logger.info('Using cookiefile %s', self.cookiefile)
            else:
                self.logger.error('Cannot use cookiefile %s', self.cookiefile)

    def __del__(self):
        if self.cookiefile:
            with open(self.cookiefile, 'w') as f:
                json.dump(requests.utils.dict_from_cookiejar(self.session.cookies), f)
                self.logger.info('Writing cookiefile %s', self.cookiefile)

    def __login(self):
        if self.cookie:
            indexPageRequest = self.session.post('http://'+self.hostname+'/index.htm')
            if 'RedirectToLoginPage' not in indexPageRequest.text:
                self.logger.info('Already logged in for %s', self.hostname)
                return
            else:
                self.logger.info('Have to login again for %s due to inactive session', self.hostname)
        loginPageRequest = self.session.post('http://'+self.hostname+'/login.htm')
        tree = html.fromstring(loginPageRequest.content)
        rand = tree.xpath('//input[@id="rand"]/@value[1]')
        if len(rand) != 1:
            self.error = 'I don t understand the firmware of the switch ' + self.hostname
            self.logger.error(self.error)
            raise ConnectionRefusedError(self.error)
        else:
            rand = rand[0]

            merged = ProSafeRetrieve.__merge(self.password, rand)
            password = hashlib.md5(str.encode(merged))

            payload = {
                'password': password.hexdigest(),
            }

            loginRequest = self.session.post('http://'+self.hostname+'/login.cgi', data=payload)
            tree = html.fromstring(loginRequest.content)
            errorMsg = tree.xpath('//input[@id="err_msg"]/@value[1]')
            if errorMsg and errorMsg[0]:
                self.error = 'I could not login at the switch ' + self.hostname + ' due to: ' + errorMsg[0]
                self.logger.error(self.error)
                raise ConnectionRefusedError(self.error)

    def retrieve(self):
        self.logger.info('Start retrieval for %s', self.hostname)

        self.error = ""
        self.infos = None
        self.status = None
        self.statistics = None
  
        try:
            self.__login()
            infoRequest = self.session.post('http://'+self.hostname+'/switch_info.htm')

            if 'RedirectToLoginPage' in infoRequest.text:
                self.error = 'Login failed for ' + self.hostname
                self.logger.error(self.error)
                raise ConnectionRefusedError(self.error)
            tree = html.fromstring(infoRequest.content)
            allinfos = tree.xpath('//table[@class="tableStyle"]//td[@nowrap=""]')
            allinfos = [allinfos[x:x+2] for x in range(0, len(allinfos), 2)]
            self.infos = dict()
            for info in allinfos:
                attribute = info[0].text

                if attribute in {'Produktname'}:
                    self.infos['product_name'] = info[1].text
                elif attribute in {'Switch-Name'}:
                    self.infos['switch_name'] = info[1].xpath('.//input[@type="text"]/@value')[0]
                elif attribute in {'Seriennummer'}:
                    self.infos['serial_number'] = info[1].text
                elif attribute in {'MAC-Adresse'}:
                    self.infos['mac_adresse'] = info[1].text
                elif attribute in {'Bootloader-Version'}:
                    self.infos['bootloader_version'] = info[1].text
                elif attribute in {'Firmwareversion'}:
                    self.infos['firmware_version'] = info[1].text
                elif attribute == "DHCP-Modus":
                    self.infos['dhcp_mode'] = info[1].xpath('.//input[@name="dhcp_mode"]/@value')[0]
                elif attribute in {'IP-Adresse'}:
                    self.infos['ip_adresse'] = info[1].xpath('.//input[@type="text"]/@value')[0]
                elif attribute in {'Subnetzmaske'}:
                    self.infos['subnetmask'] = info[1].xpath('.//input[@type="text"]/@value')[0]
                elif attribute in {'Gateway-Adresse'}:
                    self.infos['gateway_adresse'] = info[1].xpath('.//input[@type="text"]/@value')[0]

            statusRequest = self.session.post('http://' + self.hostname + '/status.htm')

            if 'RedirectToLoginPage' in statusRequest.text:
                self.error = 'Login failed for ' + self.hostname
                self.logger.error(self.error)
                raise ConnectionRefusedError(self.error)

            tree = html.fromstring(statusRequest.content)
            allports = tree.xpath('//tr[@class="portID"]/td[@sel="text"]/text()')
            allports = [x.strip() for x in allports] 
            self.status = [allports[x:x+4] for x in range(0, len(allports), 4)]

            statisticsRequest = self.session.post('http://' + self.hostname + '/port_statistics.htm')

            if 'RedirectToLoginPage' in statisticsRequest.text:
                self.error = 'Login failed for ' + self.hostname
                self.logger.error(self.error)
                raise ConnectionRefusedError(self.error)

            tree = html.fromstring(statisticsRequest.content)
            allports = tree.xpath('//tr[@class="portID"]/input[@type="hidden"]/@value')
            allports = [int(x, 16) for x in allports]
            self.statistics = [allports[x:x+3] for x in range(0, len(allports), 3)]
            self.logger.info('Retrieval for %s done', self.hostname)
        except requests.exceptions.ConnectionError:
            self.error = "Connection Error with host " + self.hostname
            self.logger.error(self.error)

    def writeResult(self):
        result = ""
        if self.infos and self.status and self.statistics:
            result += 'prosafe_switch_info{hostname="'+self.hostname+'", '
            for key, value in self.infos.items():
                result += key + '="' + value + '", '
            result += '} 1\n'
            for status in self.status:
                speedmap = {'Nicht verbunden': 0, '100M': 100, '1000M': 1000}
                result += 'prosafe_link_speed{hostname="' + self.hostname + '", port="' + status[0]+'"} ' + str(speedmap[status[2]]) + '\n'
                result += 'prosafe_max_mtu{hostname="' + self.hostname + '", port="' + status[0]+'"} ' + str(status[3]) + '\n'
            for port, statistic in enumerate(self.statistics, start=1):
                result += 'prosafe_prosafe_receive_bytes_total{hostname="' + self.hostname + '", port="' + str(port)+'"} ' + str(statistic[0]) + '\n'
                result += 'prosafe_prosafe_transmit_bytes_total{hostname="' + self.hostname + '", port="' + str(port)+'"} ' + str(statistic[1]) + '\n'
                result += 'prosafe_error_packets_total{hostname="' + self.hostname + '", port="' + str(port)+'"} ' + str(statistic[2]) + '\n'
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


def main():
    parser = argparse.ArgumentParser(description='Query Netgear ProSafe Switches using the web interface to provide statistics for Prometheus')
    parser.add_argument('config', type=argparse.FileType('r'), help='configuration')
    parser.add_argument("-v", "--verbose", help="increase output verbosity", action="store_true")
    args = parser.parse_args()

    config = yaml.load(args.config)

    logger = logging.getLogger('ProSafe_Exporter')
    logger.setLevel(logging.INFO)

    ch = logging.StreamHandler()

    if args.verbose:
        ch.setLevel(logging.INFO)
    else:
        ch.setLevel(logging.WARNING)

    # create formatter
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    # add formatter to ch
    ch.setFormatter(formatter)

    # add ch to logger
    logger.addHandler(ch)

    if 'global' not in config:
        config['global'] = dict()
    if 'host' not in config['global']:
        config['global']['host'] = '0.0.0.0'
    if 'port' not in config['global']:
        config['global']['port'] = 9493
    if 'retrieve_interval' not in config['global']:
        config['global']['retrieve_interval'] = 20.0

    if 'switches' not in config:
        logger.error('You have to define switches in the switches: section of your configuration')
        exit(1)

    retrievers = list()
    for switch in config['switches']:
        if 'hostname' not in switch:
            logger.error('You have to define the hostname for the switch, ignoring this switch entry')
            continue
        if 'password' not in switch:
            logger.error('You have to define the password for the switch, ignoring this switch entry')
            continue
        retrievers.append(ProSafeRetrieve(hostname=switch['hostname'], password=switch['password'], logger=logger))
    exporter = ProSafeExporter(retrievers=retrievers, logger=logger)
    exporter.run(host=config['global']['host'], port=config['global']['port'], retrieveInterval=config['global']['retrieve_interval'], debug=args.verbose)


if __name__ == "__main__": main()
