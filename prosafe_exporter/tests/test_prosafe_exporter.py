import sys
import os.path
import re
import pytest

import logging

from prosafe_exporter.prosafe_exporter import ProSafeRetrieve, main


@pytest.fixture(autouse=True)
def loggerCleanup():
    yield
    loggers = [logging.getLogger()] + list(logging.Logger.manager.loggerDict.values())
    for logger in loggers:
        handlers = getattr(logger, 'handlers', [])
        for handler in handlers:
            logger.removeHandler(handler)


@pytest.fixture(scope="session")
def httpserver_listen_address():
    return ("localhost", 8888)


@pytest.fixture
def retriever():
    logger = logging.getLogger('ProSafe_Exporter')

    retriever = ProSafeRetrieve(
                hostname='localhost:8888',
                password='password',
                logger=logger,
                retries=2)
    yield retriever


def checkInfos(infos, firmware):
    assert infos['product_name'] == 'GS108Ev3'
    assert infos['switch_name'] == 'MyFancySwitch'
    assert infos['serial_number'] == '123456789'
    assert infos['mac_adresse'] == '00:11:22:33:44:55'
    assert infos['firmware_version'] == firmware
    assert infos['dhcp_mode'] == '0'
    assert infos['ip_adresse'] == '1.2.3.4'
    assert infos['subnetmask'] == '255.255.255.255'
    assert infos['gateway_adresse'] == '1.2.3.4'


def checkStatus(status, firmware):
    assert len(status) == 8
    assert status[0][2] == '0'
    if firmware in ['V2.06.14GR', 'V2.06.14EN']:
        assert status[0][3] == '9702'
    assert status[1][2] == '10'
    if firmware in ['V2.06.14GR', 'V2.06.14EN']:
        assert status[1][3] == '0'
    assert status[2][2] == '100'
    if firmware in ['V2.06.14GR', 'V2.06.14EN']:
        assert status[2][3] == '100'
    assert status[3][2] == status[4][2] == status[5][2] == status[6][2] == status[7][2] == '1000'
    if firmware in ['V2.06.14GR', 'V2.06.14EN']:
        assert status[3][3] == status[4][3] == status[5][3] == status[6][3] == status[7][3] == '1000'


def checkStatistics(statistics, firmware):
    assert len(statistics) == 8
    assert statistics[0][0] == statistics[0][1] == statistics[0][2] == '0'
    assert statistics[1][0] == statistics[1][1] == statistics[1][2] == '1'
    assert statistics[2][0] == statistics[2][1] == statistics[2][2] == '15'
    assert statistics[3][0] == statistics[3][1] == statistics[3][2] == '4294967295'
    assert statistics[4][0] == statistics[4][1] == statistics[4][2] == '18446744073709551615'
    assert statistics[5][0] == statistics[5][1] == statistics[5][2] == '0'
    assert statistics[6][0] == statistics[6][1] == statistics[6][2] == '0'
    assert statistics[7][0] == statistics[7][1] == statistics[7][2] == '0'


def test_serverUnreachable(retriever):
    retriever.retrieve()
    assert retriever.error == 'Connection Error with host ' + retriever.hostname
    retriever.writeResult()
    assert retriever.result == '# ERROR: ' + retriever.error + '\n'


@pytest.mark.parametrize('firmware', [('V2.06.14GR'), ('V2.06.14EN'), ('V2.06.03EN')])
def test_standardRequestGood(retriever, firmware,  httpserver):
    with open('tests/responses/'+firmware+'/good/login.htm', 'r') as f:
        httpserver.expect_ordered_request("/login.htm", method='GET').respond_with_data(f.readlines())
    with open('tests/responses/'+firmware+'/good/login.htm', 'r') as f:
        # TODO Check password
        httpserver.expect_ordered_request("/login.cgi", method='POST').respond_with_data(f.readlines())
    with open('tests/responses/'+firmware+'/good/switch_info.htm', 'r') as f:
        httpserver.expect_ordered_request("/switch_info.htm", method='GET').respond_with_data(f.readlines())
    with open('tests/responses/'+firmware+'/good/status.htm', 'r') as f:
        httpserver.expect_ordered_request("/status.htm", method='GET').respond_with_data(f.readlines())
    if firmware in ['V2.06.14EN']:
        httpserver.expect_ordered_request("/port_statistics.htm", method='GET').respond_with_data('', status=500)
        with open('tests/responses/'+firmware+'/good/portStats.htm', 'r') as f:
            httpserver.expect_ordered_request("/portStats.htm", method='GET').respond_with_data(f.readlines())
    else:
        with open('tests/responses/'+firmware+'/good/port_statistics.htm', 'r') as f:
            httpserver.expect_ordered_request("/port_statistics.htm", method='GET').respond_with_data(f.readlines())
    retriever.retrieve()

    checkInfos(retriever.infos, firmware)
    checkStatus(retriever.status, firmware)
    checkStatistics(retriever.statistics, firmware)

    httpserver.check_assertions()

    retriever.writeResult()


@pytest.mark.parametrize('firmware', [('V2.06.14GR'), ('V2.06.14EN'), ('V2.06.03EN')])
def test_loginError(retriever, firmware,  httpserver):
    with open('tests/responses/'+firmware+'/good/login.htm', 'r') as f:
        httpserver.expect_ordered_request("/login.htm", method='GET').respond_with_data(f.readlines())
    with open('tests/responses/'+firmware+'/bad/login.cgi_error', 'r') as f:
        httpserver.expect_ordered_request("/login.cgi", method='POST').respond_with_data(f.readlines())

    with pytest.raises(ConnectionRefusedError) as pytest_wrapped_error:
        retriever.retrieve()

    httpserver.check_assertions()

    assert retriever.infos is None and retriever.status is None and retriever.statistics is None
    if firmware in ['V2.06.14GR']:
        assert retriever.error == 'I could not login at the switch ' + \
            retriever.hostname + ' due to: Das Passwort ist ungültig.'
    else:
        assert retriever.error == 'I could not login at the switch ' + \
            retriever.hostname + ' due to: The password is invalid.'

    retriever.writeResult()
    assert retriever.result == '# ERROR: ' + retriever.error + '\n'


@pytest.mark.parametrize('firmware', [('V2.06.03EN')])
def test_oneTXMissing(retriever, firmware,  httpserver):
    with open('tests/responses/'+firmware+'/good/login.htm', 'r') as f:
        httpserver.expect_ordered_request("/login.htm", method='GET').respond_with_data(f.readlines())
    with open('tests/responses/'+firmware+'/good/login.htm', 'r') as f:
        httpserver.expect_ordered_request("/login.cgi", method='POST').respond_with_data(f.readlines())
    with open('tests/responses/'+firmware+'/good/switch_info.htm', 'r') as f:
        httpserver.expect_ordered_request("/switch_info.htm", method='GET').respond_with_data(f.readlines())
    with open('tests/responses/'+firmware+'/good/status.htm', 'r') as f:
        httpserver.expect_ordered_request("/status.htm", method='GET').respond_with_data(f.readlines())
    if firmware in ['V2.06.14EN']:
        httpserver.expect_ordered_request("/port_statistics.htm", method='GET').respond_with_data('', status=500)
        with open('tests/responses/'+firmware+'/bad/portStats.htm_oneTXMissing', 'r') as f:
            badResponse = f.readlines()
            httpserver.expect_ordered_request("/portStats.htm", method='GET').respond_with_data(badResponse)
            httpserver.expect_ordered_request("/portStats.htm", method='GET').respond_with_data(badResponse)
    else:
        with open('tests/responses/'+firmware+'/bad/port_statistics.htm_oneTXMissing', 'r') as f:
            badResponse = f.readlines()
            httpserver.expect_ordered_request("/port_statistics.htm", method='GET').respond_with_data(badResponse)
            httpserver.expect_ordered_request("/port_statistics.htm", method='GET').respond_with_data(badResponse)
    retriever.retrieve()

    checkInfos(retriever.infos, firmware)

    assert retriever.status is None and retriever.statistics is None
    assert retriever.error == 'Result is not  plausible for ' + retriever.hostname + \
                              ' Different number of ports for statistics and status. This can happen when there is' \
                              ' much traffic on the device'

    httpserver.check_assertions()

    retriever.writeResult()
    assert retriever.result == '# ERROR: ' + retriever.error + '\n'


@pytest.mark.parametrize('firmware', [('V2.06.03EN')])
def test_firstPortMissing(retriever, firmware,  httpserver):
    with open('tests/responses/'+firmware+'/good/login.htm', 'r') as f:
        httpserver.expect_ordered_request("/login.htm", method='GET').respond_with_data(f.readlines())
    with open('tests/responses/'+firmware+'/good/login.htm', 'r') as f:
        httpserver.expect_ordered_request("/login.cgi", method='POST').respond_with_data(f.readlines())
    with open('tests/responses/'+firmware+'/good/switch_info.htm', 'r') as f:
        httpserver.expect_ordered_request("/switch_info.htm", method='GET').respond_with_data(f.readlines())
    with open('tests/responses/'+firmware+'/good/status.htm', 'r') as f:
        httpserver.expect_ordered_request("/status.htm", method='GET').respond_with_data(f.readlines())
    if firmware in ['V2.06.14EN']:
        httpserver.expect_ordered_request("/port_statistics.htm", method='GET').respond_with_data('', status=500)
        with open('tests/responses/'+firmware+'/bad/portStats.htm_firstPortMissing', 'r') as f:
            httpserver.expect_ordered_request("/portStats.htm", method='GET').respond_with_data(f.readlines())
        with open('tests/responses/'+firmware+'/good/portStats.htm', 'r') as f:
            httpserver.expect_ordered_request("/portStats.htm", method='GET').respond_with_data(f.readlines())
    else:
        with open('tests/responses/'+firmware+'/bad/port_statistics.htm_firstPortMissing', 'r') as f:
            httpserver.expect_ordered_request("/port_statistics.htm", method='GET').respond_with_data(f.readlines())
        with open('tests/responses/'+firmware+'/good/port_statistics.htm', 'r') as f:
            httpserver.expect_ordered_request("/port_statistics.htm", method='GET').respond_with_data(f.readlines())
    retriever.retrieve()

    checkInfos(retriever.infos, firmware)
    checkStatus(retriever.status, firmware)
    checkStatistics(retriever.statistics, firmware)

    httpserver.check_assertions()

    retriever.writeResult()


@pytest.mark.parametrize('firmware', [('V2.06.03EN')])
def test_lastPortMissing(retriever, firmware,  httpserver):
    with open('tests/responses/'+firmware+'/good/login.htm', 'r') as f:
        httpserver.expect_ordered_request("/login.htm", method='GET').respond_with_data(f.readlines())
    with open('tests/responses/'+firmware+'/good/login.htm', 'r') as f:
        httpserver.expect_ordered_request("/login.cgi", method='POST').respond_with_data(f.readlines())
    with open('tests/responses/'+firmware+'/good/switch_info.htm', 'r') as f:
        httpserver.expect_ordered_request("/switch_info.htm", method='GET').respond_with_data(f.readlines())
    with open('tests/responses/'+firmware+'/good/status.htm', 'r') as f:
        httpserver.expect_ordered_request("/status.htm", method='GET').respond_with_data(f.readlines())
    if firmware in ['V2.06.14EN']:
        httpserver.expect_ordered_request("/port_statistics.htm", method='GET').respond_with_data('', status=500)
        with open('tests/responses/'+firmware+'/bad/portStats.htm_lastPortMissing', 'r') as f:
            httpserver.expect_ordered_request("/portStats.htm", method='GET').respond_with_data(f.readlines())
        with open('tests/responses/'+firmware+'/good/portStats.htm', 'r') as f:
            httpserver.expect_ordered_request("/portStats.htm", method='GET').respond_with_data(f.readlines())
    else:
        with open('tests/responses/'+firmware+'/bad/port_statistics.htm_lastPortMissing', 'r') as f:
            httpserver.expect_ordered_request("/port_statistics.htm", method='GET').respond_with_data(f.readlines())
        with open('tests/responses/'+firmware+'/good/port_statistics.htm', 'r') as f:
            httpserver.expect_ordered_request("/port_statistics.htm", method='GET').respond_with_data(f.readlines())
    retriever.retrieve()

    checkInfos(retriever.infos, firmware)
    checkStatus(retriever.status, firmware)
    checkStatistics(retriever.statistics, firmware)

    httpserver.check_assertions()

    retriever.writeResult()


@pytest.mark.parametrize('firmware', [('V2.06.03EN')])
@pytest.mark.parametrize('retry', ['login_get', 'login_post', 'switch_info', 'status', 'statistics'])
def test_retry(retriever, firmware, retry, httpserver):
    if retry == 'login_get':
        httpserver.expect_ordered_request("/login.htm", method='GET').respond_with_data('', status=500)
        with open('tests/responses/'+firmware+'/good/login.htm', 'r') as f:
            httpserver.expect_ordered_request("/login.htm", method='GET').respond_with_data(f.readlines())
    else:
        with open('tests/responses/'+firmware+'/good/login.htm', 'r') as f:
            httpserver.expect_ordered_request("/login.htm", method='GET').respond_with_data(f.readlines())

    if retry == 'login_post':
        with open('tests/responses/'+firmware+'/good/login.htm', 'r') as f:
            httpserver.expect_ordered_request("/login.cgi", method='POST').respond_with_data('', status=500)
    elif retry not in ['login_get']:
        with open('tests/responses/'+firmware+'/good/login.htm', 'r') as f:
            httpserver.expect_ordered_request("/login.cgi", method='POST').respond_with_data(f.readlines())

    if retry == 'switch_info':
        with open('tests/responses/'+firmware+'/good/switch_info.htm', 'r') as f:
            httpserver.expect_ordered_request("/switch_info.htm", method='GET').respond_with_data('', status=500)
    elif retry not in ['login_get', 'login_post']:
        with open('tests/responses/'+firmware+'/good/switch_info.htm', 'r') as f:
            httpserver.expect_ordered_request("/switch_info.htm", method='GET').respond_with_data(f.readlines())

    if retry == 'status':
        with open('tests/responses/'+firmware+'/good/status.htm', 'r') as f:
            httpserver.expect_ordered_request("/status.htm", method='GET').respond_with_data('', status=500)
    elif retry not in ['login_get', 'login_post', 'switch_info']:
        with open('tests/responses/'+firmware+'/good/status.htm', 'r') as f:
            httpserver.expect_ordered_request("/status.htm", method='GET').respond_with_data(f.readlines())

    if retry == 'statistics':
        with open('tests/responses/'+firmware+'/good/port_statistics.htm', 'r') as f:
            httpserver.expect_ordered_request("/port_statistics.htm", method='GET').respond_with_data('', status=500)
            httpserver.expect_ordered_request("/portStats.htm", method='GET').respond_with_data('', status=500)
    elif retry not in ['login_get', 'login_post', 'switch_info', 'status']:
        with open('tests/responses/'+firmware+'/good/port_statistics.htm', 'r') as f:
            httpserver.expect_ordered_request("/port_statistics.htm", method='GET').respond_with_data(f.readlines())

    retriever.retrieve()

    assert retriever.infos is None and retriever.status is None and retriever.statistics is None
    assert retriever.error == "Connection Error with host " + retriever.hostname

    retriever.writeResult()
    assert retriever.result == '# ERROR: ' + retriever.error + '\n'


@pytest.mark.parametrize('firmware', [('V2.06.03EN')])
@pytest.mark.parametrize('redirect', ['switch_info', 'status', 'statistics'])
def test_redirect(retriever, firmware, redirect, httpserver):
    with open('tests/responses/'+firmware+'/good/login.htm', 'r') as f:
        httpserver.expect_ordered_request("/login.htm", method='GET').respond_with_data(f.readlines())
    with open('tests/responses/'+firmware+'/good/login.htm', 'r') as f:
        httpserver.expect_ordered_request("/login.cgi", method='POST').respond_with_data(f.readlines())
    if redirect in ['switch_info']:
        with open('tests/responses/'+firmware+'/good/index.htm_redirect', 'r') as f:
            httpserver.expect_ordered_request("/switch_info.htm", method='GET').respond_with_data(f.readlines())
    else:
        with open('tests/responses/'+firmware+'/good/switch_info.htm', 'r') as f:
            httpserver.expect_ordered_request("/switch_info.htm", method='GET').respond_with_data(f.readlines())
    if redirect in ['status']:
        with open('tests/responses/'+firmware+'/good/index.htm_redirect', 'r') as f:
            httpserver.expect_ordered_request("/status.htm", method='GET').respond_with_data(f.readlines())
    else:
        with open('tests/responses/'+firmware+'/good/status.htm', 'r') as f:
            httpserver.expect_ordered_request("/status.htm", method='GET').respond_with_data(f.readlines())
    if redirect in ['statistics']:
        if firmware in ['V2.06.14EN']:
            httpserver.expect_ordered_request("/port_statistics.htm", method='GET').respond_with_data('', status=500)
            with open('tests/responses/'+firmware+'/good/index.htm_redirect', 'r') as f:
                httpserver.expect_ordered_request("/portStats.htm", method='GET').respond_with_data(f.readlines())
        else:
            with open('tests/responses/'+firmware+'/good/index.htm_redirect', 'r') as f:
                httpserver.expect_ordered_request("/port_statistics.htm", method='GET').respond_with_data(f.readlines())
    else:
        if firmware in ['V2.06.14EN']:
            httpserver.expect_ordered_request("/port_statistics.htm", method='GET').respond_with_data('', status=500)
            with open('tests/responses/'+firmware+'/good/portStats.htm', 'r') as f:
                httpserver.expect_ordered_request("/portStats.htm", method='GET').respond_with_data(f.readlines())
        else:
            with open('tests/responses/'+firmware+'/good/port_statistics.htm', 'r') as f:
                httpserver.expect_ordered_request("/port_statistics.htm", method='GET').respond_with_data(f.readlines())

    with pytest.raises(ConnectionRefusedError) as pytest_wrapped_error:
        retriever.retrieve()

    assert retriever.error == 'Login failed for ' + retriever.hostname
    assert retriever.infos is None and retriever.status is None and retriever.statistics is None


@pytest.mark.parametrize('firmware', [('V2.06.14GR'), ('V2.06.03EN')])
@pytest.mark.parametrize('vectorLengthZero', [True, False])
def test_write(retriever, firmware, vectorLengthZero):
    retriever.infos = dict()
    retriever.infos['product_name'] = 'GS108Ev3'
    retriever.infos['switch_name'] = 'MyFancySwitch'
    retriever.infos['serial_number'] = '123456789'
    retriever.infos['mac_adresse'] = '00:11:22:33:44:55'
    retriever.infos['firmware_version'] = '0.1.2ABC'
    retriever.infos['dhcp_mode'] = '0'
    retriever.infos['ip_adresse'] = '1.2.3.4'
    retriever.infos['subnetmask'] = '255.255.255.255'
    retriever.infos['gateway_adresse'] = '1.2.3.4'
    if firmware in ['V2.06.03EN']:
        if vectorLengthZero:
            retriever.status = [[] for x in range(1, 9)]
        else:
            retriever.status = [[str(x), 'Active', '2'] for x in range(1, 9)]
    else:
        if vectorLengthZero:
            retriever.status = [[] for x in range(1, 9)]
        else:
            retriever.status = [[str(x), 'Active', '2', str(x*1000)] for x in range(1, 9)]
    if vectorLengthZero:
        retriever.statistics = [[] for x in range(1, 9)]
    else:
        retriever.statistics = [[str(x*1), str(x*100), str(x*1000)] for x in range(1, 9)]

    retriever.writeResult()
    resultString = '\n' \
        '# HELP prosafe_switch_info All configuration items collected. This is always 1 and only used to collect' \
        ' labels\n' \
        '# TYPE prosafe_switch_info gauge\n' \
        'prosafe_switch_info{hostname="' + retriever.hostname + '", product_name="' \
        + retriever.infos['product_name'] + '", switch_name="' \
        + retriever.infos['switch_name'] + '", serial_number="' \
        + retriever.infos['serial_number'] + '", mac_adresse="' \
        + retriever.infos['mac_adresse'] + '", firmware_version="' \
        + retriever.infos['firmware_version'] + '", dhcp_mode="' \
        + retriever.infos['dhcp_mode'] + '", ip_adresse="' \
        + retriever.infos['ip_adresse'] + '", subnetmask="' \
        + retriever.infos['subnetmask'] + '", gateway_adresse="' \
        + retriever.infos['gateway_adresse'] + '", } 1\n' \
        '\n' \
        '# HELP prosafe_link_speed Link speed of the port in MBit, 0 means unconnected\n' \
        '# TYPE prosafe_link_speed gauge\n' \
        '# UNIT prosafe_link_speed megabit per second\n'
    if not vectorLengthZero:
        resultString += 'prosafe_link_speed{hostname="' + retriever.hostname + '", port="1"} 2\n' \
            'prosafe_link_speed{hostname="' + retriever.hostname + '", port="2"} 2\n' \
            'prosafe_link_speed{hostname="' + retriever.hostname + '", port="3"} 2\n' \
            'prosafe_link_speed{hostname="' + retriever.hostname + '", port="4"} 2\n' \
            'prosafe_link_speed{hostname="' + retriever.hostname + '", port="5"} 2\n' \
            'prosafe_link_speed{hostname="' + retriever.hostname + '", port="6"} 2\n' \
            'prosafe_link_speed{hostname="' + retriever.hostname + '", port="7"} 2\n' \
            'prosafe_link_speed{hostname="' + retriever.hostname + '", port="8"} 2\n'
    resultString += '\n' \
        '# HELP prosafe_max_mtu Maximum MTU set for the port in Byte\n' \
        '# TYPE prosafe_max_mtu gauge\n' \
        '# UNIT prosafe_max_mtu bytes\n'
    if firmware not in ['V2.06.03EN'] and not vectorLengthZero:
        resultString += 'prosafe_max_mtu{hostname="' + retriever.hostname + '", port="1"} 1000\n' \
            'prosafe_max_mtu{hostname="' + retriever.hostname + '", port="2"} 2000\n' \
            'prosafe_max_mtu{hostname="' + retriever.hostname + '", port="3"} 3000\n' \
            'prosafe_max_mtu{hostname="' + retriever.hostname + '", port="4"} 4000\n' \
            'prosafe_max_mtu{hostname="' + retriever.hostname + '", port="5"} 5000\n' \
            'prosafe_max_mtu{hostname="' + retriever.hostname + '", port="6"} 6000\n' \
            'prosafe_max_mtu{hostname="' + retriever.hostname + '", port="7"} 7000\n' \
            'prosafe_max_mtu{hostname="' + retriever.hostname + '", port="8"} 8000\n'

    resultString += '\n'
    resultString += '# HELP prosafe_receive_bytes_total Received bytes at port\n' \
        '# TYPE prosafe_receive_bytes_total counter\n' \
        '# UNIT prosafe_receive_bytes_total bytes\n'
    if not vectorLengthZero:
        resultString += 'prosafe_receive_bytes_total{hostname="' + retriever.hostname + '", port="1"} 1\n' \
            'prosafe_receive_bytes_total{hostname="' + retriever.hostname + '", port="2"} 2\n' \
            'prosafe_receive_bytes_total{hostname="' + retriever.hostname + '", port="3"} 3\n' \
            'prosafe_receive_bytes_total{hostname="' + retriever.hostname + '", port="4"} 4\n' \
            'prosafe_receive_bytes_total{hostname="' + retriever.hostname + '", port="5"} 5\n' \
            'prosafe_receive_bytes_total{hostname="' + retriever.hostname + '", port="6"} 6\n' \
            'prosafe_receive_bytes_total{hostname="' + retriever.hostname + '", port="7"} 7\n' \
            'prosafe_receive_bytes_total{hostname="' + retriever.hostname + '", port="8"} 8\n'
    resultString += '\n' \
        '# HELP prosafe_transmit_bytes_total Transmitted bytes at port\n' \
        '# TYPE prosafe_transmit_bytes_total counter\n' \
        '# UNIT prosafe_transmit_bytes_total bytes\n'
    if not vectorLengthZero:
        resultString += 'prosafe_transmit_bytes_total{hostname="' + retriever.hostname + '", port="1"} 100\n' \
            'prosafe_transmit_bytes_total{hostname="' + retriever.hostname + '", port="2"} 200\n' \
            'prosafe_transmit_bytes_total{hostname="' + retriever.hostname + '", port="3"} 300\n' \
            'prosafe_transmit_bytes_total{hostname="' + retriever.hostname + '", port="4"} 400\n' \
            'prosafe_transmit_bytes_total{hostname="' + retriever.hostname + '", port="5"} 500\n' \
            'prosafe_transmit_bytes_total{hostname="' + retriever.hostname + '", port="6"} 600\n' \
            'prosafe_transmit_bytes_total{hostname="' + retriever.hostname + '", port="7"} 700\n' \
            'prosafe_transmit_bytes_total{hostname="' + retriever.hostname + '", port="8"} 800\n'
    resultString += '\n' \
        '# HELP prosafe_error_packets_total Error bytes at port\n' \
        '# TYPE prosafe_error_packets_total counter\n' \
        '# UNIT prosafe_error_packets_total bytes\n'
    if not vectorLengthZero:
        resultString += 'prosafe_error_packets_total{hostname="' + retriever.hostname + '", port="1"} 1000\n' \
            'prosafe_error_packets_total{hostname="' + retriever.hostname + '", port="2"} 2000\n' \
            'prosafe_error_packets_total{hostname="' + retriever.hostname + '", port="3"} 3000\n' \
            'prosafe_error_packets_total{hostname="' + retriever.hostname + '", port="4"} 4000\n' \
            'prosafe_error_packets_total{hostname="' + retriever.hostname + '", port="5"} 5000\n' \
            'prosafe_error_packets_total{hostname="' + retriever.hostname + '", port="6"} 6000\n' \
            'prosafe_error_packets_total{hostname="' + retriever.hostname + '", port="7"} 7000\n' \
            'prosafe_error_packets_total{hostname="' + retriever.hostname + '", port="8"} 8000\n'
    assert retriever.result == resultString
    assert retriever.error == ''


@pytest.mark.parametrize('parameters',
                         [[''],
                          ['config_does_not_exists'],
                          ['tests/configs/bad/empty.yml'],
                          ['tests/configs/bad/missingSwitches.yml'],
                          ['tests/configs/bad/missingHostname.yml'],
                          ['tests/configs/bad/missingPassword.yml'],
                          ['tests/configs/good/standard.yml'],
                          ['tests/configs/good/defaults.yml'],
                          ['-v', 'tests/configs/good/standard.yml']])
def test_main(parameters, capsys):
    sys.argv = ["prosafe_exporter"]
    for parameter in parameters:
        sys.argv.append(parameter)

    exitNoConfig = True
    exitEmptyConfig = False
    exitSwitchesMissing = True
    exitSwitchesHostnameMissing = True
    exitSwitchesPasswordMissing = True
    for parameter in parameters:
        if os.path.isfile(parameter):
            exitNoConfig = False

            if os.path.getsize(parameter) == 0:
                exitEmptyConfig = True

            with open(parameter) as f:
                if 'switches:' in f.read():
                    exitSwitchesMissing = False

            with open(parameter) as f:
                if 'hostname:' in f.read():
                    exitSwitchesHostnameMissing = False

            with open(parameter) as f:
                if 'password:' in f.read():
                    exitSwitchesPasswordMissing = False

            break

    with pytest.raises(SystemExit) as pytest_wrapped_exit:
        main(endless=False, always_early_timeout=True)
    captured = capsys.readouterr()
    if exitNoConfig:
        assert pytest_wrapped_exit.type == SystemExit
        assert pytest_wrapped_exit.value.code == 2
        assert re.match(
            r'usage: prosafe_exporter \[-h\] \[-v\] config\n'
            r'prosafe_exporter: error: argument config: can\'t open \'(.*)\': \[Errno 2\] No such file or directory:'
            r' \'(.*)\'\n',
            captured.err)

    elif exitEmptyConfig:
        assert pytest_wrapped_exit.type == SystemExit
        assert pytest_wrapped_exit.value.code == 3
        assert re.match(r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{1,3} - ProSafe_Exporter - ERROR - '
                        r'Config empty or cannot be parsed', captured.err)

    elif exitSwitchesMissing:
        assert pytest_wrapped_exit.type == SystemExit
        assert pytest_wrapped_exit.value.code == 4
        assert re.match(r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{1,3} - ProSafe_Exporter - ERROR - '
                        r'You have to define switches in the switches: section of your configuration', captured.err)

    elif exitSwitchesHostnameMissing:
        assert pytest_wrapped_exit.type == SystemExit
        assert pytest_wrapped_exit.value.code == 0
        assert re.match(r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{1,3} - ProSafe_Exporter - ERROR - '
                        r'You have to define the hostname for the switch, ignoring this switch entry', captured.err)

    elif exitSwitchesPasswordMissing:
        assert pytest_wrapped_exit.type == SystemExit
        assert pytest_wrapped_exit.value.code == 0
        assert re.match(r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{1,3} - ProSafe_Exporter - ERROR - '
                        r'You have to define the password for the switch, ignoring this switch entry', captured.err)

    else:
        assert pytest_wrapped_exit.type == SystemExit
        assert pytest_wrapped_exit.value.code == 0
        if '-v' in parameters:
            assert re.match(r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{1,3} - ProSafe_Exporter - INFO - '
                            r'Created retriever for host 192\.168\.0\.100 using cookiefile None\n'
                            r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{1,3} - ProSafe_Exporter - INFO - '
                            r'Created retriever for host 192\.168\.0\.200 using cookiefile None\n'
                            r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{1,3} - ProSafe_Exporter - INFO - '
                            r'ProSafeExporter is listening on 0\.0\.0\.0:9493 for request on /metrics endpoint \(but'
                            r' you can also use any other path\)\n'
                            r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{1,3} - ProSafe_Exporter - INFO - '
                            r'Retrieving data from all devies\n'
                            r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{1,3} - ProSafe_Exporter - INFO - '
                            r'Start retrieval for 192\.168\.0\.100\n'
                            r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{1,3} - ProSafe_Exporter - ERROR - '
                            r'Connection Error with host 192\.168\.0\.100\n'
                            r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{1,3} - ProSafe_Exporter - INFO - '
                            r'Start retrieval for 192\.168\.0\.200\n'
                            r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{1,3} - ProSafe_Exporter - ERROR - '
                            r'Connection Error with host 192\.168\.0\.200\n'
                            r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{1,3} - ProSafe_Exporter - INFO - '
                            r'Retrieving done\n'
                            r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{1,3} - ProSafe_Exporter - INFO - '
                            r'ProSafeExporter was stopped\n', captured.err)
        else:
            assert re.match(r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{1,3} - ProSafe_Exporter - ERROR - '
                            r'Connection Error with host 192\.168\.0\.100\n'
                            r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{1,3} - ProSafe_Exporter - ERROR - '
                            r'Connection Error with host 192\.168\.0\.200\n', captured.err)
