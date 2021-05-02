import pytest

import logging

from prosafe_exporter.prosafe_exporter import ProSafeRetrieve

@pytest.fixture(scope="session")
def httpserver_listen_address():
    return ("localhost", 8888)

@pytest.fixture
def retriever():
    logger = logging.getLogger('ProSafe_Exporter')
    logger.setLevel(logging.INFO)
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    ch.setFormatter(formatter)

    # add ch to logger
    logger.addHandler(ch)
    retriever = ProSafeRetrieve(
                hostname='localhost:8888',
                password='password',
                logger=logger,
                retries=2)
    return retriever

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
    assert statistics[0][0] ==  statistics[0][1] == statistics[0][2] == '0'
    assert statistics[1][0] ==  statistics[1][1] == statistics[1][2] == '1'
    assert statistics[2][0] ==  statistics[2][1] == statistics[2][2] == '15'
    assert statistics[3][0] ==  statistics[3][1] == statistics[3][2] == '4294967295'
    assert statistics[4][0] ==  statistics[4][1] == statistics[4][2] == '18446744073709551615'
    assert statistics[5][0] ==  statistics[5][1] == statistics[5][2] == '0'
    assert statistics[6][0] ==  statistics[6][1] == statistics[6][2] == '0'
    assert statistics[7][0] ==  statistics[7][1] == statistics[7][2] == '0'

def test_serverUnreachable(retriever):
    retriever.retrieve()
    assert retriever.error == 'Connection Error with host ' + retriever.hostname
    retriever.writeResult()
    assert retriever.result == '# ERROR: ' + retriever.error + '\n'

@pytest.mark.parametrize('firmware',
    [('V2.06.14GR'), ('V2.06.14EN'), ('V2.06.03EN')])
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

@pytest.mark.parametrize('firmware',
    [('V2.06.03EN')])
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

    assert retriever.statistics == retriever.statistics == None
    assert retriever.error == 'Result is not  plausible for ' + retriever.hostname + \
                        ' Different number of ports for statistics and status. This can happen when there is much' \
                        ' traffic on the device'

    httpserver.check_assertions()

    retriever.writeResult()

@pytest.mark.parametrize('firmware',
    [('V2.06.03EN')])
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

@pytest.mark.parametrize('firmware',
    [('V2.06.03EN')])
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

@pytest.mark.parametrize('firmware',
    [('V2.06.03EN')])
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

    assert retriever.infos == retriever.status == retriever.statistics == None
    assert retriever.error == "Connection Error with host " + retriever.hostname