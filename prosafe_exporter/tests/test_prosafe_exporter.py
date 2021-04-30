import pytest

import logging

from prosafe_exporter.prosafe_exporter import ProSafeExporter, ProSafeRetrieve

@pytest.fixture(scope="session")
def httpserver_listen_address():
    return ("localhost", 8888)

@pytest.fixture
def exporter():
    exporter = ProSafeExporter(retrievers=[])

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
                logger=logger)
    return retriever

def test_serverUnreachable(retriever):
    retriever.retrieve()
    assert retriever.error == 'Connection Error with host ' + retriever.hostname
    retriever.writeResult()
    assert retriever.result == ''

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

    assert retriever.infos['product_name'] == 'GS108Ev3'
    assert retriever.infos['switch_name'] == 'MyFancySwitch'
    assert retriever.infos['serial_number'] == '123456789'
    assert retriever.infos['mac_adresse'] == '00:11:22:33:44:55'
    assert retriever.infos['firmware_version'] == firmware
    assert retriever.infos['dhcp_mode'] == '0'
    assert retriever.infos['ip_adresse'] == '1.2.3.4'
    assert retriever.infos['subnetmask'] == '255.255.255.255'
    assert retriever.infos['gateway_adresse'] == '1.2.3.4'

    httpserver.check_assertions()
