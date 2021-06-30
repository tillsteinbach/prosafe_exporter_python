import sys
import os.path
import re
import random
import string
import logging
import yaml

import pytest

from prosafe_exporter.prosafe_exporter import ProSafeRetrieve, main


# seed random to generate same sequence every time the test runs to make it deterministic
random.seed(1)

logging.basicConfig(level=logging.INFO)


@pytest.fixture(scope="session")
def httpserver_listen_address():
    return ("localhost", 8888)


@pytest.fixture(name='retriever')
def fixture_retriever():

    retriever = ProSafeRetrieve(hostname='localhost:8888',
                                password='password',
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


def checkStatistics(statistics, _):
    assert len(statistics) == 8
    assert statistics[0][0] == statistics[0][1] == statistics[0][2] == '0'
    assert statistics[1][0] == statistics[1][1] == statistics[1][2] == '1'
    assert statistics[2][0] == statistics[2][1] == statistics[2][2] == '15'
    assert statistics[3][0] == statistics[3][1] == statistics[3][2] == '4294967295'
    assert statistics[4][0] == statistics[4][1] == statistics[4][2] == '18446744073709551615'
    assert statistics[5][0] == statistics[5][1] == statistics[5][2] == '0'
    assert statistics[6][0] == statistics[6][1] == statistics[6][2] == '0'
    assert statistics[7][0] == statistics[7][1] == statistics[7][2] == '0'


def genSetHeader(cookie):
    return {
        'Content-Type': 'text/html',
        'Cache-Control': 'no-cache',
        'Expires': '-1',
        'Set-Cookie': f'GS108SID={cookie}; SameSite=Lax;path=/;HttpOnly'
    }


def genWithHeader(cookie):
    return {
        'Cookie': f'GS108SID={cookie}'
    }


def generateCookie():
    length = 30
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))


def loginGood(request, firmware, password, httpserver, cookie):
    with open(f'{request.config.rootdir}/tests/responses/{firmware}/good/login.htm', 'r') as f:
        httpserver.expect_ordered_request("/login.htm", method='GET').respond_with_data(f.readlines())
    with open(f'{request.config.rootdir}/tests/responses/{firmware}/good/login.htm', 'r') as f:
        httpserver.expect_ordered_request("/login.cgi", method='POST', data=f'password={password}').respond_with_data(
            f.readlines(), headers=genSetHeader(cookie))


def test_serverUnreachable(retriever):
    retriever.retrieve()
    assert retriever.error == f'Connection Error with host {retriever.hostname}'
    retriever.writeResult()
    assert retriever.result == f'# ERROR: {retriever.error}\n'


@pytest.mark.parametrize('firmware, password', [('V2.06.14GR', '5fd34891e0221be7a1dcbd78ae81a700'),
                                                ('V2.06.14EN', '5fd34891e0221be7a1dcbd78ae81a700'),
                                                ('V2.06.03EN', 'password')])
def test_standardRequestGood(request, retriever, firmware, password, httpserver):
    cookie = generateCookie()
    loginGood(request, firmware, password, httpserver, cookie)
    with open(f'{request.config.rootdir}/tests/responses/{firmware}/good/switch_info.htm', 'r') as f:
        httpserver.expect_ordered_request("/switch_info.htm", method='GET',
                                          headers=genWithHeader(cookie)).respond_with_data(f.readlines())
    with open(f'{request.config.rootdir}/tests/responses/{firmware}/good/status.htm', 'r') as f:
        httpserver.expect_ordered_request("/status.htm", method='GET',
                                          headers=genWithHeader(cookie)).respond_with_data(f.readlines())
    if firmware in ['V2.06.14EN']:
        httpserver.expect_ordered_request("/port_statistics.htm", method='GET',
                                          headers=genWithHeader(cookie)).respond_with_data('', status=500)
        with open(f'{request.config.rootdir}/tests/responses/{firmware}/good/portStats.htm', 'r') as f:
            httpserver.expect_ordered_request("/portStats.htm", method='GET',
                                              headers=genWithHeader(cookie)).respond_with_data(f.readlines())
    else:
        with open(f'{request.config.rootdir}/tests/responses/{firmware}/good/port_statistics.htm', 'r') as f:
            httpserver.expect_ordered_request("/port_statistics.htm", method='GET',
                                              headers=genWithHeader(cookie)).respond_with_data(f.readlines())
    retriever.retrieve()

    checkInfos(retriever._ProSafeRetrieve__infos, firmware)
    checkStatus(retriever._ProSafeRetrieve__status, firmware)
    checkStatistics(retriever._ProSafeRetrieve__statistics, firmware)

    httpserver.check_assertions()

    retriever.writeResult()


@pytest.mark.parametrize('firmware, password', [('V2.06.14GR', '5fd34891e0221be7a1dcbd78ae81a700')])
def test_cookiefile(request, firmware, password, httpserver, caplog):
    cookiefile = "cookiefile.txt"
    if os.path.isfile(cookiefile):
        os.remove(cookiefile)

    retriever = ProSafeRetrieve(hostname='localhost:8888',
                                password='password',
                                retries=2,
                                cookiefile=cookiefile)

    cookie = generateCookie()
    with open(f'{request.config.rootdir}/tests/responses/{firmware}/good/login.htm', 'r') as f:
        httpserver.expect_ordered_request("/login.htm", method='GET').respond_with_data(f.readlines())
    with open(f'{request.config.rootdir}/tests/responses/{firmware}/good/login.htm', 'r') as f:
        httpserver.expect_ordered_request("/login.cgi", method='POST', data=f'password={password}').respond_with_data(
            f.readlines(), headers=genSetHeader(cookie))
    retriever._ProSafeRetrieve__login()  # pylint: disable=no-member

    LOG = logging.getLogger("ProSafeExporter")
    LOG.setLevel(level=logging.INFO)
    # Execute destructor, pytest messes around with the reference count
    retriever.__del__()
    del retriever
    assert ' Writing cookiefile cookiefile.txt' in caplog.text

    httpserver.check_assertions()

    # Test with old cookie
    retrieverNew = ProSafeRetrieve(hostname='localhost:8888',
                                   password='password',
                                   retries=2,
                                   cookiefile=cookiefile)

    with open(f'{request.config.rootdir}/tests/responses/{firmware}/good/index.htm', 'r') as f:
        httpserver.expect_ordered_request("/index.htm", method='GET',
                                          headers=genWithHeader(cookie)).respond_with_data(f.readlines())
    with open(f'{request.config.rootdir}/tests/responses/{firmware}/good/switch_info.htm', 'r') as f:
        httpserver.expect_ordered_request("/switch_info.htm", method='GET',
                                          headers=genWithHeader(cookie)).respond_with_data(f.readlines())
    with open(f'{request.config.rootdir}/tests/responses/{firmware}/good/status.htm', 'r') as f:
        httpserver.expect_ordered_request("/status.htm", method='GET',
                                          headers=genWithHeader(cookie)).respond_with_data(f.readlines())
    if firmware in ['V2.06.14EN']:
        httpserver.expect_ordered_request("/port_statistics.htm", method='GET',
                                          headers=genWithHeader(cookie)).respond_with_data('', status=500)
        with open(f'{request.config.rootdir}/tests/responses/{firmware}/good/portStats.htm', 'r') as f:
            httpserver.expect_ordered_request("/portStats.htm", method='GET',
                                              headers=genWithHeader(cookie)).respond_with_data(f.readlines())
    else:
        with open(f'{request.config.rootdir}/tests/responses/{firmware}/good/port_statistics.htm', 'r') as f:
            httpserver.expect_ordered_request("/port_statistics.htm", method='GET',
                                              headers=genWithHeader(cookie)).respond_with_data(f.readlines())

    retrieverNew.retrieve()
    httpserver.check_assertions()
    # Execute destructor, pytest messes around with the reference count
    retrieverNew.__del__()
    del retrieverNew

    # Test cookie expired
    cookieNew = generateCookie()
    retrieverNew2 = ProSafeRetrieve(hostname='localhost:8888',
                                    password='password',
                                    retries=2,
                                    cookiefile=cookiefile)
    with open(f'{request.config.rootdir}/tests/responses/{firmware}/good/index.htm_redirect', 'r') as f:
        httpserver.expect_ordered_request("/index.htm", method='GET',
                                          headers=genWithHeader(cookie)).respond_with_data(f.readlines())
    with open(f'{request.config.rootdir}/tests/responses/{firmware}/good/login.htm', 'r') as f:
        httpserver.expect_ordered_request("/login.htm", method='GET').respond_with_data(f.readlines())
    with open(f'{request.config.rootdir}/tests/responses/{firmware}/good/login.htm', 'r') as f:
        httpserver.expect_ordered_request("/login.cgi", method='POST', data=f'password={password}').respond_with_data(
            f.readlines(), headers=genSetHeader(cookieNew))
    with open(f'{request.config.rootdir}/tests/responses/{firmware}/good/switch_info.htm', 'r') as f:
        httpserver.expect_ordered_request("/switch_info.htm", method='GET',
                                          headers=genWithHeader(cookieNew)).respond_with_data(f.readlines())
    with open(f'{request.config.rootdir}/tests/responses/{firmware}/good/status.htm', 'r') as f:
        httpserver.expect_ordered_request("/status.htm", method='GET',
                                          headers=genWithHeader(cookieNew)).respond_with_data(f.readlines())
    if firmware in ['V2.06.14EN']:
        httpserver.expect_ordered_request("/port_statistics.htm", method='GET',
                                          headers=genWithHeader(cookieNew)).respond_with_data('', status=500)
        with open(f'{request.config.rootdir}/tests/responses/{firmware}/good/portStats.htm', 'r') as f:
            httpserver.expect_ordered_request("/portStats.htm", method='GET',
                                              headers=genWithHeader(cookieNew)).respond_with_data(f.readlines())
    else:
        with open(f'{request.config.rootdir}/tests/responses/{firmware}/good/port_statistics.htm', 'r') as f:
            httpserver.expect_ordered_request("/port_statistics.htm", method='GET',
                                              headers=genWithHeader(cookieNew)).respond_with_data(f.readlines())

    retrieverNew2.retrieve()
    httpserver.check_assertions()
    # Execute destructor, pytest messes around with the reference count
    retrieverNew2.__del__()
    del retrieverNew2

    with open(cookiefile, 'w') as f:
        f.write('{}{}')

    _ = ProSafeRetrieve(hostname='localhost:8888',
                        password='password',
                        retries=2,
                        cookiefile=cookiefile)
    assert f' could not use cookiefile {cookiefile} (Extra data)' in caplog.text

    LOG.setLevel(level=logging.NOTSET)

    if os.path.isfile(cookiefile):
        os.remove(cookiefile)


@pytest.mark.parametrize('firmware, password', [('V2.06.14GR', '5fd34891e0221be7a1dcbd78ae81a700'),
                                                ('V2.06.14EN', '5fd34891e0221be7a1dcbd78ae81a700'),
                                                ('V2.06.03EN', 'password')])
def test_loginError(request, retriever, firmware, password, httpserver):
    with open(f'{request.config.rootdir}/tests/responses/{firmware}/good/login.htm', 'r') as f:
        httpserver.expect_ordered_request("/login.htm", method='GET').respond_with_data(f.readlines())
    with open(f'{request.config.rootdir}/tests/responses/{firmware}/bad/login.cgi_error', 'r') as f:
        httpserver.expect_ordered_request("/login.cgi", method='POST', data=f'password={password}').respond_with_data(
            f.readlines())

    with pytest.raises(ConnectionRefusedError):
        retriever.retrieve()

    httpserver.check_assertions()

    assert (retriever._ProSafeRetrieve__infos is None and retriever._ProSafeRetrieve__status is None
            and retriever._ProSafeRetrieve__statistics is None)
    if firmware in ['V2.06.14GR']:
        assert retriever.error == 'I could not login at the switch ' + \
            retriever.hostname + ' due to: Das Passwort ist ungültig.'
    else:
        assert retriever.error == 'I could not login at the switch ' + \
            retriever.hostname + ' due to: The password is invalid.'

    retriever.writeResult()
    assert retriever.result == '# ERROR: ' + retriever.error + '\n'


@pytest.mark.parametrize('firmware, password', [('V2.06.03EN', 'password')])
@pytest.mark.parametrize('fails', [(1), (2)])
def test_partOfStatusMissing(request, retriever, firmware, password, httpserver, fails):
    cookie = generateCookie()
    loginGood(request, firmware, password, httpserver, cookie)
    with open(f'{request.config.rootdir}/tests/responses/{firmware}/good/switch_info.htm', 'r') as f:
        httpserver.expect_ordered_request("/switch_info.htm", method='GET',
                                          headers=genWithHeader(cookie)).respond_with_data(f.readlines())
    with open(f'{request.config.rootdir}/tests/responses/{firmware}/bad/status.htm_partMissing', 'r') as f:
        httpserver.expect_ordered_request("/status.htm", method='GET',
                                          headers=genWithHeader(cookie)).respond_with_data(f.readlines())
    if fails == 2:
        with open(f'{request.config.rootdir}/tests/responses/{firmware}/bad/status.htm_partMissing', 'r') as f:
            httpserver.expect_ordered_request("/status.htm", method='GET',
                                              headers=genWithHeader(cookie)).respond_with_data(f.readlines())
        retriever.retrieve()
        assert retriever._ProSafeRetrieve__status is None
        assert retriever._ProSafeRetrieve__statistics is None
    else:
        with open(f'{request.config.rootdir}/tests/responses/{firmware}/good/status.htm', 'r') as f:
            httpserver.expect_ordered_request("/status.htm", method='GET',
                                              headers=genWithHeader(cookie)).respond_with_data(f.readlines())
        if firmware in ['V2.06.14EN']:
            httpserver.expect_ordered_request("/port_statistics.htm", method='GET',
                                              headers=genWithHeader(cookie)).respond_with_data('', status=500)
            with open(f'{request.config.rootdir}/tests/responses/{firmware}/good/portStats.htm', 'r') as f:
                httpserver.expect_ordered_request("/portStats.htm", method='GET',
                                                  headers=genWithHeader(cookie)).respond_with_data(f.readlines())
        else:
            with open(f'{request.config.rootdir}/tests/responses/{firmware}/good/port_statistics.htm', 'r') as f:
                httpserver.expect_ordered_request("/port_statistics.htm", method='GET',
                                                  headers=genWithHeader(cookie)).respond_with_data(f.readlines())
        retriever.retrieve()
        checkStatus(retriever._ProSafeRetrieve__status, firmware)
        checkStatistics(retriever._ProSafeRetrieve__statistics, firmware)

    checkInfos(retriever._ProSafeRetrieve__infos, firmware)

    httpserver.check_assertions()

    retriever.writeResult()


@pytest.mark.parametrize('firmware, password', [('V2.06.03EN', 'password')])
def test_oneTXMissing(request, retriever, firmware, password, httpserver):
    cookie = generateCookie()
    loginGood(request, firmware, password, httpserver, cookie)
    with open(f'{request.config.rootdir}/tests/responses/{firmware}/good/switch_info.htm', 'r') as f:
        httpserver.expect_ordered_request("/switch_info.htm", method='GET',
                                          headers=genWithHeader(cookie)).respond_with_data(f.readlines())
    with open(f'{request.config.rootdir}/tests/responses/{firmware}/good/status.htm', 'r') as f:
        httpserver.expect_ordered_request("/status.htm", method='GET',
                                          headers=genWithHeader(cookie)).respond_with_data(f.readlines())
    if firmware in ['V2.06.14EN']:
        httpserver.expect_ordered_request("/port_statistics.htm", method='GET',
                                          headers=genWithHeader(cookie)).respond_with_data('', status=500)
        with open(f'{request.config.rootdir}/tests/responses/{firmware}/bad/portStats.htm_oneTXMissing', 'r') as f:
            badResponse = f.readlines()
            httpserver.expect_ordered_request("/portStats.htm", method='GET',
                                              headers=genWithHeader(cookie)).respond_with_data(badResponse)
            httpserver.expect_ordered_request("/portStats.htm", method='GET',
                                              headers=genWithHeader(cookie)).respond_with_data(badResponse)
    else:
        with open(f'{request.config.rootdir}/tests/responses/{firmware}/bad/port_statistics.htm_oneTXMissing',
                  'r') as f:
            badResponse = f.readlines()
            httpserver.expect_ordered_request("/port_statistics.htm", method='GET',
                                              headers=genWithHeader(cookie)).respond_with_data(badResponse)
            httpserver.expect_ordered_request("/port_statistics.htm", method='GET',
                                              headers=genWithHeader(cookie)).respond_with_data(badResponse)
    retriever.retrieve()

    checkInfos(retriever._ProSafeRetrieve__infos, firmware)
    checkStatus(retriever._ProSafeRetrieve__status, firmware)

    assert retriever._ProSafeRetrieve__statistics is None
    assert retriever.error == f'Could not retrieve correct statistics for {retriever.hostname}' \
                              f' after {retriever.retries} retries. This can happen when there is much' \
                              f' traffic on the device'

    httpserver.check_assertions()

    retriever.writeResult()
    assert retriever.result == f'# ERROR: {retriever.error}\n'


@pytest.mark.parametrize('firmware, password', [('V2.06.03EN', 'password')])
def test_firstPortMissing(request, retriever, firmware, password, httpserver):
    cookie = generateCookie()
    loginGood(request, firmware, password, httpserver, cookie)
    with open(f'{request.config.rootdir}/tests/responses/{firmware}/good/switch_info.htm', 'r') as f:
        httpserver.expect_ordered_request("/switch_info.htm", method='GET',
                                          headers=genWithHeader(cookie)).respond_with_data(f.readlines())
    with open(f'{request.config.rootdir}/tests/responses/{firmware}/good/status.htm', 'r') as f:
        httpserver.expect_ordered_request("/status.htm", method='GET',
                                          headers=genWithHeader(cookie)).respond_with_data(f.readlines())
    if firmware in ['V2.06.14EN']:
        httpserver.expect_ordered_request("/port_statistics.htm", method='GET',
                                          headers=genWithHeader(cookie)).respond_with_data('', status=500)
        with open(f'{request.config.rootdir}/tests/responses/{firmware}/bad/portStats.htm_firstPortMissing', 'r') as f:
            httpserver.expect_ordered_request("/portStats.htm", method='GET',
                                              headers=genWithHeader(cookie)).respond_with_data(f.readlines())
    else:
        with open(f'{request.config.rootdir}/tests/responses/{firmware}/bad/port_statistics.htm_firstPortMissing',
                  'r') as f:
            httpserver.expect_ordered_request("/port_statistics.htm", method='GET',
                                              headers=genWithHeader(cookie)).respond_with_data(f.readlines())
    retriever.retrieve()

    checkInfos(retriever._ProSafeRetrieve__infos, firmware)

    assert retriever._ProSafeRetrieve__status is None and retriever._ProSafeRetrieve__statistics is None

    httpserver.check_assertions()

    retriever.writeResult()


@pytest.mark.parametrize('firmware, password', [('V2.06.03EN', 'password')])
def test_lastPortMissing(request, retriever, firmware, password, httpserver):
    cookie = generateCookie()
    loginGood(request, firmware, password, httpserver, cookie)
    with open(f'{request.config.rootdir}/tests/responses/{firmware}/good/switch_info.htm', 'r') as f:
        httpserver.expect_ordered_request("/switch_info.htm", method='GET',
                                          headers=genWithHeader(cookie)).respond_with_data(f.readlines())
    with open(f'{request.config.rootdir}/tests/responses/{firmware}/good/status.htm', 'r') as f:
        httpserver.expect_ordered_request("/status.htm", method='GET',
                                          headers=genWithHeader(cookie)).respond_with_data(f.readlines())
    if firmware in ['V2.06.14EN']:
        httpserver.expect_ordered_request("/port_statistics.htm", method='GET',
                                          headers=genWithHeader(cookie)).respond_with_data('', status=500)
        with open(f'{request.config.rootdir}/tests/responses/{firmware}/bad/portStats.htm_lastPortMissing', 'r') as f:
            httpserver.expect_ordered_request("/portStats.htm", method='GET',
                                              headers=genWithHeader(cookie)).respond_with_data(f.readlines())
    else:
        with open(f'{request.config.rootdir}/tests/responses/{firmware}/bad/port_statistics.htm_lastPortMissing',
                  'r') as f:
            httpserver.expect_ordered_request("/port_statistics.htm", method='GET',
                                              headers=genWithHeader(cookie)).respond_with_data(f.readlines())
    retriever.retrieve()

    checkInfos(retriever._ProSafeRetrieve__infos, firmware)

    assert retriever._ProSafeRetrieve__status is None and retriever._ProSafeRetrieve__statistics is None

    httpserver.check_assertions()

    retriever.writeResult()


@pytest.mark.parametrize('firmware, password', [('V2.06.03EN', 'password')])
@pytest.mark.parametrize('retry', ['login_get', 'login_post', 'switch_info', 'status', 'statistics'])
def test_retry(request, retriever, firmware, retry, password, httpserver):
    cookie = generateCookie()
    if retry == 'login_get':
        httpserver.expect_ordered_request("/login.htm", method='GET').respond_with_data('', status=500)
        with open(f'{request.config.rootdir}/tests/responses/{firmware}/good/login.htm', 'r') as f:
            httpserver.expect_ordered_request("/login.htm", method='GET').respond_with_data(f.readlines())
    else:
        with open(f'{request.config.rootdir}/tests/responses/{firmware}/good/login.htm', 'r') as f:
            httpserver.expect_ordered_request("/login.htm", method='GET').respond_with_data(f.readlines())

    if retry == 'login_post':
        with open(f'{request.config.rootdir}/tests/responses/{firmware}/good/login.htm', 'r') as f:
            httpserver.expect_ordered_request("/login.cgi", method='POST',
                                              data=f'password={password}').respond_with_data('', status=500)
    elif retry not in ['login_get']:
        with open(f'{request.config.rootdir}/tests/responses/{firmware}/good/login.htm', 'r') as f:
            httpserver.expect_ordered_request("/login.cgi",
                                              method='POST',
                                              data=f'password={password}').respond_with_data(
                                                  f.readlines(), headers=genSetHeader(cookie))

    if retry == 'switch_info':
        with open(f'{request.config.rootdir}/tests/responses/{firmware}/good/switch_info.htm', 'r') as f:
            httpserver.expect_ordered_request("/switch_info.htm", method='GET',
                                              headers=genWithHeader(cookie)).respond_with_data('', status=500)
    elif retry not in ['login_get', 'login_post']:
        with open(f'{request.config.rootdir}/tests/responses/{firmware}/good/switch_info.htm', 'r') as f:
            httpserver.expect_ordered_request("/switch_info.htm", method='GET',
                                              headers=genWithHeader(cookie)).respond_with_data(f.readlines())

    if retry == 'status':
        with open(f'{request.config.rootdir}/tests/responses/{firmware}/good/status.htm', 'r') as f:
            httpserver.expect_ordered_request("/status.htm", method='GET',
                                              headers=genWithHeader(cookie)).respond_with_data('', status=500)
    elif retry not in ['login_get', 'login_post', 'switch_info']:
        with open(f'{request.config.rootdir}/tests/responses/{firmware}/good/status.htm', 'r') as f:
            httpserver.expect_ordered_request("/status.htm", method='GET',
                                              headers=genWithHeader(cookie)).respond_with_data(f.readlines())

    if retry == 'statistics':
        with open(f'{request.config.rootdir}/tests/responses/{firmware}/good/port_statistics.htm', 'r') as f:
            httpserver.expect_ordered_request("/port_statistics.htm", method='GET',
                                              headers=genWithHeader(cookie)).respond_with_data('', status=500)
            httpserver.expect_ordered_request("/portStats.htm", method='GET',
                                              headers=genWithHeader(cookie)).respond_with_data('', status=500)
    elif retry not in ['login_get', 'login_post', 'switch_info', 'status']:
        with open(f'{request.config.rootdir}/tests/responses/{firmware}/good/port_statistics.htm', 'r') as f:
            httpserver.expect_ordered_request("/port_statistics.htm", method='GET',
                                              headers=genWithHeader(cookie)).respond_with_data(f.readlines())

    retriever.retrieve()

    assert (retriever._ProSafeRetrieve__infos is None and retriever._ProSafeRetrieve__status is None
            and retriever._ProSafeRetrieve__statistics is None)
    assert retriever.error == f'Connection Error with host {retriever.hostname}'

    retriever.writeResult()
    assert retriever.result == f'# ERROR: {retriever.error}\n'


@pytest.mark.parametrize('firmware, password', [('V2.06.03EN', 'password')])
@pytest.mark.parametrize('redirect', ['switch_info', 'status', 'statistics'])
def test_redirect(request, retriever, firmware, password, redirect, httpserver):
    cookie = generateCookie()
    with open(f'{request.config.rootdir}/tests/responses/{firmware}/good/login.htm', 'r') as f:
        httpserver.expect_ordered_request("/login.htm", method='GET').respond_with_data(f.readlines())
    with open(f'{request.config.rootdir}/tests/responses/{firmware}/good/login.htm', 'r') as f:
        httpserver.expect_ordered_request("/login.cgi", method='POST', data=f'password={password}').respond_with_data(
            f.readlines(), headers=genSetHeader(cookie))
    if redirect in ['switch_info']:
        with open(f'{request.config.rootdir}/tests/responses/{firmware}/good/index.htm_redirect', 'r') as f:
            httpserver.expect_ordered_request("/switch_info.htm", method='GET',
                                              headers=genWithHeader(cookie)).respond_with_data(f.readlines())
    else:
        with open(f'{request.config.rootdir}/tests/responses/{firmware}/good/switch_info.htm', 'r') as f:
            httpserver.expect_ordered_request("/switch_info.htm", method='GET',
                                              headers=genWithHeader(cookie)).respond_with_data(f.readlines())
    if redirect in ['status']:
        with open(f'{request.config.rootdir}/tests/responses/{firmware}/good/index.htm_redirect', 'r') as f:
            httpserver.expect_ordered_request("/status.htm", method='GET',
                                              headers=genWithHeader(cookie)).respond_with_data(f.readlines())
    else:
        with open(f'{request.config.rootdir}/tests/responses/{firmware}/good/status.htm', 'r') as f:
            httpserver.expect_ordered_request("/status.htm", method='GET',
                                              headers=genWithHeader(cookie)).respond_with_data(f.readlines())
    if redirect in ['statistics']:
        if firmware in ['V2.06.14EN']:
            httpserver.expect_ordered_request("/port_statistics.htm", method='GET',
                                              headers=genWithHeader(cookie)).respond_with_data('', status=500)
            with open(f'{request.config.rootdir}/tests/responses/{firmware}/good/index.htm_redirect', 'r') as f:
                httpserver.expect_ordered_request("/portStats.htm", method='GET',
                                                  headers=genWithHeader(cookie)).respond_with_data(f.readlines())
        else:
            with open(f'{request.config.rootdir}/tests/responses/{firmware}/good/index.htm_redirect', 'r') as f:
                httpserver.expect_ordered_request("/port_statistics.htm", method='GET',
                                                  headers=genWithHeader(cookie)).respond_with_data(f.readlines())
    else:
        if firmware in ['V2.06.14EN']:
            httpserver.expect_ordered_request("/port_statistics.htm", method='GET',
                                              headers=genWithHeader(cookie)).respond_with_data('', status=500)
            with open(f'{request.config.rootdir}/tests/responses/{firmware}/good/portStats.htm', 'r') as f:
                httpserver.expect_ordered_request("/portStats.htm", method='GET',
                                                  headers=genWithHeader(cookie)).respond_with_data(f.readlines())
        else:
            with open(f'{request.config.rootdir}/tests/responses/{firmware}/good/port_statistics.htm', 'r') as f:
                httpserver.expect_ordered_request("/port_statistics.htm", method='GET',
                                                  headers=genWithHeader(cookie)).respond_with_data(f.readlines())

    with pytest.raises(ConnectionRefusedError):
        retriever.retrieve()

    assert retriever.error == f'Login failed for {retriever.hostname}'
    assert (retriever._ProSafeRetrieve__infos is None and retriever._ProSafeRetrieve__status is None
            and retriever._ProSafeRetrieve__statistics is None)


@pytest.mark.parametrize('firmware', [('V2.06.14GR'), ('V2.06.03EN')])
@pytest.mark.parametrize('vectorLengthZero', [True, False])
def test_write(retriever, firmware, vectorLengthZero):
    retriever._ProSafeRetrieve__infos = dict()
    retriever._ProSafeRetrieve__infos['product_name'] = 'GS108Ev3'
    retriever._ProSafeRetrieve__infos['switch_name'] = 'MyFancySwitch'
    retriever._ProSafeRetrieve__infos['serial_number'] = '123456789'
    retriever._ProSafeRetrieve__infos['mac_adresse'] = '00:11:22:33:44:55'
    retriever._ProSafeRetrieve__infos['firmware_version'] = '0.1.2ABC'
    retriever._ProSafeRetrieve__infos['dhcp_mode'] = '0'
    retriever._ProSafeRetrieve__infos['ip_adresse'] = '1.2.3.4'
    retriever._ProSafeRetrieve__infos['subnetmask'] = '255.255.255.255'
    retriever._ProSafeRetrieve__infos['gateway_adresse'] = '1.2.3.4'
    if firmware in ['V2.06.03EN']:
        if vectorLengthZero:
            retriever._ProSafeRetrieve__status = [[] for x in range(1, 9)]
        else:
            retriever._ProSafeRetrieve__status = [[str(x), 'Active', '2'] for x in range(1, 9)]
    else:
        if vectorLengthZero:
            retriever._ProSafeRetrieve__status = [[] for x in range(1, 9)]
        else:
            retriever._ProSafeRetrieve__status = [[str(x), 'Active', '2', str(x * 1000)] for x in range(1, 9)]
    if vectorLengthZero:
        retriever._ProSafeRetrieve__statistics = [[] for x in range(1, 9)]
    else:
        retriever._ProSafeRetrieve__statistics = [[str(x * 1), str(x * 100), str(x * 1000)] for x in range(1, 9)]

    retriever.writeResult()
    resultString = '\n' \
        '# HELP prosafe_switch_info All configuration items collected. This is always 1 and only used to collect' \
        ' labels\n' \
        '# TYPE prosafe_switch_info gauge\n' \
        f'prosafe_switch_info{{hostname="{retriever.hostname}", product_name="' \
        + retriever._ProSafeRetrieve__infos['product_name'] + '", switch_name="' \
        + retriever._ProSafeRetrieve__infos['switch_name'] + '", serial_number="' \
        + retriever._ProSafeRetrieve__infos['serial_number'] + '", mac_adresse="' \
        + retriever._ProSafeRetrieve__infos['mac_adresse'] + '", firmware_version="' \
        + retriever._ProSafeRetrieve__infos['firmware_version'] + '", dhcp_mode="' \
        + retriever._ProSafeRetrieve__infos['dhcp_mode'] + '", ip_adresse="' \
        + retriever._ProSafeRetrieve__infos['ip_adresse'] + '", subnetmask="' \
        + retriever._ProSafeRetrieve__infos['subnetmask'] + '", gateway_adresse="' \
        + retriever._ProSafeRetrieve__infos['gateway_adresse'] + '"} 1\n' \
        '\n' \
        '# HELP prosafe_link_speed Link speed of the port in MBit, 0 means unconnected\n' \
        '# TYPE prosafe_link_speed gauge\n' \
        '# UNIT prosafe_link_speed megabit per second\n'
    if not vectorLengthZero:
        resultString += f'prosafe_link_speed{{hostname="{retriever.hostname}", port="1"}} 2\n' \
            f'prosafe_link_speed{{hostname="{retriever.hostname}", port="2"}} 2\n' \
            f'prosafe_link_speed{{hostname="{retriever.hostname}", port="3"}} 2\n' \
            f'prosafe_link_speed{{hostname="{retriever.hostname}", port="4"}} 2\n' \
            f'prosafe_link_speed{{hostname="{retriever.hostname}", port="5"}} 2\n' \
            f'prosafe_link_speed{{hostname="{retriever.hostname}", port="6"}} 2\n' \
            f'prosafe_link_speed{{hostname="{retriever.hostname}", port="7"}} 2\n' \
            f'prosafe_link_speed{{hostname="{retriever.hostname}", port="8"}} 2\n'
    resultString += '\n' \
        '# HELP prosafe_max_mtu Maximum MTU set for the port in Byte\n' \
        '# TYPE prosafe_max_mtu gauge\n' \
        '# UNIT prosafe_max_mtu bytes\n'
    if firmware not in ['V2.06.03EN'] and not vectorLengthZero:
        resultString += f'prosafe_max_mtu{{hostname="{retriever.hostname}", port="1"}} 1000\n' \
            f'prosafe_max_mtu{{hostname="{retriever.hostname}", port="2"}} 2000\n' \
            f'prosafe_max_mtu{{hostname="{retriever.hostname}", port="3"}} 3000\n' \
            f'prosafe_max_mtu{{hostname="{retriever.hostname}", port="4"}} 4000\n' \
            f'prosafe_max_mtu{{hostname="{retriever.hostname}", port="5"}} 5000\n' \
            f'prosafe_max_mtu{{hostname="{retriever.hostname}", port="6"}} 6000\n' \
            f'prosafe_max_mtu{{hostname="{retriever.hostname}", port="7"}} 7000\n' \
            f'prosafe_max_mtu{{hostname="{retriever.hostname}", port="8"}} 8000\n'

    resultString += '\n'
    resultString += '# HELP prosafe_receive_bytes_total Received bytes at port\n' \
        '# TYPE prosafe_receive_bytes_total counter\n' \
        '# UNIT prosafe_receive_bytes_total bytes\n'
    if not vectorLengthZero:
        resultString += f'prosafe_receive_bytes_total{{hostname="{retriever.hostname}", port="1"}} 1\n' \
            f'prosafe_receive_bytes_total{{hostname="{retriever.hostname}", port="2"}} 2\n' \
            f'prosafe_receive_bytes_total{{hostname="{retriever.hostname}", port="3"}} 3\n' \
            f'prosafe_receive_bytes_total{{hostname="{retriever.hostname}", port="4"}} 4\n' \
            f'prosafe_receive_bytes_total{{hostname="{retriever.hostname}", port="5"}} 5\n' \
            f'prosafe_receive_bytes_total{{hostname="{retriever.hostname}", port="6"}} 6\n' \
            f'prosafe_receive_bytes_total{{hostname="{retriever.hostname}", port="7"}} 7\n' \
            f'prosafe_receive_bytes_total{{hostname="{retriever.hostname}", port="8"}} 8\n'
    resultString += '\n' \
        '# HELP prosafe_transmit_bytes_total Transmitted bytes at port\n' \
        '# TYPE prosafe_transmit_bytes_total counter\n' \
        '# UNIT prosafe_transmit_bytes_total bytes\n'
    if not vectorLengthZero:
        resultString += f'prosafe_transmit_bytes_total{{hostname="{retriever.hostname}", port="1"}} 100\n' \
            f'prosafe_transmit_bytes_total{{hostname="{retriever.hostname}", port="2"}} 200\n' \
            f'prosafe_transmit_bytes_total{{hostname="{retriever.hostname}", port="3"}} 300\n' \
            f'prosafe_transmit_bytes_total{{hostname="{retriever.hostname}", port="4"}} 400\n' \
            f'prosafe_transmit_bytes_total{{hostname="{retriever.hostname}", port="5"}} 500\n' \
            f'prosafe_transmit_bytes_total{{hostname="{retriever.hostname}", port="6"}} 600\n' \
            f'prosafe_transmit_bytes_total{{hostname="{retriever.hostname}", port="7"}} 700\n' \
            f'prosafe_transmit_bytes_total{{hostname="{retriever.hostname}", port="8"}} 800\n'
    resultString += '\n' \
        '# HELP prosafe_error_packets_total Error bytes at port\n' \
        '# TYPE prosafe_error_packets_total counter\n' \
        '# UNIT prosafe_error_packets_total bytes\n'
    if not vectorLengthZero:
        resultString += f'prosafe_error_packets_total{{hostname="{retriever.hostname}", port="1"}} 1000\n' \
            f'prosafe_error_packets_total{{hostname="{retriever.hostname}", port="2"}} 2000\n' \
            f'prosafe_error_packets_total{{hostname="{retriever.hostname}", port="3"}} 3000\n' \
            f'prosafe_error_packets_total{{hostname="{retriever.hostname}", port="4"}} 4000\n' \
            f'prosafe_error_packets_total{{hostname="{retriever.hostname}", port="5"}} 5000\n' \
            f'prosafe_error_packets_total{{hostname="{retriever.hostname}", port="6"}} 6000\n' \
            f'prosafe_error_packets_total{{hostname="{retriever.hostname}", port="7"}} 7000\n' \
            f'prosafe_error_packets_total{{hostname="{retriever.hostname}", port="8"}} 8000\n'
    assert retriever.result == resultString
    assert retriever.error == ''


@pytest.mark.parametrize('parameters',  # noqa: C901
                         [[''],
                          ['config_does_not_exists'],
                          ['tests/configs/bad/empty.yml'],
                          ['tests/configs/bad/missingSwitches.yml'],
                          ['tests/configs/bad/missingHostname.yml'],
                          ['tests/configs/bad/missingPassword.yml'],
                          ['tests/configs/good/standard.yml'],
                          ['tests/configs/good/defaults.yml'],
                          ['-vv', 'tests/configs/good/standard.yml']])
def test_main(request, parameters, caplog, capsys):  # noqa: C901
    sys.argv = ["prosafe_exporter"]
    for parameter in parameters:
        sys.argv.append(parameter)

    exitNoConfig = True
    exitEmptyConfig = False
    exitSwitchesMissing = True
    exitSwitchesHostnameMissing = True
    exitSwitchesPasswordMissing = True
    config = None
    for parameter in parameters:
        if os.path.isfile(parameter):
            exitNoConfig = False

            if os.path.getsize(parameter) == 0:
                exitEmptyConfig = True

            with open(parameter) as f:
                configContent = f.read()
                if 'switches:' in configContent:
                    exitSwitchesMissing = False

                if 'hostname:' in configContent:
                    exitSwitchesHostnameMissing = False

                if 'password:' in configContent:
                    exitSwitchesPasswordMissing = False

                if 'cookiefile:' in configContent:
                    config = yaml.load(configContent, Loader=yaml.SafeLoader)
                    assert config
                    for switch in config['switches']:
                        if 'cookiefile' in switch:
                            if os.path.isfile(f'{request.config.rootdir}/{switch["cookiefile"]}'):
                                os.remove(f'{request.config.rootdir}/{switch["cookiefile"]}')
                            assert not os.path.isfile(f'{request.config.rootdir}/{switch["cookiefile"]}')

            break

    with pytest.raises(SystemExit) as pytest_wrapped_exit:
        main(endless=False, always_early_timeout=True)
    captured = capsys.readouterr()
    if exitNoConfig:
        assert pytest_wrapped_exit.type == SystemExit
        assert pytest_wrapped_exit.value.code == 2
        assert re.match(
            r'usage: prosafe_exporter \[-h\] \[-v\] \[--version\] config\n'
            r'prosafe_exporter: error: argument config: can\'t open \'(.*)\': \[Errno 2\] No such file or directory:'
            r' \'(.*)\'\n',
            captured.err)

    elif exitEmptyConfig:
        assert pytest_wrapped_exit.type == SystemExit
        assert pytest_wrapped_exit.value.code == 3
        assert re.match(r'.+Config empty or cannot be parsed', caplog.text)

    elif exitSwitchesMissing:
        assert pytest_wrapped_exit.type == SystemExit
        assert pytest_wrapped_exit.value.code == 4
        assert re.match(r'.+You have to define switches in the switches: section of your configuration', caplog.text)

    elif exitSwitchesHostnameMissing:
        assert pytest_wrapped_exit.type == SystemExit
        assert pytest_wrapped_exit.value.code == 0
        assert re.match(r'.+You have to define the hostname for the switch, ignoring this switch entry', caplog.text)

    elif exitSwitchesPasswordMissing:
        assert pytest_wrapped_exit.type == SystemExit
        assert pytest_wrapped_exit.value.code == 0
        assert re.match(r'.+You have to define the password for the switch, ignoring this switch entry', caplog.text)

    else:
        assert pytest_wrapped_exit.type == SystemExit
        assert pytest_wrapped_exit.value.code == 0
        if '-v' in parameters:
            assert re.match(r'(.+Created retriever for host (.*)( but could not use cookiefile (.*) '
                            r'\(Expecting value\))?\n)+'
                            r'.+Created retriever for host 192\.168\.0\.200\n'
                            r'.+ProSafeExporter is listening on 0\.0\.0\.0:9493 for request on /metrics endpoint \(but'
                            r' you can also use any other path\)\n'
                            r'.+Retrieving data from all devies\n'
                            r'(.+Start retrieval for (.*)\n'
                            r'.+Connection Error with host (.*)\n)+'
                            r'.+Retrieving done\n'
                            r'.+ProSafeExporter was stopped\n'
                            r'(.+Writing cookiefile (.*)\n)*', caplog.text)
        else:
            assert re.match(r'(.+Connection Error with host (.*)\n)+', caplog.text)

    if config:
        for switch in config['switches']:  # pylint: disable=unsubscriptable-object
            if 'cookiefile' in switch:
                if os.path.isfile(f'{request.config.rootdir}/{switch["cookiefile"]}'):
                    os.remove(f'{request.config.rootdir}/{switch["cookiefile"]}')
                assert not os.path.isfile(f'{request.config.rootdir}/{switch["cookiefile"]}')
