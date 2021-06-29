from datetime import datetime, timedelta
import logging
import pytest

from prosafe_exporter.prosafe_exporter import ProSafeExporter, ProSafeRetrieve

logging.basicConfig(level=logging.INFO)


@pytest.fixture(name='client')
def fixture_client():

    exporter = ProSafeExporter(retrievers=[])

    with exporter.app.test_client() as client:
        yield (exporter, client)


@pytest.fixture(name='retriever')
def fixture_retriever():

    retrieverFixture = ProSafeRetrieve(hostname='localhost:8888',
                                       password='password',
                                       retries=2)
    yield retrieverFixture


def test_empty(client):
    rv = client[1].get('/metrics')
    assert rv.status_code == 503
    assert rv.data == b''


@pytest.mark.parametrize('path', [('/'), ('/probe'), ('/metric'), ('/metrics')])
def test_withData(client, retriever, path):
    exporter = client[0]

    exporter.retrievers = [retriever]
    retriever.result = "Nothing to see here"
    exporter.lastRetrieve = datetime.now()

    rv = client[1].get(path)
    assert rv.status_code == 200
    assert rv.data == b'# Exporter output\n\n' + bytes(retriever.result, encoding='utf-8') + b'\n\n'


@pytest.mark.parametrize('path', [('/')])
def test_withOldData(client, retriever, path):
    exporter = client[0]

    exporter.retrievers = [retriever]
    retriever.result = "Nothing to see here"
    exporter.lastRetrieve = datetime.now() - timedelta(seconds=1000)

    rv = client[1].get(path)
    assert rv.status_code == 503
    assert rv.data == b''


def test_withRetrieve(client, retriever):
    exporter = client[0]

    exporter.retrievers = [retriever]
    exporter._ProSafeExporter__retrieve()

    rv = client[1].get('/metrics')
    assert rv.status_code == 200
    assert rv.data == b'# Exporter output\n\n' + bytes(retriever.result, encoding='utf-8') + b'\n\n'


@pytest.mark.parametrize('firmware', [('V2.06.03EN')])
def test_withRetrieveException(request, client, retriever, httpserver, firmware):
    exporter = client[0]

    exporter.retrievers = [retriever]
    with open(f'{request.config.rootdir}/tests/responses/{firmware}/good/login.htm', 'r') as f:
        httpserver.expect_ordered_request("/login.htm", method='GET').respond_with_data(f.readlines())
    with open(f'{request.config.rootdir}/tests/responses/{firmware}/good/login.htm', 'r') as f:
        httpserver.expect_ordered_request("/login.cgi", method='POST').respond_with_data(f.readlines())
    with open(f'{request.config.rootdir}/tests/responses/{firmware}/good/index.htm_redirect', 'r') as f:
        httpserver.expect_ordered_request("/switch_info.htm", method='GET').respond_with_data(f.readlines())

    exporter._ProSafeExporter__retrieve()

    rv = client[1].get('/metrics')
    assert rv.status_code == 200
    assert rv.data == (b'# Exporter output\n\n# ERROR: Login failed for '
                       + bytes(retriever.hostname, encoding='utf-8') + b'\n\n\n')
