import logging
import pytest

from prosafe_exporter.prosafe_exporter import ProSafeExporter, ProSafeRetrieve


@pytest.fixture(name='client')
def fixture_client():
    logger = logging.getLogger('ProSafe_Exporter')

    exporter = ProSafeExporter(retrievers=[], logger=logger)

    with exporter.app.test_client() as client:
        yield (exporter, client)


@pytest.fixture(name='retriever')
def fixture_retriever():
    logger = logging.getLogger('ProSafe_Exporter')

    retrieverFixture = ProSafeRetrieve(hostname='localhost:8888',
                                       password='password',
                                       logger=logger,
                                       retries=2)
    yield retrieverFixture


def test_empty(client):
    rv = client[1].get('/metrics')
    assert rv.data == b'# Exporter output\n\n'


@pytest.mark.parametrize('path', [('/'), ('/probe'), ('/metric'), ('/metrics')])
def test_withData(client, retriever, path):
    exporter = client[0]

    exporter.retrievers = [retriever]
    retriever.result = "Nothing to see here"

    rv = client[1].get(path)
    assert rv.data == b'# Exporter output\n\n' + bytes(retriever.result, encoding='utf-8') + b'\n\n'


def test_withRetrieve(client, retriever):
    exporter = client[0]

    exporter.retrievers = [retriever]
    exporter._ProSafeExporter__retrieve()

    rv = client[1].get('/metrics')
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
    assert rv.data == (b'# Exporter output\n\n# ERROR: Login failed for '
                       + bytes(retriever.hostname, encoding='utf-8') + b'\n\n\n')
