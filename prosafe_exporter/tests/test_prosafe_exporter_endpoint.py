import pytest

import logging

from prosafe_exporter.prosafe_exporter import ProSafeExporter, ProSafeRetrieve

@pytest.fixture
def client():
    logger = logging.getLogger('ProSafe_Exporter')
    logger.setLevel(logging.INFO)
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    # add formatter to ch
    ch.setFormatter(formatter)

    # add ch to logger
    logger.addHandler(ch)
    exporter = ProSafeExporter(retrievers=[], logger=logger)

    with exporter.app.test_client() as client:
        yield (exporter, client)

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

def test_empty(client):
    rv = client[1].get('/metrics')
    assert rv.data == b'# Exporter output\n\n'

@pytest.mark.parametrize('path',
    [('/'), ('/probe'), ('/metric'), ('/metrics')])
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