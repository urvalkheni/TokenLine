import pytest


@pytest.fixture(scope="session", autouse=True)
def dispose_collector_engine_after_test_session():
    """Keep the module-level collector engine from retaining SQLite connections."""
    yield

    from backend.collector.db import dispose_engine

    dispose_engine()
