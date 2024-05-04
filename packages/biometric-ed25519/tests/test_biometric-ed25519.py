import pytest

@pytest.fixture
# A test function that always passes
def test_dummy(test_account):
    assert True, "Dummy test always passes"