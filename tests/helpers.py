from contextlib import contextmanager


@contextmanager
def assert_raises(exc_klass):
    excepted = None
    try:
        yield
    except Exception as exc:
        excepted = exc
    assert type(excepted) == exc_klass
