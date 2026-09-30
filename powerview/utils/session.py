from functools import wraps
from threading import Lock, RLock
from types import GeneratorType


_creation_lock = Lock()


def session_lock(owner):
    owner = vars(owner).get('conn', vars(owner).get('_connection', owner))
    with _creation_lock:
        lock = vars(owner).get('_session_lock')
        if lock is None:
            lock = RLock()
            owner._session_lock = lock
        return lock


def share_session_lock(owner, connection):
    with _creation_lock:
        lock = vars(connection).get('_session_lock') or vars(owner).get('_session_lock') or RLock()
        owner._session_lock = connection._session_lock = lock


def session_locked(method):
    @wraps(method)
    def locked(self, *args, **kwargs):
        with session_lock(self):
            result = method(self, *args, **kwargs)
            return list(result) if isinstance(result, GeneratorType) else result
    return locked


def session_guard(owner):
    def decorate(function):
        @wraps(function)
        def guarded(*args, **kwargs):
            with session_lock(owner):
                return function(*args, **kwargs)
        return guarded
    return decorate
