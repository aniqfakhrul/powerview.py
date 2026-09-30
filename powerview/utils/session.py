from functools import wraps
from threading import Lock
from _thread import RLock
from types import GeneratorType
import logging


_creation_lock = Lock()


class SessionLock(RLock):
    def __init__(self):
        super().__init__()
        self.owner = None
        self.interrupted = False
        self.recovering = False

    def __exit__(self, exc_type, error, traceback):
        try:
            if isinstance(error, KeyboardInterrupt) and self.owner is not None and not hasattr(error, 'session_lock'):
                self.interrupted = True
                error.session_lock = self
        finally:
            super().__exit__(exc_type, error, traceback)


def session_lock(owner):
    owner = vars(owner).get('conn', vars(owner).get('_connection', owner))
    with _creation_lock:
        lock = vars(owner).get('_session_lock')
        if lock is None:
            lock = SessionLock()
            owner._session_lock = lock
        return lock


def share_session_lock(owner, connection):
    with _creation_lock:
        lock = vars(connection).get('_session_lock') or vars(owner).get('_session_lock') or SessionLock()
        if lock.owner is None:
            lock.owner = owner
        owner._session_lock = connection._session_lock = lock
    for name in ('search', 'add', 'modify', 'delete', 'modify_dn', 'compare', 'extended', 'bind', 'rebind'):
        operation = getattr(connection, name, None)
        if getattr(operation, '__self__', None) is connection and not getattr(operation, '_powerview_session_guard', False):
            setattr(connection, name, session_guard(connection)(operation))


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
            lock = session_lock(owner)
            with lock:
                if owner is not lock.owner and vars(owner).get('_session_lock') is lock and lock.interrupted and not lock.recovering:
                    raise ConnectionError('LDAP session interrupted; reconnect before using this session')
                return function(*args, **kwargs)
        guarded._powerview_session_guard = True
        return guarded
    return decorate


def recover_interrupted_session(error):
    lock = getattr(error, 'session_lock', None)
    if lock is None:
        return False
    try:
        logging.info('LDAP operation interrupted. Replacing the session')
        return lock.owner.reset_connection(fresh=True)
    except KeyboardInterrupt:
        logging.warning('LDAP recovery interrupted; the next query will retry')
        return False
