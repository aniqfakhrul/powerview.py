import sys
import types
import typing as t

import decorator as deco

from gssapi.raw.misc import GSSError

if t.TYPE_CHECKING:
    from gssapi.sec_contexts import SecurityContext


def import_gssapi_extension(
    name: str,
) -> t.Optional[types.ModuleType]:
    """Import a GSSAPI extension module

    This method imports a GSSAPI extension module based
    on the name of the extension (not including the
    'ext_' prefix).  If the extension is not available,
    the method retuns None.

    Args:
        name (str): the name of the extension

    Returns:
        module: Either the extension module or None
    """

    try:
        path = 'gssapi.raw.ext_{0}'.format(name)
        __import__(path)
        return sys.modules[path]
    except ImportError:
        return None


def inquire_property(
    name: str,
    doc: t.Optional[str] = None
) -> property:
    """Creates a property based on an inquire result

    This method creates a property that calls the
    :python:`_inquire` method, and return the value of the
    requested information.

    Args:
        name (str): the name of the 'inquire' result information

    Returns:
        property: the created property
    """

    def inquire_property(self: "SecurityContext") -> t.Any:
        if not self._started:
            msg = (f"Cannot read {name} from a security context whose "
                   "establishment has not yet been started.")
            raise AttributeError(msg)

        return getattr(self._inquire(**{name: True}), name)

    return property(inquire_property, doc=doc)


# use UTF-8 as the default encoding, like Python 3
_ENCODING = 'UTF-8'


def _get_encoding() -> str:
    """Gets the current encoding used for strings.

    This value is used to encode and decode string
    values like names.

    Returns:
        str: the current encoding
    """
    return _ENCODING


def set_encoding(
    enc: str,
) -> None:
    """Sets the current encoding used for strings

    This value is used to encode and decode string
    values like names.

    Args:
        enc: the encoding to use
    """

    global _ENCODING
    _ENCODING = enc


def _encode_dict(
    d: t.Dict[t.Union[bytes, str], t.Union[bytes, str]],
) -> t.Dict[bytes, bytes]:
    """Encodes any relevant strings in a dict"""
    def enc(x: t.Union[bytes, str]) -> bytes:
        if isinstance(x, str):
            return x.encode(_ENCODING)
        else:
            return x

    return {enc(k): enc(v) for k, v in d.items()}


# in case of Python 3, just use exception chaining
@deco.decorator
def catch_and_return_token(
    func: t.Callable,
    self: "SecurityContext",
    *args: t.Any,
    **kwargs: t.Any,
) -> t.Optional[bytes]:
    """Optionally defer exceptions and return a token instead

    When `__DEFER_STEP_ERRORS__` is set on the implementing class
    or instance, methods wrapped with this wrapper will
    catch and save their :python:`GSSError` exceptions and
    instead return the result token attached to the exception.

    The exception can be later retrived through :python:`_last_err`
    (and :python:`_last_tb` when Python 2 is in use).
    """

    try:
        return func(self, *args, **kwargs)
    except GSSError as e:
        defer_step_errors = getattr(self, '__DEFER_STEP_ERRORS__', False)
        if e.token is not None and defer_step_errors:
            self._last_err = e
            # skip the "return func" line above in the traceback
            tb = e.__traceback__.tb_next  # type: ignore[union-attr]
            self._last_err.__traceback__ = tb

            return e.token
        else:
            raise


@deco.decorator
def check_last_err(
    func: t.Callable,
    self: "SecurityContext",
    *args: t.Any,
    **kwargs: t.Any,
) -> t.Any:
    """Check and raise deferred errors before running the function

    This method checks :python:`_last_err` before running the wrapped
    function.  If present and not None, the exception will be raised
    with its original traceback.
    """

    if self._last_err is not None:
        try:
            raise self._last_err
        finally:
            self._last_err = None
    else:
        return func(self, *args, **kwargs)


class CheckLastError(type):
    """Check for a deferred error on all methods

    This metaclass applies the :python:`check_last_err` decorator
    to all methods not prefixed by '_'.

    Additionally, it enabled `__DEFER_STEP_ERRORS__` by default.
    """

    def __new__(
        cls,
        name: str,
        parents: t.Tuple[t.Type],
        attrs: t.Dict[str, t.Any],
    ) -> "CheckLastError":
        attrs['__DEFER_STEP_ERRORS__'] = True

        for attr_name in attrs:
            attr = attrs[attr_name]

            # wrap only methods
            if not isinstance(attr, types.FunctionType):
                continue

            if attr_name[0] != '_':
                attrs[attr_name] = check_last_err(attr)

        return super(CheckLastError, cls).__new__(cls, name, parents, attrs)
