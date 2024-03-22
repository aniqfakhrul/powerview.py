import typing as t

class OID:
    """
    A GSSAPI OID

    A new OID may be created by passing the `elements` argument
    to the constructor.  The `elements` argument should be a
    :class:`bytes` consisting of the BER-encoded values in the OID.

    To retrieve the underlying bytes, use the :class:`bytes`
    function in Python 3.

    This object is hashable, and may be compared using equality
    operators.
    """

    def __new__(
        cls,
        cpy: t.Optional["OID"] = None,
        elements: t.Optional[bytes] = None,
    ) -> "OID": ...

    @classmethod
    def from_int_seq(
        cls,
        integer_sequence: t.Union[str, t.Iterable[int]],
    ) -> "OID":
        """Create a OID from a sequence of integers.

        This method creates an OID from a sequence of integers.
        The sequence can either be in dotted form as a string,
        or in list form.

        This method is not for BER-encoded byte strings, which
        can be passed directly to the OID constructor.

        Args:
            integer_sequence: either a list of integers or
                a string in dotted form

        Returns:
            OID: the OID represented by the given integer sequence

        Raises:
            ValueError: the sequence is less than two elements long
        """

    @property
    def dotted_form(self) -> str: ...
