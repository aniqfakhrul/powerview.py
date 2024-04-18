import typing as t

if t.TYPE_CHECKING:
    from gssapi.raw.named_tuples import InquireAttrsResult, DisplayAttrResult
    from gssapi.raw.oids import OID


def indicate_mechs_by_attrs(
    desired_mech_attrs: t.Optional[t.Iterable["OID"]] = None,
    except_mech_attrs: t.Optional[t.Iterable["OID"]] = None,
    critical_mech_attrs: t.Optional[t.Iterable["OID"]] = None,
) -> t.Set["OID"]:
    """Get a set of mechanisms that have the specified attributes.

    Args:
        desired_mech_attrs (~gssapi.OID): Attributes that the output mechs MUST
            offer
        except_mech_attrs (~gssapi.OID): Attributes that the output mechs MUST
            NOT offer
        critical_mech_attrs (~gssapi.OID): Attributes that the output mechs
            MUST understand and offer

    Returns:
        ~gssapi.MechType: a set of mechs which satisfy the given criteria

    Raises:
        ~gssapi.exceptions.GSSError
    """


def inquire_attrs_for_mech(
    mech: "OID",
) -> "InquireAttrsResult":
    """Gets the set of attrs supported and known by a mechanism.

    Args:
        mech (~gssapi.raw.types.MechType): Mechanism to inquire about

    Returns:
        InquireAttrsResult: the results of inquiry; a mech's attributes and
        known attributes

    Raises:
        ~gssapi.exceptions.GSSError
    """


def display_mech_attr(
    attr: "OID",
) -> "DisplayAttrResult":
    """Returns information about attributes in human readable form.

    Args:
        attr (~gssapi.OID): Mechanism attribute to retrieve names and
            descriptions of

    Returns:
        DisplayAttrResult: the results of displaying the attribute; mech name,
        short description, and long description.

    Raises:
        ~gssapi.exceptions.GSSError
    """
