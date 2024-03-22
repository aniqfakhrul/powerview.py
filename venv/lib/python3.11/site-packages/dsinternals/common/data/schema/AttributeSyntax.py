#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : AttributeSyntax.py
# Author             : Podalirius (@podalirius_)
# Date created       : 31 Jul 2021

from enum import Enum


class AttributeSyntax(Enum):
    """
    AttributeSyntax
    
    Specifies the data representation (syntax) type of an Attribute object.
    """

    # Not a legal syntax.
    Undefined = 0x80000

    # A distinguished name of a directory service object.
    DN = Undefined + 1

    # An OID value type.
    Oid = Undefined + 2

    # A case-sensitive string type.
    CaseExactString = Undefined + 3

    # A case-insensitive string type.
    CaseIgnoreString = Undefined + 4

    # Printable character set string or IA5 character set string.
    String = Undefined + 5

    # A numeric value represented as a string.
    NumericString = Undefined + 6

    # An ADS_DN_WITH_BINARY structure used for mapping a distinguished name to a non-varying GUID.
    DNWithBinary = Undefined + 7

    # A Boolean value type.
    Bool = Undefined + 8

    # A 32-bit number or enumeration.
    Int = Undefined + 9

    # A byte array represented as a string
    OctetString = Undefined + 10

    # UTC Time or Generalized-Time.
    Time = Undefined + 11

    # Unicode string.
    UnicodeString = Undefined + 12

    # A Presentation-Address object type.
    PresentationAddress = Undefined + 13

    # An ADS_DN_WITH_STRING structure used for mapping a distinguished name to a non-varying string value.
    DNWithString = Undefined + 14

    # A security descriptor value type.
    SecurityDescriptor = Undefined + 15

    # A 64 bit (large) integer value type.
    Int64 = Undefined + 16

    # An SID value type.
    Sid = Undefined + 17

