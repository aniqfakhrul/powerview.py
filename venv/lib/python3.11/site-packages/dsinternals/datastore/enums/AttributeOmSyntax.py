#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : AttributeOmSyntax.py
# Author             : Podalirius (@podalirius_)
# Date created       : 31 Jul 2021

from enum import Enum


class AttributeOmSyntax(Enum):
    """
    AttributeOmSyntax

    """

    Undefined = 0
    Boolean = 1
    Integer = 2
    OctetString = 4
    ObjectIdentifierString = 6
    Enumeration = 10
    NumericString = 18
    PrintableString = 19
    TeletexString = 20
    IA5String = 22
    UtcTimeString = 23
    GeneralisedTimeString = 24
    UnicodeString = 64
    I8 = 65
    ObjectSecurityDescriptor = 66
    Object = 127
