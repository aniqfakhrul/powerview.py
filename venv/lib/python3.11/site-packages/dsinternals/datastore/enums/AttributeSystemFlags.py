#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : AttributeSystemFlags.py
# Author             : Podalirius (@podalirius_)
# Date created       : 31 Jul 2021

from enum import Enum


class AttributeSystemFlags(Enum):
    """
    AttributeSystemFlags
    
    An integer value that contains flags that define additional properties of the attribute.
    """

    NONE = 0

    # The attribute will not be replicated.
    NotReplicated = 1

    # If set, this attribute is a member of partial attribute set (PAS) regardless of the value of attribute isMemberofPartialAttributeSet.
    RequiredInPartialSet = 2

    # The attribute is constructed.
    Constructed = 4

    # This attribute is an operational attribute, as defined in [RFC2251] section 3.2.1.
    Operational = 8

    # When set, indicates the object is a category 1 object. A category 1 object is a class or attribute that is included in the base schema included with the system.
    Base = 16

    # This attribute can be used as an RDN attribute of a class.
    Rdn = 32

    # The attribute cannot be renamed.
    DisallowRename = 0x8000000
