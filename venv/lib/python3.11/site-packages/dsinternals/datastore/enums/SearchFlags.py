#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : SearchFlags.py
# Author             : Podalirius (@podalirius_)
# Date created       : 31 Jul 2021

from enum import Enum


class SearchFlags(Enum):
    """
    SearchFlags

    https://msdn.microsoft.com/en-us/library/cc223153.aspx
    """

    # No flags set.
    NONE = 0

    # Index over attribute only.
    AttributeIndex = 0x00000001

    # Index over container and attribute.
    ContainerIndex = 0x00000002

    # Add this attribute to the ambiguous name resolution (ANR) set (should be used in conjunction with 1).
    AmbiguousNameResolution = 0x00000004

    # Preserve this attribute on logical deletion (that is, make this attribute available on tombstones).
    PreserveOnDelete = 0x00000008

    # Include this attribute when copying a user object
    Copy = 0x00000010

    # Create a Tuple index for the attribute to improve medial searches
    TupleIndex = 0x00000020

    # Specifies a hint for the DC to create subtree index for a Virtual List View (VLV) search.
    SubtreeIndex = 0x00000040

    # Specifies that the attribute is confidential. An extended access check is required.
    Confidential = 0x00000080

    # Specifies that auditing of changes to individual values contained in this attribute MUST NOT be performed.
    NeverValueAudit = 0x00000100

    # Specifies that the attribute is a member of the filtered attribute set.
    RODCFilteredAttribute = 0x00000200

    #  Specifies a hint to the DC to perform additional implementation-specific, nonvisible tracking of link values.
    ExtendedLinkTracking = 0x00000400

    # Specifies that the attribute is not to be returned by search operations that are not scoped to a single object.
    BaseOnly = 0x00000800

    # Specifies that the attribute is a partition secret. An extended access check is required.
    PartitionSecret = 0x00001000
