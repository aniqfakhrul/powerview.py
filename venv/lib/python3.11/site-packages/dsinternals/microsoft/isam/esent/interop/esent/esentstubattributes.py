#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : esentstubattributes.py
# Author             : Podalirius (@podalirius_)
# Date created       : 31 Jul 2021

from enum import Enum


class SecurityAction(Enum):
    """
    SecurityAction

    A fake enumeration to allow compilation on platforms that lack this enumeration.
    """

    LinkDemand = 0


class SecurityPermissionAttribute(Attribute):
    """
    SecurityPermissionAttribute

    A fake attribute to allow compilation on platforms that lack this attribute.
    """

    def __init__(self, action: SecurityAction):
        """
        Initializes a new instance of the <see cref="SecurityPermissionAttribute"/> class.
        """
        pass

    def toString(self):
        """
        Prints out the object's contents.

        <returns>A string representation or the object.</returns>
        """
        return self.ToString()


class BestFitMappingAttribute(Attribute):
    """
    BestFitMappingAttribute

    A fake attribute to allow compilation on platforms that lack this attribute.
    """

    ThrowOnUnmappableChar = None

    def __init__(self, bestFitMapping: bool):
        """
        The best fit mapping.
        """
        pass

    def toString(self):
        """
        Prints out the object's contents.

        <returns>A string representation or the object.</returns>
        """
        return self.ToString()


class SuppressUnmanagedCodeSecurityAttribute(Attribute):
    """
    SuppressUnmanagedCodeSecurityAttribute

    A fake attribute to allow compilation on platforms that lack this attribute.
    """

    def toString(self):
        """
        Prints out the object's contents.

        <returns>A string representation or the object.</returns>
        """
        return self.ToString()


class ComVisibleAttribute(Attribute):
    """
    SuppressUnmanagedCodeSecurityAttribute

    A fake attribute to allow compilation on platforms that lack this attribute.
    """

    def __init__(self, comVisible: bool):
        pass

    def toString(self):
        """
        Prints out the object's contents.

        <returns>A string representation or the object.</returns>
        """
        return self.ToString()


class SerializableAttribute(Attribute):
    """
    SuppressUnmanagedCodeSecurityAttribute

    Indicates that a class can be serialized. This class cannot be inherited.
    """

    def toString(self):
        """
        Prints out the object's contents.

        <returns>A string representation or the object.</returns>
        """
        return self.ToString()


class NonSerializedAttribute(Attribute):
    """
    Indicates that a field of a serializable class should not be serialized. This class cannot be inherited.

    Prints out the object's contents.

    <returns>A string representation or the object.</returns>
    """

    def toString(self):
        return base.toString()


class Consistency(Enum):
    """
    Consistency

    The consistency model. A stub.
    """
    # Might corrupt the process.
    MayCorruptProcess = 0

    # Might corrupt the application domain.
    MayCorruptAppDomain = 1

    # Might corrupt the instance.
    MayCorruptInstance = 2

    # Will not corrupt the state.
    WillNotCorruptState = 3


class Cer(ENum):
    """
    Cer

    The Crticial Execution Region description. A stub.
    """

    # No options.
    NONE = 0

    # This might fail.
    MayFail = 1

    # A successful CER.
    Success = 2


class ReliabilityContractAttribute(Attribute):
    """
    ReliabilityContractAttribute

    The description of the reliability contract. A stub.
    """

    # The consistency guarantee. A stub.
    consistency: Consistency = None

    # The critical execution region. A stub.
    cer: Cer = Cer.NONE

    def __init__(self, consistencyGuarantee: Consistency, cer: Cer):
        """
        Initializes a new instance of the ReliabilityContractAttribute class. A stub.

        <param name="consistencyGuarantee">The guarantee of the consistency.</param>
        <param name="cer">The critical execution region description.</param>
        """
        self.consistency = consistencyGuarantee
        self.cer = cer

    def getConsistency(self):
        """
        Gets the consistency guarantee. A stub.
        """
        return self.consistency

    def getCer(self):
        """
        Gets the critical execution region. A stub.
        """
        return self.cer
