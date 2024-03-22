#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : NetConnectOptions.py
# Author             : Podalirius (@podalirius_)
# Date created       : 31 Jul 2021

from enum import Enum


class NetConnectOptions(Enum):
    """
    NetConnectOptions

    A set of connection options.

    See: https://msdn.microsoft.com/library/windows/desktop/aa385413.aspx
    """

    # The network resource connection should be remembered.
    UpdateProfile = 0x00000001

    # The network resource connection should not be put in the recent connection list.
    UpdateRecent = 0x00000002

    # The network resource connection should not be remembered.
    Temporary = 0x00000004

    # If this flag is set, the operating system may interact with the user for authentication purposes.
    Interactive = 0x00000008

    # This flag instructs the system not to use any default settings for user names or passwords without offering the user the opportunity to supply an alternative.
    Prompt = 0x00000010

    # This flag forces the redirection of a local device when making the connection.
    Redirect = 0x00000080

    # If this flag is set, then the operating system does not start to use a new media to try to establish the connection (initiate a new dial up connection, for example).
    CurrentMedia = 0x00000200

    # ///If this flag is set, the operating system prompts the user for authentication using the command line instead of a graphical user interface (GUI).
    CommandLine = 0x00000800

    # If this flag is set, and the operating system prompts for a credential, the credential should be saved by the credential manager.
    CmdSaveCred = 0x00001000

    # If this flag is set, and the operating system prompts for a credential, the credential is reset by the credential manager.
    CredReset = 0x00002000
