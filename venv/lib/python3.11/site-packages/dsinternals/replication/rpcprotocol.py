#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : rpcprotocol.py
# Author             : Podalirius (@podalirius_)
# Date created       : 31 Jul 2021

from enum import Enum


class RpcProtocol(Enum):
    """
    RpcProtocol
    """

    TCP = 0
    SMB = 1
    HTTP = 2
