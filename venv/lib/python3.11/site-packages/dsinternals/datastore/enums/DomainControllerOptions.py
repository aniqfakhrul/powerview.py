#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : DomainControllerOptions.py
# Author             : Podalirius (@podalirius_)
# Date created       : 31 Jul 2021

from enum import Enum


class DomainControllerOptions(Enum):
    """
    DomainControllerOptions
    """

    NONE = 0
    GlobalCatalog = 1
    DisableInboundReplication = 2
    DisableOutboundReplication = 4
    DisableConnectionTranslation = 8
