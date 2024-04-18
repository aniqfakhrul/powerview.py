#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : JET_sesparam.py
# Author             : Podalirius (@podalirius_)
# Date created       : 31 Jul 2021

from enum import Enum


class JET_sesparam(Enum):
    """
    JET_sesparam

    ESENT session parameters.
    
    <seealso cref="Windows10.Windows10Sesparam"/>
    """

    # This parameter is not meant to be used. 
    Base = 4096

    # This parameter sets the grbits for commit.  It is functionally the same as the
    # system parameter JET_param.CommitDefault when used with an instance and a sesid.
    # Note: JET_param.CommitDefault is not currently exposed in the ESE interop layer.
    CommitDefault = Base + 1

    # This parameter sets a user specific commit context that will be placed in the
    # transaction log on commit to level 0.
    CommitGenericContext = Base + 2
