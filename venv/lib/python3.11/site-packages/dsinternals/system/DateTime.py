#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : DateTime.py
# Author             : Podalirius (@podalirius_)
# Date created       : 28 Jul 2021

import datetime
import time


class DateTime(object):
    """
    Documentation for class DateTime

    https://docs.microsoft.com/en-us/dotnet/api/system.datetime?view=net-5.0
    """

    def __init__(self, ticks: int = 0):
        if ticks == 0:
            self.Value = datetime.datetime.now()
            # diff 1601 - epoch
            diff = datetime.datetime(1970, 1, 1, 0, 0, 0) - datetime.datetime(1601, 1, 1, 0, 0, 0)
            # nanoseconds between 1601 and epoch
            diff_ns = int(diff.total_seconds()) * 1000000000
            # nanoseconds between epoch and now
            now_ns = time.time_ns()
            # ticks between 1601 and now
            ticks = (diff_ns + now_ns) // 100
            self.ticks = ticks
        else:
            self.Value = datetime.datetime(1601, 1, 1, 0, 0, 0) + datetime.timedelta(seconds=ticks / 1e7)
            self.ticks = ticks

    def toUniversalTime(self):
        return self.Value.utcnow()

    def toTicks(self):
        return self.ticks

    def __repr__(self):
        return str(self.Value)
