#!/usr/bin/env python3

import json
from collections import abc
from datetime import timedelta

def make_serializable(data):
    if isinstance(data, abc.Mapping):
        return {key: make_serializable(value) for key, value in data.items()}
    elif isinstance(data, list):
        return [make_serializable(element) for element in data]
    elif isinstance(data, bytes):
        return data.decode('utf-8', errors='ignore')
    elif isinstance(data, timedelta):
        return str(data)
    else:
        return data