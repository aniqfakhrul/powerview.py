import hashlib
import re


def dacl_fingerprint(dacl):
    return hashlib.sha256(dacl.getData()).hexdigest()


def ace_identity(ace, index, fingerprint):
    return {
        'index': index,
        'ace': hashlib.sha256(ace.getData()).hexdigest(),
        'dacl': fingerprint,
    }


def validate_ace_identity(selection):
    if not isinstance(selection, dict) or set(selection) != {'index', 'ace', 'dacl'}:
        raise ValueError('An exact ACE selection requires index, ace and dacl fingerprints.')
    if type(selection['index']) is not int or selection['index'] < 0:
        raise ValueError('The ACE index must be a non-negative integer.')
    for key in ('ace', 'dacl'):
        if not isinstance(selection[key], str) or not re.fullmatch(r'[0-9a-f]{64}', selection[key]):
            raise ValueError('Invalid ACE fingerprint. Refresh Security and select the entry again.')
