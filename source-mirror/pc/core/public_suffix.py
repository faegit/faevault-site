"""Offline official Public Suffix List, including private and wildcard rules.

Implements https://github.com/publicsuffix/list/wiki/Format. Vendored data retains
its MPL-2.0 header and is bundled alongside this module in PyInstaller builds.
"""
from functools import lru_cache
import ipaddress
from pathlib import Path


@lru_cache(maxsize=1)
def _rules():
    exact, wildcards, exceptions = set(), set(), set()
    for line in Path(__file__).with_name('public_suffix_list.dat').read_text(encoding='utf-8').splitlines():
        parts = line.split()
        if not parts or parts[0].startswith('//'):
            continue
        rule = parts[0]
        destination = exceptions if rule.startswith('!') else wildcards if rule.startswith('*.') else exact
        rule = rule[1:] if rule.startswith('!') else rule[2:] if rule.startswith('*.') else rule
        destination.add(rule.encode('idna').decode('ascii').lower())
    return frozenset(exact), frozenset(wildcards), frozenset(exceptions)


@lru_cache(maxsize=4096)
def registrable_domain(host: str) -> str | None:
    try:
        normalized = host.rstrip('.').encode('idna').decode('ascii').lower()
        ipaddress.ip_address(normalized)
        return None
    except UnicodeError:
        return None
    except ValueError:
        pass
    labels = normalized.split('.')
    if len(labels) < 2 or any(not label for label in labels):
        return None
    exact, wildcards, exceptions = _rules()
    suffix_length = 1
    for index in range(len(labels)):
        suffix = '.'.join(labels[index:])
        count = len(labels) - index
        if suffix in exceptions:
            suffix_length = count - 1
            break
        if suffix in exact:
            suffix_length = max(suffix_length, count)
        if index > 0 and suffix in wildcards:
            suffix_length = max(suffix_length, count + 1)
    return '.'.join(labels[-suffix_length-1:]) if len(labels) > suffix_length else None
