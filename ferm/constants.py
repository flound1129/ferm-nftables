from typing import Any, Dict


def get_constants() -> Dict[str, Any]:
    """Return built-in constants."""
    return {
        'match': {
            'ip': {
                'state': {'ctstate': 'c'},
                'conntrack': {'ctstate': 'c', 'ctstatus': 's', 'ctexpire': 's'},
                'multiport': {'sports': 'c', 'dports': 'c', 'ports': 'c'},
                'limit': {'limit': 's', 'limit-burst': 's'},
                'mark': {'mark': 1},
            },
            'ip6': {
                'state': {'ctstate': 'c'},
                'conntrack': {'ctstate': 'c', 'ctstatus': 's', 'ctexpire': 's'},
                'multiport': {'sports': 'c', 'dports': 'c', 'ports': 'c'},
                'limit': {'limit': 's', 'limit-burst': 's'},
                'mark': {'mark': 1},
            },
        },
        'target': {
            'ip': {
                'ACCEPT': {},
                'DROP': {},
                'REJECT': {'reject-with': 's'},
                'LOG': {'log-level': 's', 'log-prefix': 's'},
                'MASQUERADE': {'to-ports': 's'},
                'SNAT': {'to-source': 's'},
                'DNAT': {'to-destination': 's'},
                'RETURN': {},
            },
            'ip6': {
                'ACCEPT': {},
                'DROP': {},
                'REJECT': {'reject-with': 's'},
                'LOG': {'log-level': 's', 'log-prefix': 's'},
                'MASQUERADE': {'to-ports': 's'},
                'SNAT': {'to-source': 's'},
                'DNAT': {'to-destination': 's'},
                'RETURN': {},
            },
        },
        'shortcut': {
            'ip': {},
            'ip6': {},
        },
        'builtin_chains': {
            'filter': ['INPUT', 'OUTPUT', 'FORWARD'],
            'nat': ['PREROUTING', 'POSTROUTING'],
            'mangle': ['PREROUTING', 'INPUT', 'FORWARD', 'OUTPUT', 'POSTROUTING'],
        },
        'builtin_targets': ['ACCEPT', 'DROP', 'QUEUE', 'RETURN'],
    }


MATCH_DEFS: Dict[str, Dict[str, Dict[str, Any]]] = {
    'ip': get_constants()['match']['ip'],
    'ip6': get_constants()['match']['ip6'],
}

TARGET_DEFS: Dict[str, Dict[str, Dict[str, Any]]] = {
    'ip': get_constants()['target']['ip'],
    'ip6': get_constants()['target']['ip6'],
}

SHORTCUTS: Dict[str, Dict[str, tuple]] = {
    'ip': {},
    'ip6': {},
}

BUILTIN_CHAINS: Dict[str, list] = get_constants()['builtin_chains']

BUILTIN_TARGETS: set = set(get_constants()['builtin_targets'])
