from typing import Any, Dict, List, Optional, Set

from .lexer import FermError, Lexer, Token


TOKEN_STRING = 'STRING'
TOKEN_NUMBER = 'NUMBER'
TOKEN_CIDR = 'CIDR'
TOKEN_LPAREN = 'LPAREN'
TOKEN_RPAREN = 'RPAREN'
TOKEN_LBRACE = 'LBRACE'
TOKEN_RBRACE = 'RBRACE'
TOKEN_SEMICOLON = 'SEMICOLON'
TOKEN_KEYWORD = 'KEYWORD'
TOKEN_AT_KEYWORD = 'AT_KEYWORD'
TOKEN_AMPERSAND = 'AMPERSAND'
TOKEN_DOLLAR = 'DOLLAR'
TOKEN_NOT = 'NOT'
TOKEN_COMMA = 'COMMA'
TOKEN_EQUALS = 'EQUALS'


PROTO_DEFS = {
    'ip': {
        'tcp': {'dport': 1, 'sport': 1, 'tcp-flags': 's', 'flags': 's'},
        'udp': {'dport': 1, 'sport': 1},
        'icmp': {'icmp-type': 1},
        'esp': {},
        'ah': {},
        'gre': {},
        'ipv4': {},
        'ipv6': {},
        'igmp': {},
        'all': {},
    },
    'ip6': {
        'tcp': {'dport': 1, 'sport': 1, 'tcp-flags': 's', 'flags': 's'},
        'udp': {'dport': 1, 'sport': 1},
        'icmpv6': {'icmp-type': 1},
        'esp': {},
        'ah': {},
        'ipv6-icmp': {'icmp-type': 1},
        'ipv6': {},
        'all': {},
    },
}

MATCH_DEFS = {
    'ip': {
        'state': {'ctstate': 'c'},
        'conntrack': {'ctstate': 'c', 'ctstatus': 's', 'ctexpire': 's'},
        'multiport': {'sports': 'c', 'dports': 'c', 'ports': 'c'},
        'mac': {'mac-source': 1, 'mac destination': 1},
        'owner': {'uid-owner': 's', 'gid-owner': 's', 'pid-owner': 's', 'sid-owner': 's'},
        'comment': {'comment': 's'},
        'length': {'length': 's'},
        'limit': {'limit': 's', 'limit-burst': 's'},
        'mark': {'mark': 1},
        'dscp': {'dscp': 's', 'dscp-class': 's'},
        'ecn': {'ecn-tcp-cwr': 's', 'ecn-tcp-ece': 's', 'ecn-ip-ect': 's'},
        'ttl': {'ttl': 's'},
        'u32': {'u32': 's'},
        'string': {'algo': 's', 'from': 's', 'to': 's', 'string': 's'},
        'recent': {'name': 's', 'set': 0, 'update': 0, 'remove': 0, 'rcheck': 0, 'seconds': 's', 'hitcount': 's', 'rttl': 's'},
        'helper': {'helper': 's'},
        'connmark': {'ctmark': 1},
        'rpfilter': {'loose': 0, 'invert': 0},
        'iprange': {'src-range': 's', 'dst-range': 's'},
        'geoip': {'src-cc': 'c', 'dst-cc': 'c'},
        'time': {'datestart': 's', 'datestop': 's', 'timestart': 's', 'timestop': 's', 'weekdays': 'c', 'monthdays': 'c', 'contiguous': 0, 'kernel-clock': 0, 'utc': 0, 'localtz': 0},
        'nth': {'every': 's', 'counter': 's', 'start': 's', 'packet': 's'},
        'random': {'probability': 's', 'every': 's', 'packet': 's'},
        'osf': {'genre': 's', 'ttl': 's', 'log': 0},
    },
    'ip6': {
        'state': {'ctstate': 'c'},
        'conntrack': {'ctstate': 'c', 'ctstatus': 's', 'ctexpire': 's'},
        'multiport': {'sports': 'c', 'dports': 'c', 'ports': 'c'},
        'mac': {'mac-source': 1, 'mac-destination': 1},
        'owner': {'uid-owner': 's', 'gid-owner': 's', 'pid-owner': 's', 'sid-owner': 's'},
        'comment': {'comment': 's'},
        'length': {'length': 's'},
        'limit': {'limit': 's', 'limit-burst': 's'},
        'mark': {'mark': 1},
        'dscp': {'dscp': 's', 'dscp-class': 's'},
        'ecn': {'ecn-tcp-cwr': 's', 'ecn-tcp-ece': 's', 'ecn-ip-ect': 's'},
        'hl': {'hl': 's'},
        'hbh': {},
        'frag': {'fragid': 's', 'fragseq': 's'},
        'dst': {},
        'src': {},
        'u32': {'u32': 's'},
        'string': {'algo': 's', 'from': 's', 'to': 's', 'string': 's'},
        'recent': {'name': 's', 'set': 0, 'update': 0, 'remove': 0, 'rcheck': 0, 'seconds': 's', 'hitcount': 's', 'rttl': 's'},
        'helper': {'helper': 's'},
        'connmark': {'ctmark': 1},
        'rpfilter': {'loose': 0, 'invert': 0},
        'iprange': {'src-range': 's', 'dst-range': 's'},
        'time': {'datestart': 's', 'datestop': 's', 'timestart': 's', 'timestop': 's', 'weekdays': 'c', 'monthdays': 'c', 'contiguous': 0, 'kernel-clock': 0, 'utc': 0, 'localtz': 0},
    },
}

TARGET_DEFS = {
    'ip': {
        'ACCEPT': {},
        'DROP': {},
        'REJECT': {'reject-with': 's'},
        'LOG': {'log-level': 's', 'log-prefix': 's', 'log-tcp-sequence': 0, 'log-tcp-options': 0, 'log-ip-options': 0},
        'MASQUERADE': {'to-ports': 's', 'random': 0},
        'SNAT': {'to-source': 's', 'random': 0, 'persistent': 0},
        'DNAT': {'to-destination': 's', 'to-ports': 's', 'random': 0, 'persistent': 0},
        'REDIRECT': {'to-ports': 's', 'random': 0},
        'TARPIT': {},
        'QUEUE': {},
        'RETURN': {},
        'MARK': {'set-mark': 's'},
        'CONNMARK': {'set-mark': 's', 'save-mark': 0, 'restore-mark': 0, 'ctmask': 's', 'mask': 's'},
        'CLASSIFY': {'set-class': 's'},
        'TTL': {'set-ttl': 's', 'ttl-dec': 's', 'ttl-inc': 's'},
        'DSCP': {'set-dscp': 's', 'set-dscp-class': 's'},
        'ECN': {'ecn-tcp-removal': 's'},
        'SAME': {'to': 's', 'nodst': 0, 'random': 0},
        'NFQUEUE': {'queue-num': 's', 'queue-bypass': 0},
        'AUDIT': {'type': 's', 'flags': 'c'},
        'CT': {'notrack': 0, 'helper': 's', 'expectation': 0, 'zone': 's', 'events': 'c'},
        'NETMAP': {'to': 's'},
        'NFLOG': {'group': 's', 'prefix': 's', 'size': 's', 'threshold': 's'},
        'SET': {'add-set': 's', 'del-set': 's', 'exist': 0},
        'TEE': {'gateway': 's'},
        'TOS': {'set-tos': 's', 'and-tos': 's', 'or-tos': 's', 'xor-tos': 's'},
    },
    'ip6': {
        'ACCEPT': {},
        'DROP': {},
        'REJECT': {'reject-with': 's'},
        'LOG': {'log-level': 's', 'log-prefix': 's', 'log-tcp-sequence': 0, 'log-tcp-options': 0, 'log-ip-options': 0},
        'MASQUERADE': {'to-ports': 's', 'random': 0},
        'SNAT': {'to-source': 's', 'random': 0, 'persistent': 0},
        'DNAT': {'to-destination': 's', 'to-ports': 's', 'random': 0, 'persistent': 0},
        'REDIRECT': {'to-ports': 's', 'random': 0},
        'TARPIT': {},
        'QUEUE': {},
        'RETURN': {},
        'MARK': {'set-mark': 's'},
        'CONNMARK': {'set-mark': 's', 'save-mark': 0, 'restore-mark': 0, 'ctmask': 's', 'mask': 's'},
        'HL': {'set-ttl': 's', 'ttl-dec': 's', 'ttl-inc': 's'},
        'CLASSIFY': {'set-class': 's'},
        'DSCP': {'set-dscp': 's', 'set-dscp-class': 's'},
        'NETMAP': {'to': 's'},
        'NFLOG': {'group': 's', 'prefix': 's', 'size': 's', 'threshold': 's'},
        'SET': {'add-set': 's', 'del-set': 's', 'exist': 0},
        'TEE': {'gateway': 's'},
    },
}

SHORTCUTS = {
    'ip': {
        'saddr': ('iprange', 'src-range'),
        'daddr': ('iprange', 'dst-range'),
        'sport': ('multiport', 'sports'),
        'dport': ('multiport', 'dports'),
        'icmp-type': ('icmp', 'icmp-type'),
    },
    'ip6': {
        'saddr': ('iprange', 'src-range'),
        'daddr': ('iprange', 'dst-range'),
        'sport': ('multiport', 'sports'),
        'dport': ('multiport', 'dports'),
        'icmp-type': ('ipv6header', 'header'),
    },
}

BUILTIN_CHAINS = {
    'filter': ['INPUT', 'OUTPUT', 'FORWARD'],
    'nat': ['PREROUTING', 'POSTROUTING', 'INPUT', 'OUTPUT'],
    'mangle': ['PREROUTING', 'INPUT', 'FORWARD', 'OUTPUT', 'POSTROUTING'],
    'raw': ['PREROUTING', 'OUTPUT'],
    'security': ['INPUT', 'OUTPUT', 'FORWARD'],
}

BUILTIN_TARGETS = {'ACCEPT', 'DROP', 'QUEUE', 'RETURN'}


def expand_ports(ports: str) -> List[str]:
    result = []
    for part in ports.replace(',', ' ').split():
        if ':' in part:
            start, end = part.split(':')
            result.extend(str(i) for i in range(int(start), int(end) + 1))
        else:
            result.append(part)
    return result


def format_ip_or_cidr(value: str) -> str:
    value = value.strip()
    if '/' in value:
        return value
    if '-' in value:
        return value
    return value


class Rule:
    def __init__(self):
        self.domain: str = "ip"
        self.domain_family: str = "ip"
        self.table: str = "filter"
        self.chain: Optional[str] = None
        self.policy: Optional[str] = None
        self.interface: Optional[str] = None
        self.outer_interface: Optional[str] = None
        self.protocol: Optional[str] = None
        self.source: Optional[str] = None
        self.dest: Optional[str] = None
        self.sport: Optional[str] = None
        self.dport: Optional[str] = None
        self.icmp_type: Optional[str] = None
        self.fragment: bool = False
        self.tcp_flags: Optional[Dict[str, str]] = None
        self.match_modules: Dict[str, Dict[str, Any]] = {}
        self.target: Optional[str] = None
        self.target_options: List[str] = []
        self.log_level: Optional[str] = None
        self.log_prefix: Optional[str] = None
        self.limit: Optional[str] = None
        self.limit_burst: Optional[str] = None
        self.ctstate: Optional[str] = None
        self.mark: Optional[str] = None
        self.tos: Optional[str] = None
        self.ttl: Optional[str] = None
        self.innotify: bool = False
        self.secmark: Optional[str] = None
        self.physdev_in: Optional[str] = None
        self.physdev_out: Optional[str] = None
        self.physdev_is_bridged: bool = False
        self.has_rule: bool = False
        self.has_action: bool = False
        self.subchain: Optional[str] = None
        self.goto: bool = False
        self.negated: Set[str] = set()
        self.lines: List[str] = []

    def copy(self) -> 'Rule':
        new_rule = Rule()
        new_rule.__dict__.update(self.__dict__)
        new_rule.match_modules = {k: v.copy() for k, v in self.match_modules.items()}
        new_rule.negated = self.negated.copy()
        new_rule.target_options = self.target_options.copy()
        new_rule.lines = self.lines.copy()
        return new_rule


class Chain:
    def __init__(self, name: str, table: str = "filter", policy: Optional[str] = None):
        self.name = name
        self.table = table
        self.policy = policy
        self.rules: List[Rule] = []
        self.subchains: List['Chain'] = []


class Table:
    def __init__(self, name: str):
        self.name = name
        self.chains: Dict[str, Chain] = {}


class Domain:
    def __init__(self, name: str):
        self.name = name
        self.enabled: bool = False
        self.tables: Dict[str, Table] = {}
        self.auto_chain_counter: int = 0


class Parser:
    def __init__(self, tokens: List[Token], filename: str = "", defines: Optional[Dict] = None):
        self.tokens = tokens
        self.pos = 0
        self.filename = filename
        self.current_line = 1
        self.defines = defines or {}
        self.functions: Dict[str, Any] = {}
        self.stack: List[Dict] = [{}]
        self.domains: Dict[str, Domain] = {'ip': Domain('inet')}
        self.current_domain = 'ip'
        self.current_table = 'filter'
        self.current_chain = ''
        self.current_rule = Rule()
        self.defined_vars: Dict[str, Any] = {}
        self.auto_chain_counter = 0
        self._recursion_depth = 0
        self._max_recursion_depth = 100

    def current_token(self) -> Optional[Token]:
        if self.pos < len(self.tokens):
            return self.tokens[self.pos]
        return None

    def advance(self) -> Optional[Token]:
        if self.pos < len(self.tokens):
            token = self.tokens[self.pos]
            self.pos += 1
            if token.type in ('STRING', 'NUMBER', 'CIDR'):
                self.current_line = token.line
            return token
        return None

    def expect(self, token_type: str, expected_value: Optional[str] = None) -> Token:
        token = self.advance()
        if token is None:
            raise FermError(f"Unexpected end of input, expected {token_type}", self.filename, self.current_line)
        if token.type != token_type:
            raise FermError(f"Expected {token_type}, got {token.type}", self.filename, self.current_line)
        if expected_value and token.value != expected_value:
            raise FermError(f"Expected '{expected_value}', got '{token.value}'", self.filename, self.current_line)
        return token

    def consume(self, value: str) -> bool:
        token = self.current_token()
        if token and token.type == TOKEN_STRING and token.value.upper() == value.upper():
            self.advance()
            return True
        if value == '!' and token and token.type == TOKEN_NOT:
            self.advance()
            return True
        return False

    def _parse_negation(self) -> tuple[bool, str]:
        negated = self.consume('!')
        prefix = '!' if negated else ''
        return negated, prefix

    def _parse_optional_string(self) -> Optional[str]:
        token = self.current_token()
        if token and token.type == TOKEN_STRING:
            return self.advance().value
        return None

    def _parse_optional_dollar_var(self) -> Optional[str]:
        token = self.current_token()
        if token and token.type == TOKEN_DOLLAR:
            self.advance()
            var_token = self.expect(TOKEN_STRING)
            return self._resolve_var('$' + var_token.value)
        return None

    def parse(self):
        while self.current_token():
            self._parse_statement()
        return self.domains

    def _save_rule(self):
        if not self.current_rule:
            return
        
        if not self.current_rule.has_rule and not self.current_rule.has_action:
            return
        
        if not self.current_chain:
            return
        
        table = self.domains[self.current_domain].tables.get(self.current_table)
        if not table:
            return
        
        chain = table.chains.get(self.current_chain)
        if not chain:
            return
        
        rule_copy = self.current_rule.copy()
        chain.rules.append(rule_copy)
        
        self.current_rule = Rule()

    def _resolve_var(self, var_name: str) -> str:
        if var_name in self.defined_vars:
            return str(self.defined_vars[var_name])
        if var_name in self.defines:
            return str(self.defines[var_name])
        return var_name

    def _parse_statement(self):
        token = self.current_token()
        if token is None:
            return

        if token.type == TOKEN_SEMICOLON:
            self.advance()
            self._save_rule()
            return

        if token.type == TOKEN_LBRACE:
            self._recursion_depth += 1
            if self._recursion_depth > self._max_recursion_depth:
                raise FermError("Maximum nesting depth exceeded", self.filename, self.current_line)
            self.advance()
            while not self.current_token() or self.current_token().type != TOKEN_RBRACE:
                self._parse_statement()
            if self.current_token():
                self.advance()
            self._recursion_depth -= 1
            return

        if token.type == TOKEN_RBRACE:
            return

        if token.type == TOKEN_KEYWORD:
            keyword = token.value.upper()
            self.advance()
            if keyword == 'TABLE':
                self._parse_table()
            elif keyword == 'CHAIN':
                self._parse_chain()
            elif keyword == 'POLICY':
                self._parse_policy()
            else:
                self._parse_rule_element(keyword)
        elif token.type == TOKEN_AT_KEYWORD:
            self._parse_at_keyword()
        elif token.type == TOKEN_AMPERSAND:
            self._parse_function_call()
        elif token.type == TOKEN_STRING:
            keyword = token.value.upper()
            self.advance()
            self._parse_rule_element(keyword)
        else:
            self.advance()

    def _parse_table(self):
        table_name = self.expect(TOKEN_STRING).value
        self.current_table = table_name

        if not self.domains[self.current_domain].tables.get(table_name):
            self.domains[self.current_domain].tables[table_name] = Table(table_name)

        token = self.current_token()
        if token and token.type == TOKEN_KEYWORD and token.value == 'CHAIN':
            self._parse_chain()
        elif token and token.type == TOKEN_LBRACE:
            self.advance()
            while self.current_token() and self.current_token().type != TOKEN_RBRACE:
                self._parse_statement()
            if self.current_token():
                self.advance()

    def _parse_chain(self):
        chain_name = None
        token = self.current_token()
        if token and token.type == TOKEN_STRING:
            chain_name = self.advance().value
        
        if not chain_name:
            chain_name = self._get_auto_chain_name()

        self.current_chain = chain_name

        if self.current_table not in self.domains[self.current_domain].tables:
            self.domains[self.current_domain].tables[self.current_table] = Table(self.current_table)
        
        table = self.domains[self.current_domain].tables[self.current_table]
        if chain_name not in table.chains:
            table.chains[chain_name] = Chain(chain_name, self.current_table)

        token = self.current_token()
        if token and token.type == 'KEYWORD' and token.value.upper() == 'POLICY':
            self.advance()
            self._parse_policy()
        
        if token and token.type == 'LBRACE':
            self.advance()
            while self.current_token() and self.current_token().type != 'RBRACE':
                self._parse_statement()
            if self.current_token():
                self.advance()

    def _parse_policy(self):
        policy = self.expect('STRING').value.upper()
        
        table = self.domains[self.current_domain].tables.get(self.current_table)
        if table and self.current_chain in table.chains:
            table.chains[self.current_chain].policy = policy
        
        self.expect('SEMICOLON')

    def _get_auto_chain_name(self) -> str:
        self.auto_chain_counter += 1
        return f"ferm_auto_{self.auto_chain_counter}"

    def _parse_at_keyword(self):
        token = self.current_token()
        keyword = token.value.lower()
        self.advance()

        if keyword == '@def':
            self._parse_def()
        elif keyword == '@include':
            self._parse_include()
        elif keyword == '@if':
            self._parse_if()
        elif keyword == '@else':
            self._parse_else()
        elif keyword == '@hook':
            self._parse_hook()
        elif keyword == '@exec' or keyword == '@shell':
            self._parse_exec()
        elif keyword == '@subchain' or keyword == 'subchain':
            self._parse_subchain()
        elif keyword == '@gotosubchain':
            self._parse_subchain(goto=True)
        else:
            raise FermError(f"Unknown @keyword: {keyword}", self.filename, self.current_line)

    def _parse_def(self):
        token_type = self.advance()
        if token_type.type == 'DOLLAR':
            var_name = self.expect('STRING').value
            self.expect('EQUALS')
            value = self._parse_value()
            self.defined_vars[var_name] = value
            self.expect('SEMICOLON')
        elif token_type.type == 'AMPERSAND':
            func_name = self.expect('STRING').value
            self._parse_function_def(func_name)

    def _parse_function_def(self, func_name: str):
        self.expect('LPAREN')
        
        params = []
        while self.current_token() and self.current_token().type != 'RPAREN':
            token = self.advance()
            if token.type == 'DOLLAR':
                params.append(self.expect('STRING').value)
            elif token.type == 'AMPERSAND':
                params.append('&' + self.expect('STRING').value)
        
        self.expect('RPAREN')
        self.expect('EQUALS')
        
        func_body = []
        depth = 1
        self.advance()
        while self.current_token() and depth > 0:
            token = self.current_token()
            if token.type == 'LBRACE':
                depth += 1
            elif token.type == 'RBRACE':
                depth -= 1
                if depth == 0:
                    self.advance()
                    break
            func_body.append(self.advance())
        
        self.expect('SEMICOLON')
        
        self.functions[func_name] = {'params': params, 'body': func_body}

    def _parse_function_call(self):
        self.advance()
        func_name = self.expect('STRING').value
        self.expect('LPAREN')
        
        args = []
        while self.current_token() and self.current_token().type != 'RPAREN':
            args.append(self._parse_value())
            if self.current_token() and self.current_token().type == 'COMMA':
                self.advance()
        
        self.expect('RPAREN')
        
        if func_name not in self.functions:
            raise FermError(f"Unknown function: &{func_name}", self.filename, self.current_line)
        
        func_def = self.functions[func_name]
        params = func_def['params']
        body = func_def['body']
        
        if len(args) != len(params):
            raise FermError(f"Function &{func_name} expects {len(params)} arguments, got {len(args)}", self.filename, self.current_line)
        
        param_map = dict(zip(params, args))
        
        expanded = self._expand_function_body(body, param_map)
        
        self._recursion_depth += 1
        if self._recursion_depth > self._max_recursion_depth:
            raise FermError(f"Function recursion limit exceeded", self.filename, self.current_line)
        
        # Insert expanded tokens before current position (the SEMICOLON after function call)
        # Then continue from where we were (which is now after the inserted tokens)
        insert_pos = self.pos
        for token in reversed(expanded):
            self.tokens.insert(insert_pos, token)
        
        self._recursion_depth -= 1
        
        return ''

    def _expand_function_body(self, body: List[Token], param_map: Dict[str, str]) -> List[Token]:
        expanded = []
        i = 0
        while i < len(body):
            token = body[i]
            if token.type == 'DOLLAR':
                if i + 1 < len(body) and body[i + 1].type == 'STRING':
                    var_name = body[i + 1].value
                    i += 1
                    if var_name in param_map:
                        expanded.append(Token('STRING', param_map[var_name], token.line))
                    else:
                        expanded.append(token)
                        expanded.append(body[i])
                else:
                    var_name = token.value.lstrip('$')
                    if var_name in param_map:
                        expanded.append(Token('STRING', param_map[var_name], token.line))
                    else:
                        expanded.append(token)
            elif token.type == 'AMPERSAND':
                nested_func_name = body[i + 1].value if i + 1 < len(body) else ''
                expanded.append(token)
                expanded.append(Token('STRING', nested_func_name, self.current_line))
                i += 1
                if i + 1 < len(body) and body[i + 1].type == 'LPAREN':
                    expanded.append(body[i + 1])
                    i += 1
                    while i < len(body) and body[i].type != 'RPAREN':
                        expanded.append(body[i])
                        i += 1
                    if i < len(body):
                        expanded.append(body[i])
                        i += 1
            else:
                expanded.append(token)
            i += 1
        return expanded

    def _parse_include(self):
        while self.current_token() and self.current_token().type != 'SEMICOLON':
            self.advance()
        if self.current_token():
            self.expect('SEMICOLON')

    def _parse_if(self):
        condition = self._parse_value()
        
        if self.current_token() and self.current_token().type == 'LBRACE':
            self.advance()
            depth = 1
            while depth > 0 and self.current_token():
                if self.current_token().type == 'LBRACE':
                    depth += 1
                elif self.current_token().type == 'RBRACE':
                    depth -= 1
                self.advance()

    def _parse_else(self):
        if self.current_token() and self.current_token().type == 'LBRACE':
            self.advance()
            while self.current_token() and self.current_token().type != 'RBRACE':
                self.advance()
            if self.current_token():
                self.advance()

    def _parse_hook(self):
        while self.current_token() and self.current_token().type != 'SEMICOLON':
            self.advance()
        if self.current_token():
            self.expect('SEMICOLON')

    def _parse_exec(self):
        while self.current_token() and self.current_token().type != 'SEMICOLON':
            self.advance()
        if self.current_token():
            self.expect('SEMICOLON')

    def _parse_subchain(self, goto: bool = False):
        subchain_name = None
        
        token = self.current_token()
        if token:
            if token.type == 'STRING':
                subchain_name = self.advance().value
            elif token.type == 'LBRACE':
                subchain_name = self._get_auto_chain_name()

        if not subchain_name:
            subchain_name = self._get_auto_chain_name()

        if subchain_name and self.current_table:
            table = self.domains[self.current_domain].tables.get(self.current_table)
            if table and subchain_name not in table.chains:
                table.chains[subchain_name] = Chain(subchain_name, self.current_table)

        if self.current_token() and self.current_token().type == 'LBRACE':
            self.advance()
            while self.current_token() and self.current_token().type != 'RBRACE':
                self._parse_statement()
            if self.current_token():
                self.advance()

    def _parse_value(self):
        values = []
        
        while self.current_token() and self.current_token().type in ('STRING', 'NUMBER', 'CIDR', 'LPAREN', 'NOT', 'DOLLAR', 'AMPERSAND'):
            token = self.advance()
            
            if token.type == 'LPAREN':
                inner_values = []
                while self.current_token() and self.current_token().type != 'RPAREN':
                    inner_values.append(self._parse_value())
                self.expect('RPAREN')
                values.append('(' + ' '.join(str(v) for v in inner_values) + ')')
            elif token.type == 'DOLLAR':
                var_name = self.expect('STRING').value
                values.append(f'${var_name}')
            elif token.type == 'NOT':
                values.append('!' + str(self._parse_value()))
            elif token.type == 'AMPERSAND':
                self._parse_function_call()
                break
            else:
                values.append(token.value)
        
        if len(values) == 1:
            return values[0]
        return ' '.join(str(v) for v in values)

    def _parse_rule_element(self, keyword: str):
        keyword_upper = keyword.upper()
        
        if keyword_upper == 'DOMAIN' or keyword_upper in ('IP', 'IP6'):
            self._parse_domain(keyword_upper)
            return
        
        if keyword_upper == 'INTERFACE':
            self._parse_interface()
            return
        
        if keyword_upper == 'OUTERFACE':
            self._parse_outerface()
            return
        
        if keyword_upper == 'PROTO':
            self._parse_proto()
            return
        
        if keyword_upper == 'SADDR':
            self._parse_saddr()
            return
        
        if keyword_upper == 'DADDR':
            self._parse_daddr()
            return
        
        if keyword_upper == 'SPORT':
            self._parse_sport()
            return
        
        if keyword_upper == 'DPORT':
            self._parse_dport()
            return
        
        if keyword_upper == 'ICMP-TYPE':
            self._parse_icmp_type()
            return
        
        if keyword_upper == 'FRAGMENT':
            self.current_rule.fragment = True
            self.current_rule.has_rule = True
            return
        
        if keyword_upper == 'MOD' or keyword_upper == 'MODULE':
            self._parse_module()
            return
        
        if keyword_upper == 'LOG':
            self._parse_log()
            return
        
        if keyword_upper == 'LIMIT':
            self._parse_limit()
            return
        
        if keyword_upper == 'STATE' or keyword_upper == 'CTSTATE':
            self._parse_state()
            return
        
        if keyword_upper == 'MARK':
            self._parse_mark()
            return
        
        if keyword_upper == 'TOS':
            self._parse_tos()
            return
        
        if keyword_upper == 'TTL':
            self._parse_ttl()
            return
        
        if keyword_upper in BUILTIN_TARGETS or keyword_upper in TARGET_DEFS.get(self.current_domain, {}):
            self._parse_target(keyword_upper)
            return

    def _parse_domain(self, domain: str):
        self.current_domain = 'ip'
        self.current_rule.domain = 'inet'
        self.current_rule.domain_family = 'inet'

    def _parse_interface(self):
        negated = False
        if self.consume('!'):
            negated = True
        
        interface = self.expect('STRING').value
        
        if negated:
            self.current_rule.negated.add('interface')
        
        self.current_rule.interface = ('!' if negated else '') + interface
        self.current_rule.has_rule = True

    def _parse_outerface(self):
        negated = False
        if self.consume('!'):
            negated = True
        
        interface = self.expect('STRING').value
        
        if negated:
            self.current_rule.negated.add('outerface')
        
        self.current_rule.outer_interface = ('!' if negated else '') + interface
        self.current_rule.has_rule = True

    def _parse_proto(self):
        negated = False
        if self.consume('!'):
            negated = True
        
        proto = self.expect('STRING').value
        
        if negated:
            self.current_rule.negated.add('protocol')
        
        self.current_rule.protocol = ('!' if negated else '') + proto
        self.current_rule.has_rule = True

    def _parse_saddr(self):
        negated = False
        if self.consume('!'):
            negated = True
        
        token = self.current_token()
        if token and token.type == 'DOLLAR':
            self.advance()
            var_token = self.expect('STRING')
            addr = self._resolve_var('$' + var_token.value)
        else:
            addr = self.expect('STRING').value
            addr = self._resolve_var(addr)
        
        if negated:
            self.current_rule.negated.add('saddr')
        
        self.current_rule.source = ('!' if negated else '') + format_ip_or_cidr(addr)
        self.current_rule.has_rule = True

    def _parse_daddr(self):
        negated = False
        if self.consume('!'):
            negated = True
        
        token = self.current_token()
        if token and token.type == 'DOLLAR':
            self.advance()
            var_token = self.expect('STRING')
            addr = self._resolve_var('$' + var_token.value)
        else:
            addr = self.expect('STRING').value
            addr = self._resolve_var(addr)
        
        if negated:
            self.current_rule.negated.add('daddr')
        
        self.current_rule.dest = ('!' if negated else '') + format_ip_or_cidr(addr)
        self.current_rule.has_rule = True

    def _parse_sport(self):
        negated = False
        if self.consume('!'):
            negated = True
        
        token = self.current_token()
        if token and token.type == 'LPAREN':
            self.advance()
            ports = []
            while self.current_token() and self.current_token().type != 'RPAREN':
                tok = self.advance()
                if tok and tok.type in ('STRING', 'NUMBER'):
                    ports.append(tok.value)
            self.expect('RPAREN')
            sport = '(' + ' '.join(ports) + ')'
        elif token and token.type == 'DOLLAR':
            self.advance()
            var_token = self.expect('STRING')
            sport = '$' + var_token.value
            sport = self._resolve_var(sport)
        elif token and token.type == 'NUMBER':
            sport = self.advance().value
        else:
            sport = self.expect('STRING').value
        
        if negated:
            self.current_rule.negated.add('sport')
        
        self.current_rule.sport = ('!' if negated else '') + str(sport)
        self.current_rule.has_rule = True

    def _parse_dport(self):
        negated = False
        if self.consume('!'):
            negated = True
        
        token = self.current_token()
        if token and token.type == 'LPAREN':
            self.advance()
            ports = []
            while self.current_token() and self.current_token().type != 'RPAREN':
                tok = self.advance()
                if tok and tok.type in ('STRING', 'NUMBER'):
                    ports.append(tok.value)
            self.expect('RPAREN')
            dport = '(' + ' '.join(ports) + ')'
        elif token and token.type == 'DOLLAR':
            self.advance()
            var_token = self.expect('STRING')
            dport = '$' + var_token.value
            dport = self._resolve_var(dport)
        elif token and token.type == 'NUMBER':
            dport = self.advance().value
        else:
            dport = self.expect('STRING').value
        
        if negated:
            self.current_rule.negated.add('dport')
        
        self.current_rule.dport = ('!' if negated else '') + str(dport)
        self.current_rule.has_rule = True

    def _parse_icmp_type(self):
        negated = False
        if self.consume('!'):
            negated = True
        
        icmp_type = self.expect('STRING').value
        
        if negated:
            self.current_rule.negated.add('icmp_type')
        
        self.current_rule.icmp_type = ('!' if negated else '') + icmp_type
        self.current_rule.has_rule = True

    def _parse_module(self):
        module = self.expect('STRING').value
        
        if module not in self.current_rule.match_modules:
            self.current_rule.match_modules[module] = {}
        
        while self.current_token() and self.current_token().type not in ('SEMICOLON', 'KEYWORD', 'AT_KEYWORD', 'LBRACE', 'RBRACE'):
            token = self.advance()
            if token and token.type == 'STRING':
                key = token.value
                value = self.expect('STRING').value
                self.current_rule.match_modules[module][key] = value

    def _parse_log(self):
        self.current_rule.target = 'LOG'
        self.current_rule.has_action = True
        
        while self.current_token() and self.current_token().type not in ('SEMICOLON', 'KEYWORD', 'AT_KEYWORD', 'LBRACE', 'RBRACE'):
            token = self.current_token()
            if token and token.type == 'STRING':
                key = self.advance().value
                if key.lower() == 'level':
                    self.current_rule.log_level = self.expect('STRING').value
                elif key.lower() == 'prefix':
                    self.current_rule.log_prefix = self.expect('STRING').value
                else:
                    self.advance()

    def _parse_limit(self):
        limit = self.expect('STRING').value
        self.current_rule.limit = limit
        
        if self.current_token() and self.current_token().type == 'STRING':
            burst = self.current_token().value
            if 'burst' in burst.lower():
                self.advance()
                self.current_rule.limit_burst = self.expect('STRING').value

    def _parse_state(self):
        negated = False
        if self.consume('!'):
            negated = True
        
        state_values = []
        
        if self.current_token() and self.current_token().type == 'LPAREN':
            self.advance()
            while self.current_token() and self.current_token().type != 'RPAREN':
                token = self.advance()
                if token:
                    state_values.append(token.value)
            self.expect('RPAREN')
        else:
            token = self.advance()
            if token:
                state_values.append(token.value)
        
        if negated:
            self.current_rule.negated.add('ctstate')
        
        self.current_rule.ctstate = ('!' if negated else '') + ','.join(state_values)
        self.current_rule.has_rule = True

    def _parse_mark(self):
        negated = False
        if self.consume('!'):
            negated = True
        
        mark = self.expect('STRING').value
        
        if negated:
            self.current_rule.negated.add('mark')
        
        self.current_rule.mark = ('!' if negated else '') + mark
        self.current_rule.has_rule = True

    def _parse_tos(self):
        negated = False
        if self.consume('!'):
            negated = True
        
        tos = self.expect('STRING').value
        
        if negated:
            self.current_rule.negated.add('tos')
        
        self.current_rule.tos = ('!' if negated else '') + tos
        self.current_rule.has_rule = True

    def _parse_ttl(self):
        negated = False
        if self.consume('!'):
            negated = True
        
        ttl = self.expect('STRING').value
        
        if negated:
            self.current_rule.negated.add('ttl')
        
        self.current_rule.ttl = ('!' if negated else '') + ttl
        self.current_rule.has_rule = True

    def _parse_target(self, target: str):
        self.current_rule.target = target
        self.current_rule.has_action = True
        
        while self.current_token() and self.current_token().type == 'STRING':
            opt = self.advance().value
            if self.current_token() and self.current_token().type == 'STRING':
                val = self.advance().value
                self.current_rule.target_options.extend([opt, val])
