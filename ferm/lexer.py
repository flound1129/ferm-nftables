from typing import Any, List, Optional


class FermError(Exception):
    def __init__(self, message: str, filename: str = "", line: int = 0):
        self.message = message
        self.filename = filename
        self.line = line
        super().__init__(self._format_message())

    def _format_message(self) -> str:
        if self.filename:
            return f"{self.filename}:{self.line}: {self.message}"
        return self.message


class Token:
    def __init__(self, type: str, value: Any, line: int = 0):
        self.type = type
        self.value = value
        self.line = line

    def __repr__(self) -> str:
        return f"Token({self.type}, {self.value!r})"


TOKEN_LPAREN = 'LPAREN'
TOKEN_RPAREN = 'RPAREN'
TOKEN_LBRACE = 'LBRACE'
TOKEN_RBRACE = 'RBRACE'
TOKEN_SEMICOLON = 'SEMICOLON'
TOKEN_NOT = 'NOT'
TOKEN_DOLLAR = 'DOLLAR'
TOKEN_AMPERSAND = 'AMPERSAND'
TOKEN_EQUALS = 'EQUALS'
TOKEN_AT_KEYWORD = 'AT_KEYWORD'
TOKEN_KEYWORD = 'KEYWORD'
TOKEN_STRING = 'STRING'
TOKEN_NUMBER = 'NUMBER'
TOKEN_CIDR = 'CIDR'


def _token(type: str, value: Any, line: int = 0) -> Token:
    return Token(type, value, line)


class Lexer:
    KEYWORDS = {
        'table', 'chain', 'interface', 'outerface', 'saddr', 'daddr',
        'proto', 'sport', 'dport', 'icmp-type', 'fragment', 'log', 'limit',
        'limit-burst', 'tos', 'ttl', 'mark', 'state', 'ctstate', 'policy',
        'ACCEPT', 'DROP', 'REJECT', 'LOG', 'MASQUERADE', 'DNAT', 'SNAT',
        'RETURN', 'TARPIT', 'QUEUE', 'mod', 'module', 'modprobe',
        'goto', 'subchain', '@subchain', '@gotosubchain', '@if', '@else',
        '@include', '@def', '@hook', '@exec', '@shell',
        'in', 'out', 'forward', 'pre', 'post',
    }

    def __init__(self, text: str, filename: str = ""):
        self.text = text
        self.filename = filename
        self.pos = 0
        self.line = 1
        self.tokens: List[Token] = []
        self._in_brace_depth = 0
        self._after_module = False

    def peek(self, offset: int = 1) -> Optional['Token']:
        idx = self.pos + offset - 1
        if idx < len(self.tokens):
            return self.tokens[idx]
        return None

    def current(self) -> Optional[Token]:
        tok = self.peek(1)
        return tok

    def advance(self) -> Optional[Token]:
        if self.pos < len(self.tokens):
            token = self.tokens[self.pos]
            self.pos += 1
            return token
        return None

    def expect(self, expected_type: str) -> Token:
        token = self.advance()
        if token is None or token.type != expected_type:
            raise FermError(f"Expected {expected_type}, got {token}", self.filename, self.line)
        return token

    def match(self, expected_type: str) -> bool:
        return self.current() is not None and self.current().type == expected_type

    def match_value(self, expected_value: str) -> bool:
        return (self.current() is not None and 
                self.current().type == TOKEN_STRING and 
                self.current().value.lower() == expected_value.lower())

    def consume(self, value: str) -> bool:
        token = self.current()
        if token and token.type == TOKEN_STRING and token.value.lower() == value.lower():
            self.advance()
            return True
        return False

    def tokenize(self) -> List[Token]:
        while self.pos < len(self.text):
            self._skip_whitespace_and_comments()
            if self.pos >= len(self.text):
                break

            char = self.text[self.pos]

            if char == '#':
                self._skip_comment()
            elif char == '"' or char == "'":
                self._read_string(char)
            elif char == '(':
                self.tokens.append(_token(TOKEN_LPAREN, '('))
                self.pos += 1
                self._in_brace_depth += 1
            elif char == ')':
                self.tokens.append(_token(TOKEN_RPAREN, ')'))
                self.pos += 1
                self._in_brace_depth -= 1
            elif char == '{':
                self.tokens.append(_token(TOKEN_LBRACE, '{'))
                self.pos += 1
            elif char == '}':
                self.tokens.append(_token(TOKEN_RBRACE, '}'))
                self.pos += 1
            elif char == ';':
                self.tokens.append(_token(TOKEN_SEMICOLON, ';'))
                self.pos += 1
            elif char == '!':
                self.tokens.append(_token(TOKEN_NOT, '!'))
                self.pos += 1
            elif char == '$':
                self.tokens.append(_token(TOKEN_DOLLAR, '$'))
                self.pos += 1
            elif char == '&':
                self.tokens.append(_token(TOKEN_AMPERSAND, '&'))
                self.pos += 1
            elif char == '=':
                self.tokens.append(_token(TOKEN_EQUALS, '='))
                self.pos += 1
            elif char == '@':
                self._read_at_keyword()
            elif char.isalpha() or char == '_' or char == '-' or char == '.':
                self._read_identifier()
            elif char.isdigit() or char == ':':
                self._read_number_or_range()
            elif char == '/':
                self._read_cidr()
            else:
                raise FermError(f"Unexpected character: {char}", self.filename, self.line)

        return self.tokens

    def _skip_whitespace_and_comments(self):
        while self.pos < len(self.text):
            if self.text[self.pos].isspace():
                if self.text[self.pos] == '\n':
                    self.line += 1
                self.pos += 1
            elif self.text[self.pos] == '#':
                self._skip_comment()
            else:
                break

    def _skip_comment(self):
        while self.pos < len(self.text) and self.text[self.pos] != '\n':
            self.pos += 1

    def _read_string(self, quote: str):
        self.pos += 1
        start = self.pos
        while self.pos < len(self.text) and self.text[self.pos] != quote:
            if self.text[self.pos] == '\\' and self.pos + 1 < len(self.text):
                self.pos += 2
            else:
                self.pos += 1
        if self.pos >= len(self.text):
            raise FermError("Unterminated string", self.filename, self.line)
        value = self.text[start:self.pos]
        self.pos += 1
        self.tokens.append(_token(TOKEN_STRING, value))

    def _read_at_keyword(self):
        start = self.pos
        self.pos += 1
        while self.pos < len(self.text) and (self.text[self.pos].isalnum() or self.text[self.pos] in '_-'):
            self.pos += 1
        value = self.text[start:self.pos]
        self.tokens.append(_token(TOKEN_AT_KEYWORD, value))

    def _read_identifier(self):
        start = self.pos
        while self.pos < len(self.text) and (self.text[self.pos].isalnum() or self.text[self.pos] in '_-'):
            self.pos += 1
        
        if self.pos < len(self.text) and self.text[self.pos] == '.':
            while self.pos < len(self.text) and (self.text[self.pos].isdigit() or self.text[self.pos] == '.'):
                self.pos += 1
            if self.pos < len(self.text) and self.text[self.pos] == '/':
                self.pos += 1
                while self.pos < len(self.text) and self.text[self.pos].isdigit():
                    self.pos += 1
        
        value = self.text[start:self.pos]

        if self._after_module:
            self.tokens.append(_token(TOKEN_STRING, value))
            self._after_module = False
        elif value.lower() in self.KEYWORDS:
            self.tokens.append(_token(TOKEN_KEYWORD, value.upper()))
            if value.lower() in ('mod', 'module'):
                self._after_module = True
        elif value.startswith('@'):
            self.tokens.append(_token(TOKEN_AT_KEYWORD, value))
        else:
            self.tokens.append(_token(TOKEN_STRING, value))

    def _read_number_or_range(self):
        start = self.pos
        while self.pos < len(self.text) and (self.text[self.pos].isdigit() or self.text[self.pos] == ':'):
            self.pos += 1
        
        if self.pos < len(self.text) and self.text[self.pos] == '.':
            while self.pos < len(self.text) and (self.text[self.pos].isdigit() or self.text[self.pos] == '.'):
                self.pos += 1
            if self.pos < len(self.text) and self.text[self.pos] == '/':
                self.pos += 1
                while self.pos < len(self.text) and self.text[self.pos].isdigit():
                    self.pos += 1
            value = self.text[start:self.pos]
            self.tokens.append(_token(TOKEN_STRING, value))
        else:
            value = self.text[start:self.pos]
            self.tokens.append(_token(TOKEN_NUMBER, value))

    def _read_cidr(self):
        start = self.pos
        self.pos += 1
        while self.pos < len(self.text) and (self.text[self.pos].isdigit() or self.text[self.pos] == '.'):
            self.pos += 1
        value = self.text[start:self.pos]
        self.tokens.append(_token(TOKEN_CIDR, value))
