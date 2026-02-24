import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from ferm.lexer import Lexer, Token, FermError
from ferm.parser import Rule, Chain, Parser, Domain, Table
from ferm.output import generate_iptables_command, generate_iptables_restore
from ferm.nft import generate_nft_rules
from ferm import Ferm


class TestLexer:
    def test_basic_tokens(self):
        lexer = Lexer('table filter { chain INPUT { policy DROP; } }')
        tokens = lexer.tokenize()
        types = [t.type for t in tokens]
        assert 'KEYWORD' in types
        assert 'LBRACE' in types
        assert 'RBRACE' in types
        assert 'SEMICOLON' in types
    
    def test_string_token(self):
        lexer = Lexer('"test string"')
        tokens = lexer.tokenize()
        assert len(tokens) == 1
        assert tokens[0].type == 'STRING'
        assert tokens[0].value == 'test string'
    
    def test_number_token(self):
        lexer = Lexer('8080')
        tokens = lexer.tokenize()
        assert len(tokens) == 1
        assert tokens[0].type == 'NUMBER'
        assert tokens[0].value == '8080'
    
    def test_variable(self):
        lexer = Lexer('$MY_VAR')
        tokens = lexer.tokenize()
        assert len(tokens) == 2
        assert tokens[0].type == 'DOLLAR'
        assert tokens[1].type == 'STRING'
        assert tokens[1].value == 'MY_VAR'
    
    def test_at_keyword(self):
        lexer = Lexer('@include "file.conf"')
        tokens = lexer.tokenize()
        assert tokens[0].type == 'AT_KEYWORD'
        assert tokens[0].value == '@include'


class TestParser:
    def test_parse_table(self):
        lexer = Lexer('table filter { }')
        tokens = lexer.tokenize()
        parser = Parser(tokens)
        domains = parser.parse()
        assert 'filter' in domains['ip'].tables
    
    def test_parse_chain(self):
        lexer = Lexer('table filter { chain INPUT { policy ACCEPT; } }')
        tokens = lexer.tokenize()
        parser = Parser(tokens)
        domains = parser.parse()
        assert 'INPUT' in domains['ip'].tables['filter'].chains
        assert domains['ip'].tables['filter'].chains['INPUT'].policy == 'ACCEPT'
    
    def test_parse_simple_rule(self):
        lexer = Lexer('table filter { chain INPUT { interface lo ACCEPT; } }')
        tokens = lexer.tokenize()
        parser = Parser(tokens)
        domains = parser.parse()
        chain = domains['ip'].tables['filter'].chains['INPUT']
        assert len(chain.rules) > 0
        assert chain.rules[0].interface == 'lo'
    
    def test_parse_port(self):
        lexer = Lexer('table filter { chain INPUT { proto tcp dport 80 ACCEPT; } }')
        tokens = lexer.tokenize()
        parser = Parser(tokens)
        domains = parser.parse()
        chain = domains['ip'].tables['filter'].chains['INPUT']
        rule = chain.rules[0]
        assert rule.protocol == 'tcp'
        assert rule.dport == '80'
    
    def test_parse_multiport(self):
        lexer = Lexer('table filter { chain INPUT { proto tcp dport (80 443) ACCEPT; } }')
        tokens = lexer.tokenize()
        parser = Parser(tokens)
        domains = parser.parse()
        chain = domains['ip'].tables['filter'].chains['INPUT']
        rule = chain.rules[0]
        assert rule.dport == '(80 443)'
    
    def test_parse_variable(self):
        lexer = Lexer('@def $PORT = 8080; table filter { chain INPUT { dport $PORT ACCEPT; } }')
        tokens = lexer.tokenize()
        parser = Parser(tokens)
        domains = parser.parse()
        chain = domains['ip'].tables['filter'].chains['INPUT']
        assert len(chain.rules) > 0


class TestOutput:
    def test_generate_basic_command(self):
        rule = Rule()
        rule.protocol = 'tcp'
        rule.dport = '80'
        rule.target = 'ACCEPT'
        cmd = generate_iptables_command(rule, 'INPUT')
        assert '-p' in cmd
        assert 'tcp' in cmd
        assert '--dport' in cmd
        assert '80' in cmd
        assert '-j' in cmd
        assert 'ACCEPT' in cmd
    
    def test_generate_multiport(self):
        rule = Rule()
        rule.protocol = 'tcp'
        rule.dport = '(80 443 8080)'
        rule.target = 'ACCEPT'
        cmd = generate_iptables_command(rule, 'INPUT')
        assert '-m' in cmd
        assert 'multiport' in cmd
        assert '--dports' in cmd
        assert '80,443,8080' in cmd
    
    def test_generate_with_source(self):
        rule = Rule()
        rule.source = '192.168.1.0/24'
        rule.target = 'ACCEPT'
        cmd = generate_iptables_command(rule, 'INPUT')
        assert '-s' in cmd
        assert '192.168.1.0/24' in cmd
    
    def test_generate_with_interface(self):
        rule = Rule()
        rule.interface = 'eth0'
        rule.target = 'ACCEPT'
        cmd = generate_iptables_command(rule, 'INPUT')
        assert '-i' in cmd
        assert 'eth0' in cmd
    
    def test_generate_iptables_restore(self):
        domain = Domain('ip')
        domain.tables['filter'] = Table('filter')
        domain.tables['filter'].chains['INPUT'] = Chain('INPUT', 'filter')
        
        rule = Rule()
        rule.target = 'ACCEPT'
        domain.tables['filter'].chains['INPUT'].rules.append(rule)
        
        domains = {'ip': domain}
        result = generate_iptables_restore(domains)
        assert 'ip' in result
        assert '*filter' in result['ip']
        assert ':INPUT ACCEPT' in result['ip']


class TestFerm:
    def test_load_simple_config(self, tmp_path):
        config = tmp_path / "test.conf"
        config.write_text('table filter { chain INPUT { policy ACCEPT; } }')
        
        f = Ferm()
        f.load_config(str(config))
        assert 'INPUT' in f.domains['ip'].tables['filter'].chains
    
    def test_noexec_mode(self, tmp_path):
        config = tmp_path / "test.conf"
        config.write_text('table filter { chain INPUT { policy ACCEPT; } }')
        
        f = Ferm()
        f.load_config(str(config))
        f.noexec = True
        f.lines = True
        
        # Should not raise
        f.apply()
    
    def test_lines_mode(self, tmp_path):
        config = tmp_path / "test.conf"
        config.write_text('table filter { chain INPUT { policy ACCEPT; } }')
        
        f = Ferm()
        f.load_config(str(config))
        f.lines = True
        f.noexec = True
        f.apply()
        
        # Should print output
        # (We can't easily test stdout, but it shouldn't raise)


class TestExamples:
    def test_webserver(self):
        f = Ferm()
        f.load_config('ferm/examples/webserver.ferm')
        f.lines = True
        f.noexec = True
        f.apply()
    
    def test_workstation(self):
        f = Ferm()
        f.load_config('ferm/examples/workstation.ferm')
        f.lines = True
        f.noexec = True
        f.apply()
    
    def test_mailserver(self):
        f = Ferm()
        f.load_config('ferm/examples/mailserver.ferm')
        f.lines = True
        f.noexec = True
        f.apply()
    
    def test_ipv6(self):
        f = Ferm()
        f.load_config('ferm/examples/ipv6.ferm')
        f.lines = True
        f.noexec = True
        f.apply()


class TestNftOutput:
    def test_generate_nft_basic(self):
        domain = Domain('ip')
        domain.tables['filter'] = Table('filter')
        domain.tables['filter'].chains['INPUT'] = Chain('INPUT', 'filter')
        
        rule = Rule()
        rule.protocol = 'tcp'
        rule.dport = '80'
        rule.target = 'ACCEPT'
        domain.tables['filter'].chains['INPUT'].rules.append(rule)
        
        domains = {'ip': domain}
        result = generate_nft_rules(domains)
        assert 'add table inet filter' in result
        assert 'add chain inet filter INPUT' in result
        assert 'tcp dport 80 accept' in result
    
    def test_nft_webserver(self):
        f = Ferm()
        f.load_config('ferm/examples/webserver.ferm')
        f.lines = True
        f.noexec = True
        f.use_nft = True
        f.apply()


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
