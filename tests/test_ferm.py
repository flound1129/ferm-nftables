import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from ferm.lexer import Lexer, Token, FermError
from ferm.parser import Rule, Chain, Parser, Domain, Table
from ferm.output import generate_iptables_command, generate_iptables_restore
from ferm.nft import generate_nft_rules
from ferm import Ferm
from ferm.constants import MATCH_DEFS, TARGET_DEFS, SHORTCUTS, BUILTIN_CHAINS, BUILTIN_TARGETS, get_constants


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

    def test_comment(self):
        lexer = Lexer('# this is a comment\ntable filter { }')
        tokens = lexer.tokenize()
        types = [t.type for t in tokens]
        assert 'KEYWORD' in types
    
    def test_ip_address(self):
        lexer = Lexer('192.168.1.1')
        tokens = lexer.tokenize()
        assert tokens[0].type == 'STRING'
        assert tokens[0].value == '192.168.1.1'
    
    def test_cidr(self):
        lexer = Lexer('192.168.1.0/24')
        tokens = lexer.tokenize()
        assert tokens[0].type == 'STRING'
        assert '192.168.1.0/24' in tokens[0].value
    
    def test_negation(self):
        lexer = Lexer('! interface lo ACCEPT')
        tokens = lexer.tokenize()
        assert tokens[0].type == 'NOT'
    
    def test_proto(self):
        lexer = Lexer('proto tcp')
        tokens = lexer.tokenize()
        assert tokens[0].type == 'KEYWORD'
        assert tokens[0].value == 'PROTO'


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

    def test_parse_nat_table(self):
        lexer = Lexer('table nat { chain PREROUTING { dport 80 DNAT to 192.168.1.1:8080; } }')
        tokens = lexer.tokenize()
        parser = Parser(tokens)
        domains = parser.parse()
        assert 'nat' in domains['ip'].tables
        chain = domains['ip'].tables['nat'].chains['PREROUTING']
        assert chain.rules[0].target == 'DNAT'

    def test_parse_mangle_table(self):
        lexer = Lexer('table mangle { chain PREROUTING { } }')
        tokens = lexer.tokenize()
        parser = Parser(tokens)
        domains = parser.parse()
        assert 'mangle' in domains['ip'].tables

    def test_parse_log_target(self):
        lexer = Lexer('table filter { chain INPUT { LOG; } }')
        tokens = lexer.tokenize()
        parser = Parser(tokens)
        domains = parser.parse()
        chain = domains['ip'].tables['filter'].chains['INPUT']
        assert chain.rules[0].target == 'LOG'

    def test_parse_reject_target(self):
        lexer = Lexer('table filter { chain INPUT { REJECT; } }')
        tokens = lexer.tokenize()
        parser = Parser(tokens)
        domains = parser.parse()
        chain = domains['ip'].tables['filter'].chains['INPUT']
        assert chain.rules[0].target == 'REJECT'

    def test_parse_masquerade(self):
        lexer = Lexer('table nat { chain POSTROUTING { outerface eth0 MASQUERADE; } }')
        tokens = lexer.tokenize()
        parser = Parser(tokens)
        domains = parser.parse()
        chain = domains['ip'].tables['nat'].chains['POSTROUTING']
        assert chain.rules[0].target == 'MASQUERADE'

    def test_parse_snat(self):
        lexer = Lexer('table nat { chain POSTROUTING { SNAT to 192.168.1.1; } }')
        tokens = lexer.tokenize()
        parser = Parser(tokens)
        domains = parser.parse()
        chain = domains['ip'].tables['nat'].chains['POSTROUTING']
        assert chain.rules[0].target == 'SNAT'

    def test_parse_dnat(self):
        lexer = Lexer('table nat { chain PREROUTING { DNAT to 192.168.1.1:8080; } }')
        tokens = lexer.tokenize()
        parser = Parser(tokens)
        domains = parser.parse()
        chain = domains['ip'].tables['nat'].chains['PREROUTING']
        assert chain.rules[0].target == 'DNAT'

    def test_parse_return(self):
        lexer = Lexer('table filter { chain INPUT { RETURN; } }')
        tokens = lexer.tokenize()
        parser = Parser(tokens)
        domains = parser.parse()
        chain = domains['ip'].tables['filter'].chains['INPUT']
        assert chain.rules[0].target == 'RETURN'

    def test_parse_dest_port_range(self):
        lexer = Lexer('table filter { chain INPUT { proto tcp dport 1000:2000 ACCEPT; } }')
        tokens = lexer.tokenize()
        parser = Parser(tokens)
        domains = parser.parse()
        chain = domains['ip'].tables['filter'].chains['INPUT']
        assert chain.rules[0].dport == '1000:2000'

    def test_parse_outerface(self):
        lexer = Lexer('table nat { chain POSTROUTING { outerface eth0 MASQUERADE; } }')
        tokens = lexer.tokenize()
        parser = Parser(tokens)
        domains = parser.parse()
        chain = domains['ip'].tables['nat'].chains['POSTROUTING']
        assert chain.rules[0].outer_interface == 'eth0'

    def test_parse_icmp_type(self):
        lexer = Lexer('table filter { chain INPUT { proto icmp icmp-type echo-request ACCEPT; } }')
        tokens = lexer.tokenize()
        parser = Parser(tokens)
        domains = parser.parse()
        chain = domains['ip'].tables['filter'].chains['INPUT']
        assert chain.rules[0].icmp_type == 'echo-request'

    def test_parse_fragment(self):
        lexer = Lexer('table filter { chain INPUT { fragment ACCEPT; } }')
        tokens = lexer.tokenize()
        parser = Parser(tokens)
        domains = parser.parse()
        chain = domains['ip'].tables['filter'].chains['INPUT']
        assert chain.rules[0].fragment == True


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

    def test_generate_iptables_with_table(self):
        rule = Rule()
        rule.table = 'nat'
        rule.target = 'MASQUERADE'
        cmd = generate_iptables_command(rule, 'POSTROUTING')
        assert '-t' in cmd
        assert 'nat' in cmd
    
    def test_generate_iptables_negated_interface(self):
        rule = Rule()
        rule.interface = '!lo'
        rule.target = 'ACCEPT'
        cmd = generate_iptables_command(rule, 'INPUT')
        assert '!' in cmd
    
    def test_generate_iptables_negated_source(self):
        rule = Rule()
        rule.source = '!192.168.1.0/24'
        rule.target = 'ACCEPT'
        cmd = generate_iptables_command(rule, 'INPUT')
        assert '-s' in cmd
    
    def test_generate_iptables_with_ctstate(self):
        rule = Rule()
        rule.ctstate = 'ESTABLISHED,RELATED'
        rule.target = 'ACCEPT'
        cmd = generate_iptables_command(rule, 'INPUT')
        assert '-m' in cmd
        assert 'conntrack' in cmd
        assert '--ctstate' in cmd
    
    def test_generate_iptables_with_mark(self):
        rule = Rule()
        rule.mark = '0x1'
        rule.target = 'ACCEPT'
        cmd = generate_iptables_command(rule, 'INPUT')
        assert '-m' in cmd
        assert 'mark' in cmd
    
    def test_generate_iptables_with_tos(self):
        rule = Rule()
        rule.tos = '0x05'
        rule.target = 'ACCEPT'
        cmd = generate_iptables_command(rule, 'INPUT')
        assert '-m' in cmd
        assert 'tos' in cmd
    
    def test_generate_iptables_log_target(self):
        rule = Rule()
        rule.target = 'LOG'
        rule.log_prefix = 'TEST '
        rule.log_level = '4'
        cmd = generate_iptables_command(rule, 'INPUT')
        assert '-j' in cmd
        assert 'LOG' in cmd
        assert '--log-prefix' in cmd
    
    def test_generate_iptables_with_sport(self):
        rule = Rule()
        rule.protocol = 'tcp'
        rule.sport = '1000'
        rule.target = 'ACCEPT'
        cmd = generate_iptables_command(rule, 'INPUT')
        assert '--sport' in cmd
    
    def test_generate_iptables_with_dport_negated(self):
        rule = Rule()
        rule.protocol = 'tcp'
        rule.dport = '!80'
        rule.target = 'ACCEPT'
        cmd = generate_iptables_command(rule, 'INPUT')
        assert '!' in cmd
        assert '--dport' in cmd
    
    def test_generate_iptables_with_icmp_type(self):
        rule = Rule()
        rule.protocol = 'icmp'
        rule.icmp_type = 'echo-request'
        rule.target = 'ACCEPT'
        cmd = generate_iptables_command(rule, 'INPUT')
        assert '--icmp-type' in cmd
    
    def test_generate_iptables_fragment(self):
        rule = Rule()
        rule.fragment = True
        rule.target = 'ACCEPT'
        cmd = generate_iptables_command(rule, 'INPUT')
        assert '-f' in cmd
    
    def test_generate_iptables_with_outer_interface(self):
        rule = Rule()
        rule.outer_interface = 'eth0'
        rule.target = 'ACCEPT'
        cmd = generate_iptables_command(rule, 'INPUT')
        assert '-o' in cmd
    
    def test_generate_iptables_with_dest(self):
        rule = Rule()
        rule.dest = '192.168.1.0/24'
        rule.target = 'ACCEPT'
        cmd = generate_iptables_command(rule, 'INPUT')
        assert '-d' in cmd
    
    def test_sanitize_for_iptables(self):
        from ferm.output import sanitize_for_iptables
        assert sanitize_for_iptables('test') == 'test'
        assert sanitize_for_iptables(str(123)) == '123'
        with pytest.raises(ValueError):
            sanitize_for_iptables('test\n')
    
    def test_generate_iptables_restore_empty(self):
        from ferm.output import generate_iptables_restore
        result = generate_iptables_restore({})
        assert result == {}
    
    def test_generate_iptables_restore_flush(self):
        domain = Domain('ip')
        domain.tables['filter'] = Table('filter')
        domain.tables['filter'].chains['INPUT'] = Chain('INPUT', 'filter')
        rule = Rule()
        rule.target = 'ACCEPT'
        domain.tables['filter'].chains['INPUT'].rules.append(rule)
        result = generate_iptables_restore({'ip': domain}, flush=True)
        assert 'ip' in result
    
    def test_ip6tables(self):
        rule = Rule()
        rule.domain = 'ip6'
        rule.target = 'ACCEPT'
        cmd = generate_iptables_command(rule, 'INPUT')
        assert 'ip6tables' in cmd
    
    def test_iptables_insert(self):
        rule = Rule()
        rule.target = 'ACCEPT'
        cmd = generate_iptables_command(rule, 'INPUT', append=False)
        assert '-I' in cmd


class TestFermMain:
    def test_load_simple_config(self, tmp_path):
        config = tmp_path / "test.conf"
        config.write_text('table filter { chain INPUT { policy ACCEPT; } }')
        
        f = Ferm()
        f.load_config(str(config))
        assert 'INPUT' in f.domains['ip'].tables['filter'].chains
    
    def test_noexec_mode_apply(self, tmp_path):
        config = tmp_path / "test.conf"
        config.write_text('table filter { chain INPUT { policy ACCEPT; } }')
        
        f = Ferm()
        f.load_config(str(config))
        f.noexec = True
        f.lines = True
        f.apply()
    
    def test_lines_mode_output(self, tmp_path):
        config = tmp_path / "test.conf"
        config.write_text('table filter { chain INPUT { policy ACCEPT; } }')
        
        f = Ferm()
        f.load_config(str(config))
        f.lines = True
        f.noexec = True
        f.apply()

    def test_ferm_init_defaults(self):
        f = Ferm()
        assert f.noexec == False
        assert f.flush == False
        assert f.lines == False
        assert f.slow == False
        assert f.remote == False
        assert f.noflush == False
        assert f.shell == False
        assert f.confirm == False
        assert f.timeout == 0
        assert f.use_nft == True
    
    def test_ferm_with_defines(self, tmp_path):
        config = tmp_path / "test.conf"
        config.write_text('table filter { chain INPUT { policy ACCEPT; } }')
        
        f = Ferm()
        f.defines['$TEST'] = 'test_value'
        f.load_config(str(config))
        assert 'INPUT' in f.domains['ip'].tables['filter'].chains
    
    def test_ferm_load_multiple_configs(self, tmp_path):
        config1 = tmp_path / "test1.conf"
        config1.write_text('table filter { chain INPUT { policy DROP; } }')
        config2 = tmp_path / "test2.conf"
        config2.write_text('table filter { chain OUTPUT { policy ACCEPT; } }')
        
        f = Ferm()
        f.load_config(str(config1))
        f.load_config(str(config2))
        assert 'INPUT' in f.domains['ip'].tables['filter'].chains
        assert 'OUTPUT' in f.domains['ip'].tables['filter'].chains
    
    def test_ferm_use_iptables_mode(self, tmp_path):
        config = tmp_path / "test.conf"
        config.write_text('table filter { chain INPUT { policy ACCEPT; } }')
        
        f = Ferm()
        f.load_config(str(config))
        f.use_nft = False
        f.noexec = True
        f.lines = True
        f.apply()
    
    def test_ferm_show_lines(self, tmp_path):
        config = tmp_path / "test.conf"
        config.write_text('table filter { chain INPUT { policy ACCEPT; } }')
        
        f = Ferm()
        f.load_config(str(config))
        f.show_lines()
    
    def test_ferm_flush_mode(self, tmp_path):
        config = tmp_path / "test.conf"
        config.write_text('table filter { chain INPUT { policy ACCEPT; } }')
        
        f = Ferm()
        f.load_config(str(config))
        f.flush = True
        f.show_lines()
    
    def test_ferm_remote_mode(self, tmp_path):
        config = tmp_path / "test.conf"
        config.write_text('table filter { chain INPUT { policy ACCEPT; } }')
        
        f = Ferm()
        f.load_config(str(config))
        f.remote = True
        f.noexec = True
        f.apply()
    
    def test_ferm_slow_mode(self, tmp_path):
        config = tmp_path / "test.conf"
        config.write_text('table filter { chain INPUT { policy ACCEPT; } }')
        
        f = Ferm()
        f.load_config(str(config))
        f.slow = True
        f.noexec = True
        f.apply()
    
    def test_ferm_noflush_mode(self, tmp_path):
        config = tmp_path / "test.conf"
        config.write_text('table filter { chain INPUT { policy ACCEPT; } }')
        
        f = Ferm()
        f.load_config(str(config))
        f.noflush = True
        f.noexec = True
        f.use_nft = False
        f.apply()
    
    def test_noexec_mode(self, tmp_path):
        config = tmp_path / "test.conf"
        config.write_text('table filter { chain INPUT { policy ACCEPT; } }')
        
        f = Ferm()
        f.load_config(str(config))
        f.noexec = True
        f.lines = True
        f.apply()
    
    def test_lines_mode(self, tmp_path):
        config = tmp_path / "test.conf"
        config.write_text('table filter { chain INPUT { policy ACCEPT; } }')
        
        f = Ferm()
        f.load_config(str(config))
        f.lines = True
        f.noexec = True
        f.apply()

    def test_ferm_init_defaults(self):
        f = Ferm()
        assert f.noexec == False
        assert f.flush == False
        assert f.lines == False
        assert f.slow == False
        assert f.remote == False
        assert f.noflush == False
        assert f.shell == False
        assert f.confirm == False
        assert f.timeout == 0
        assert f.use_nft == True
    
    def test_ferm_with_defines(self, tmp_path):
        config = tmp_path / "test.conf"
        config.write_text('table filter { chain INPUT { policy ACCEPT; } }')
        
        f = Ferm()
        f.defines['$TEST'] = 'test_value'
        f.load_config(str(config))
        assert 'INPUT' in f.domains['ip'].tables['filter'].chains
    
    def test_ferm_load_multiple_configs(self, tmp_path):
        config1 = tmp_path / "test1.conf"
        config1.write_text('table filter { chain INPUT { policy DROP; } }')
        config2 = tmp_path / "test2.conf"
        config2.write_text('table filter { chain OUTPUT { policy ACCEPT; } }')
        
        f = Ferm()
        f.load_config(str(config1))
        f.load_config(str(config2))
        assert 'INPUT' in f.domains['ip'].tables['filter'].chains
        assert 'OUTPUT' in f.domains['ip'].tables['filter'].chains
    
    def test_ferm_use_iptables_mode(self, tmp_path):
        config = tmp_path / "test.conf"
        config.write_text('table filter { chain INPUT { policy ACCEPT; } }')
        
        f = Ferm()
        f.load_config(str(config))
        f.use_nft = False
        f.noexec = True
        f.lines = True
        f.apply()
    
    def test_ferm_show_lines(self, tmp_path):
        config = tmp_path / "test.conf"
        config.write_text('table filter { chain INPUT { policy ACCEPT; } }')
        
        f = Ferm()
        f.load_config(str(config))
        f.show_lines()
    
    def test_ferm_flush_mode(self, tmp_path):
        config = tmp_path / "test.conf"
        config.write_text('table filter { chain INPUT { policy ACCEPT; } }')
        
        f = Ferm()
        f.load_config(str(config))
        f.flush = True
        f.show_lines()


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
        assert 'table inet filter' in result
        assert 'chain input' in result
        assert 'tcp dport 80 accept' in result
    
    def test_nft_webserver(self):
        f = Ferm()
        f.load_config('ferm/examples/webserver.ferm')
        f.lines = True
        f.noexec = True
        f.use_nft = True
        f.apply()

    def test_nft_masquerade(self):
        from ferm.nft import generate_nft_command
        rule = Rule()
        rule.table = 'nat'
        rule.target = 'MASQUERADE'
        cmd = generate_nft_command(rule, 'POSTROUTING', 'nat')
        assert 'masquerade' in cmd
    
    def test_nft_snat(self):
        from ferm.nft import generate_nft_command
        rule = Rule()
        rule.table = 'nat'
        rule.target = 'SNAT'
        rule.target_options = ['to', '1.2.3.4']
        cmd = generate_nft_command(rule, 'POSTROUTING', 'nat')
        assert 'nat snat' in cmd
    
    def test_nft_dnat(self):
        from ferm.nft import generate_nft_command
        rule = Rule()
        rule.table = 'nat'
        rule.target = 'DNAT'
        rule.target_options = ['to', '1.2.3.4:8080']
        cmd = generate_nft_command(rule, 'PREROUTING', 'nat')
        assert 'nat dnat' in cmd
    
    def test_nft_interface(self):
        from ferm.nft import generate_nft_command
        rule = Rule()
        rule.interface = 'eth0'
        rule.target = 'ACCEPT'
        cmd = generate_nft_command(rule, 'INPUT')
        assert 'iif eth0' in cmd
    
    def test_nft_interface_negated(self):
        from ferm.nft import generate_nft_command
        rule = Rule()
        rule.interface = '!lo'
        rule.target = 'ACCEPT'
        cmd = generate_nft_command(rule, 'INPUT')
        assert 'iif != lo' in cmd
    
    def test_nft_outer_interface(self):
        from ferm.nft import generate_nft_command
        rule = Rule()
        rule.outer_interface = 'eth0'
        rule.target = 'ACCEPT'
        cmd = generate_nft_command(rule, 'OUTPUT')
        assert 'oif eth0' in cmd
    
    def test_nft_source(self):
        from ferm.nft import generate_nft_command
        rule = Rule()
        rule.source = '192.168.1.0/24'
        rule.target = 'ACCEPT'
        cmd = generate_nft_command(rule, 'INPUT')
        assert 'ip saddr 192.168.1.0/24' in cmd
    
    def test_nft_dest(self):
        from ferm.nft import generate_nft_command
        rule = Rule()
        rule.dest = '10.0.0.1'
        rule.target = 'ACCEPT'
        cmd = generate_nft_command(rule, 'OUTPUT')
        assert 'ip daddr 10.0.0.1' in cmd
    
    def test_nft_multiport(self):
        from ferm.nft import generate_nft_command
        rule = Rule()
        rule.dport = '(80 443)'
        rule.target = 'ACCEPT'
        cmd = generate_nft_command(rule, 'INPUT')
        assert 'dport' in cmd
    
    def test_nft_ctstate(self):
        from ferm.nft import generate_nft_command
        rule = Rule()
        rule.ctstate = 'ESTABLISHED,RELATED'
        rule.target = 'ACCEPT'
        cmd = generate_nft_command(rule, 'INPUT')
        assert 'ct state' in cmd
    
    def test_nft_mark(self):
        from ferm.nft import generate_nft_command
        rule = Rule()
        rule.mark = '0x1'
        rule.target = 'ACCEPT'
        cmd = generate_nft_command(rule, 'INPUT')
        assert 'mark 0x1' in cmd
    
    def test_nft_tos(self):
        from ferm.nft import generate_nft_command
        rule = Rule()
        rule.tos = '0x05'
        rule.target = 'ACCEPT'
        cmd = generate_nft_command(rule, 'INPUT')
        assert 'meta tos' in cmd
    
    def test_nft_drop(self):
        from ferm.nft import generate_nft_command
        rule = Rule()
        rule.target = 'DROP'
        cmd = generate_nft_command(rule, 'INPUT')
        assert 'drop' in cmd
    
    def test_nft_reject(self):
        from ferm.nft import generate_nft_command
        rule = Rule()
        rule.target = 'REJECT'
        cmd = generate_nft_command(rule, 'INPUT')
        assert 'reject' in cmd
    
    def test_nft_return(self):
        from ferm.nft import generate_nft_command
        rule = Rule()
        rule.target = 'RETURN'
        cmd = generate_nft_command(rule, 'INPUT')
        assert 'return' in cmd
    
    def test_nft_log(self):
        from ferm.nft import generate_nft_command
        rule = Rule()
        rule.target = 'LOG'
        rule.log_prefix = 'TEST '
        cmd = generate_nft_command(rule, 'INPUT')
        assert 'log' in cmd
    
    def test_nft_redirect(self):
        from ferm.nft import generate_nft_command
        rule = Rule()
        rule.target = 'REDIRECT'
        cmd = generate_nft_command(rule, 'INPUT')
        assert 'redirect' in cmd
    
    def test_nft_mangle_table(self):
        from ferm.nft import generate_nft_rules
        domain = Domain('ip')
        domain.tables['mangle'] = Table('mangle')
        domain.tables['mangle'].chains['PREROUTING'] = Chain('PREROUTING', 'mangle')
        rule = Rule()
        rule.table = 'mangle'
        rule.target = 'ACCEPT'
        domain.tables['mangle'].chains['PREROUTING'].rules.append(rule)
        result = generate_nft_rules({'ip': domain})
        assert 'table inet mangle' in result
    
    def test_sanitize_nft(self):
        from ferm.nft import sanitize_nft
        assert sanitize_nft('test') == 'test'
        assert sanitize_nft(str(123)) == '123'
        with pytest.raises(ValueError):
            sanitize_nft('test\n')
    
    def test_nft_proto_negated(self):
        from ferm.nft import generate_nft_command
        rule = Rule()
        rule.protocol = '!tcp'
        rule.target = 'ACCEPT'
        cmd = generate_nft_command(rule, 'INPUT')
        assert 'ip protocol != tcp' in cmd
    
    def test_nft_ip6(self):
        from ferm.nft import generate_nft_rules
        domain = Domain('ip6')
        domain.tables['filter'] = Table('filter')
        domain.tables['filter'].chains['INPUT'] = Chain('INPUT', 'filter')
        rule = Rule()
        rule.target = 'ACCEPT'
        domain.tables['filter'].chains['INPUT'].rules.append(rule)
        result = generate_nft_rules({'ip6': domain})
        assert 'table inet filter' in result
    
    def test_nft_policy_drop(self):
        from ferm.nft import generate_nft_rules
        domain = Domain('ip')
        domain.tables['filter'] = Table('filter')
        chain = Chain('INPUT', 'filter', policy='DROP')
        domain.tables['filter'].chains['INPUT'] = chain
        result = generate_nft_rules({'ip': domain})
        assert 'policy drop' in result
    
    def test_apply_nft_rules_dry_run(self):
        from ferm.nft import apply_nft_rules
        result = apply_nft_rules(dry_run=True)
        assert result == True


if __name__ == '__main__':
    pytest.main([__file__, '-v'])


class TestConstants:
    def test_constants_loaded(self):
        assert MATCH_DEFS is not None
        assert TARGET_DEFS is not None
        assert SHORTCUTS is not None
        assert BUILTIN_CHAINS is not None
        assert BUILTIN_TARGETS is not None
    
    def test_get_constants(self):
        constants = get_constants()
        assert 'match' in constants
        assert 'target' in constants
    
    def test_match_defs_structure(self):
        assert 'ip' in MATCH_DEFS
        assert 'ip6' in MATCH_DEFS
    
    def test_target_defs_structure(self):
        assert 'ip' in TARGET_DEFS
        assert 'ip6' in TARGET_DEFS
    
    def test_shortcuts_structure(self):
        assert 'ip' in SHORTCUTS
        assert 'ip6' in SHORTCUTS
    
    def test_builtin_chains(self):
        assert isinstance(BUILTIN_CHAINS, dict)
    
    def test_builtin_targets(self):
        assert isinstance(BUILTIN_TARGETS, set)
        assert 'ACCEPT' in BUILTIN_TARGETS
        assert 'DROP' in BUILTIN_TARGETS


class TestParserMore:
    def test_rule_copy(self):
        rule = Rule()
        rule.protocol = 'tcp'
        rule.dport = '80'
        rule.target = 'ACCEPT'
        rule_copy = rule.copy()
        assert rule_copy.protocol == 'tcp'
        assert rule_copy.dport == '80'
        assert rule_copy.target == 'ACCEPT'
    
    def test_rule_copy_preserves_negated(self):
        rule = Rule()
        rule.protocol = 'tcp'
        rule.negated.add('protocol')
        rule_copy = rule.copy()
        assert 'protocol' in rule_copy.negated
    
    def test_chain_init(self):
        chain = Chain('INPUT', 'filter', 'DROP')
        assert chain.name == 'INPUT'
        assert chain.table == 'filter'
        assert chain.policy == 'DROP'
    
    def test_table_init(self):
        table = Table('filter')
        assert table.name == 'filter'
        assert table.chains == {}
    
    def test_domain_init(self):
        domain = Domain('ip')
        assert domain.name == 'ip'
        assert domain.enabled == False
        assert domain.tables == {}
    
    def test_parser_with_filename(self):
        lexer = Lexer('table filter { chain INPUT { policy DROP; } }', '/path/to/file.conf')
        tokens = lexer.tokenize()
        parser = Parser(tokens, filename='/path/to/file.conf')
        domains = parser.parse()
        assert 'ip' in domains
    
    def test_parser_with_defines(self):
        lexer = Lexer('@def $PORT = 8080; table filter { chain INPUT { dport $PORT ACCEPT; } }')
        tokens = lexer.tokenize()
        parser = Parser(tokens, defines={'$PORT': '8080'})
        domains = parser.parse()
        chain = domains['ip'].tables['filter'].chains['INPUT']
        assert chain.rules[0].dport == '8080'
    
    def test_parse_multiple_tables(self):
        lexer = Lexer('table filter { chain INPUT { policy DROP; } } table nat { chain PREROUTING { } }')
        tokens = lexer.tokenize()
        parser = Parser(tokens)
        domains = parser.parse()
        assert 'filter' in domains['ip'].tables
        assert 'nat' in domains['ip'].tables
    
    def test_parse_multiple_chains(self):
        lexer = Lexer('table filter { chain INPUT { policy DROP; } chain OUTPUT { policy ACCEPT; } }')
        tokens = lexer.tokenize()
        parser = Parser(tokens)
        domains = parser.parse()
        assert 'INPUT' in domains['ip'].tables['filter'].chains
        assert 'OUTPUT' in domains['ip'].tables['filter'].chains
    
    def test_parse_table_policy(self):
        lexer = Lexer('table filter { chain INPUT { policy DROP; } }')
        tokens = lexer.tokenize()
        parser = Parser(tokens)
        domains = parser.parse()
        chain = domains['ip'].tables['filter'].chains['INPUT']
        assert chain.policy == 'DROP'
    
    def test_parse_saddr(self):
        lexer = Lexer('table filter { chain INPUT { saddr 192.168.1.0/24 ACCEPT; } }')
        tokens = lexer.tokenize()
        parser = Parser(tokens)
        domains = parser.parse()
        chain = domains['ip'].tables['filter'].chains['INPUT']
        assert chain.rules[0].source == '192.168.1.0/24'
    
    def test_parse_daddr(self):
        lexer = Lexer('table filter { chain INPUT { daddr 10.0.0.1 ACCEPT; } }')
        tokens = lexer.tokenize()
        parser = Parser(tokens)
        domains = parser.parse()
        chain = domains['ip'].tables['filter'].chains['INPUT']
        assert chain.rules[0].dest == '10.0.0.1'
    
    def test_parse_saddr_with_var(self):
        lexer = Lexer('@def $NET = 10.0.0.0/8; table filter { chain INPUT { saddr $NET ACCEPT; } }')
        tokens = lexer.tokenize()
        parser = Parser(tokens)
        domains = parser.parse()
        chain = domains['ip'].tables['filter'].chains['INPUT']
        assert chain.rules[0].source is not None
    
    def test_parse_negated_proto(self):
        lexer = Lexer('table filter { chain INPUT { proto tcp ACCEPT; } }')
        tokens = lexer.tokenize()
        parser = Parser(tokens)
        domains = parser.parse()
        chain = domains['ip'].tables['filter'].chains['INPUT']
        assert chain.rules[0].protocol == 'tcp'
    
    def test_parse_proto_udp(self):
        lexer = Lexer('table filter { chain INPUT { proto udp ACCEPT; } }')
        tokens = lexer.tokenize()
        parser = Parser(tokens)
        domains = parser.parse()
        chain = domains['ip'].tables['filter'].chains['INPUT']
        assert chain.rules[0].protocol == 'udp'
    
    def test_parse_proto_icmp(self):
        lexer = Lexer('table filter { chain INPUT { proto icmp ACCEPT; } }')
        tokens = lexer.tokenize()
        parser = Parser(tokens)
        domains = parser.parse()
        chain = domains['ip'].tables['filter'].chains['INPUT']
        assert chain.rules[0].protocol == 'icmp'
    
    def test_parse_multiport_dports(self):
        lexer = Lexer('table filter { chain INPUT { proto tcp dport (80 443 8080) ACCEPT; } }')
        tokens = lexer.tokenize()
        parser = Parser(tokens)
        domains = parser.parse()
        chain = domains['ip'].tables['filter'].chains['INPUT']
        assert chain.rules[0].dport == '(80 443 8080)'
    
    def test_parse_rule_with_module(self):
        lexer = Lexer('table filter { chain INPUT { mod state state ESTABLISHED ACCEPT; } }')
        tokens = lexer.tokenize()
        parser = Parser(tokens)
        domains = parser.parse()
        chain = domains['ip'].tables['filter'].chains['INPUT']
        assert 'state' in chain.rules[0].match_modules
    
    def test_parse_log_target_only(self):
        lexer = Lexer('table filter { chain INPUT { LOG; } }')
        tokens = lexer.tokenize()
        parser = Parser(tokens)
        domains = parser.parse()
        chain = domains['ip'].tables['filter'].chains['INPUT']
        assert chain.rules[0].target == 'LOG'
    
    def test_parse_target_options(self):
        lexer = Lexer('table nat { chain PREROUTING { DNAT to 192.168.1.1:8080; } }')
        tokens = lexer.tokenize()
        parser = Parser(tokens)
        domains = parser.parse()
        chain = domains['ip'].tables['nat'].chains['PREROUTING']
        assert chain.rules[0].target == 'DNAT'
    
    def test_parse_at_def(self):
        lexer = Lexer('@def $VAR1 = value1; @def $VAR2 = value2; table filter { chain INPUT { } }')
        tokens = lexer.tokenize()
        parser = Parser(tokens)
        domains = parser.parse()
        assert 'filter' in domains['ip'].tables
    
    def test_parse_empty_chain(self):
        lexer = Lexer('table filter { chain INPUT { } }')
        tokens = lexer.tokenize()
        parser = Parser(tokens)
        domains = parser.parse()
        assert 'INPUT' in domains['ip'].tables['filter'].chains
    
    def test_parse_multiple_rules(self):
        lexer = Lexer('table filter { chain INPUT { interface lo ACCEPT; interface eth0 DROP; } }')
        tokens = lexer.tokenize()
        parser = Parser(tokens)
        domains = parser.parse()
        chain = domains['ip'].tables['filter'].chains['INPUT']
        assert len(chain.rules) == 2
    
    def test_parse_rules_with_policy(self):
        lexer = Lexer('table filter { chain INPUT { policy DROP; interface lo ACCEPT; } }')
        tokens = lexer.tokenize()
        parser = Parser(tokens)
        domains = parser.parse()
        chain = domains['ip'].tables['filter'].chains['INPUT']
        assert chain.policy == 'DROP'
    
    def test_parse_domain(self):
        lexer = Lexer('domain ip; table filter { chain INPUT { policy DROP; } }')
        tokens = lexer.tokenize()
        parser = Parser(tokens)
        domains = parser.parse()
        assert 'ip' in domains
    
    def test_parse_table_mangle(self):
        lexer = Lexer('table mangle { chain PREROUTING { } }')
        tokens = lexer.tokenize()
        parser = Parser(tokens)
        domains = parser.parse()
        assert 'mangle' in domains['ip'].tables
    
    def test_parse_table_raw(self):
        lexer = Lexer('table raw { chain PREROUTING { } }')
        tokens = lexer.tokenize()
        parser = Parser(tokens)
        domains = parser.parse()
        assert 'raw' in domains['ip'].tables
    
    def test_parse_empty_rules(self):
        lexer = Lexer('table filter { chain INPUT { } }')
        tokens = lexer.tokenize()
        parser = Parser(tokens)
        domains = parser.parse()
        chain = domains['ip'].tables['filter'].chains['INPUT']
        assert len(chain.rules) == 0
    
    def test_parse_dport_only(self):
        lexer = Lexer('table filter { chain INPUT { proto tcp dport 443 ACCEPT; } }')
        tokens = lexer.tokenize()
        parser = Parser(tokens)
        domains = parser.parse()
        chain = domains['ip'].tables['filter'].chains['INPUT']
        assert chain.rules[0].dport == '443'
    
    def test_parse_policy_accept(self):
        lexer = Lexer('table filter { chain INPUT { policy ACCEPT; } }')
        tokens = lexer.tokenize()
        parser = Parser(tokens)
        domains = parser.parse()
        chain = domains['ip'].tables['filter'].chains['INPUT']
        assert chain.policy == 'ACCEPT'
    
    def test_parse_policy_drop(self):
        lexer = Lexer('table filter { chain INPUT { policy DROP; } }')
        tokens = lexer.tokenize()
        parser = Parser(tokens)
        domains = parser.parse()
        chain = domains['ip'].tables['filter'].chains['INPUT']
        assert chain.policy == 'DROP'
    
    def test_parse_interface_eth(self):
        lexer = Lexer('table filter { chain INPUT { interface eth0 ACCEPT; } }')
        tokens = lexer.tokenize()
        parser = Parser(tokens)
        domains = parser.parse()
        chain = domains['ip'].tables['filter'].chains['INPUT']
        assert chain.rules[0].interface == 'eth0'
    
    def test_parse_interface_wlan(self):
        lexer = Lexer('table filter { chain INPUT { interface wlan0 ACCEPT; } }')
        tokens = lexer.tokenize()
        parser = Parser(tokens)
        domains = parser.parse()
        chain = domains['ip'].tables['filter'].chains['INPUT']
        assert chain.rules[0].interface == 'wlan0'


class TestOutputMore:
    def test_generate_iptables_with_table_nat(self):
        rule = Rule()
        rule.table = 'nat'
        rule.target = 'DNAT'
        rule.target_options = ['to', '1.2.3.4:8080']
        cmd = generate_iptables_command(rule, 'PREROUTING')
        assert '-t' in cmd
        assert 'nat' in cmd
    
    def test_generate_iptables_negated_proto(self):
        rule = Rule()
        rule.protocol = '!tcp'
        rule.target = 'ACCEPT'
        cmd = generate_iptables_command(rule, 'INPUT')
        assert '!' in cmd
        assert '-p' in cmd
    
    def test_generate_iptables_negated_dest(self):
        rule = Rule()
        rule.dest = '!192.168.1.0/24'
        rule.target = 'ACCEPT'
        cmd = generate_iptables_command(rule, 'INPUT')
        assert '!' in cmd
    
    def test_generate_iptables_ttl(self):
        rule = Rule()
        rule.ttl = 'set 64'
        rule.target = 'ACCEPT'
        cmd = generate_iptables_command(rule, 'INPUT')
        assert '-m' in cmd
        assert 'ttl' in cmd
    
    def test_generate_iptables_match_modules(self):
        rule = Rule()
        rule.match_modules = {'limit': {'limit': '10/minute'}}
        rule.target = 'LOG'
        cmd = generate_iptables_command(rule, 'INPUT')
        assert '-m' in cmd
        assert 'limit' in cmd
    
    def test_generate_iptables_target_options(self):
        rule = Rule()
        rule.target = 'DNAT'
        rule.target_options = ['to', '1.2.3.4:8080']
        cmd = generate_iptables_command(rule, 'PREROUTING')
        assert '-j' in cmd
    
    def test_generate_iptables_restore_multiple_tables(self):
        domain = Domain('ip')
        domain.tables['filter'] = Table('filter')
        domain.tables['filter'].chains['INPUT'] = Chain('INPUT', 'filter')
        domain.tables['nat'] = Table('nat')
        domain.tables['nat'].chains['PREROUTING'] = Chain('PREROUTING', 'nat')
        
        domain.tables['filter'].chains['INPUT'].rules.append(Rule())
        domain.tables['filter'].chains['INPUT'].rules[0].target = 'ACCEPT'
        
        domain.tables['nat'].chains['PREROUTING'].rules.append(Rule())
        domain.tables['nat'].chains['PREROUTING'].rules[0].target = 'DNAT'
        
        result = generate_iptables_restore({'ip': domain})
        assert '*filter' in result['ip']
        assert '*nat' in result['ip']


class TestNftMore:
    def test_nft_proto(self):
        from ferm.nft import generate_nft_command
        rule = Rule()
        rule.protocol = 'tcp'
        rule.target = 'ACCEPT'
        cmd = generate_nft_command(rule, 'INPUT')
        assert 'tcp accept' in cmd
    
    def test_nft_sport(self):
        from ferm.nft import generate_nft_command
        rule = Rule()
        rule.sport = '80'
        rule.target = 'ACCEPT'
        cmd = generate_nft_command(rule, 'INPUT')
        assert 'sport 80' in cmd
    
    def test_nft_negated_ctstate(self):
        from ferm.nft import generate_nft_command
        rule = Rule()
        rule.ctstate = '!ESTABLISHED'
        rule.target = 'ACCEPT'
        cmd = generate_nft_command(rule, 'INPUT')
        assert 'ct state != established' in cmd
    
    def test_nft_negated_mark(self):
        from ferm.nft import generate_nft_command
        rule = Rule()
        rule.mark = '!0x1'
        rule.target = 'ACCEPT'
        cmd = generate_nft_command(rule, 'INPUT')
        assert 'mark != 0x1' in cmd
    
    def test_nft_negated_tos(self):
        from ferm.nft import generate_nft_command
        rule = Rule()
        rule.tos = '!0x05'
        rule.target = 'ACCEPT'
        cmd = generate_nft_command(rule, 'INPUT')
        assert 'meta mark != 0x05' in cmd
    
    def test_nft_match_modules(self):
        from ferm.nft import generate_nft_command
        rule = Rule()
        rule.match_modules = {'limit': {'limit': '10/minute'}}
        rule.target = 'LOG'
        cmd = generate_nft_command(rule, 'INPUT')
        assert 'limit limit 10/minute' in cmd
    
    def test_nft_state_module(self):
        from ferm.nft import generate_nft_command
        rule = Rule()
        rule.match_modules = {'state': {'state': 'ESTABLISHED'}}
        rule.target = 'ACCEPT'
        cmd = generate_nft_command(rule, 'INPUT')
        assert 'ct state ESTABLISHED' in cmd
    
    def test_nft_jump(self):
        from ferm.nft import generate_nft_command
        rule = Rule()
        rule.target = 'CUSTOM_CHAIN'
        cmd = generate_nft_command(rule, 'INPUT')
        assert 'jump CUSTOM_CHAIN' in cmd
    
    def test_nft_rules_multiple_domains(self):
        domain_ip = Domain('ip')
        domain_ip.tables['filter'] = Table('filter')
        domain_ip.tables['filter'].chains['INPUT'] = Chain('INPUT', 'filter')
        domain_ip.tables['filter'].chains['INPUT'].rules.append(Rule())
        domain_ip.tables['filter'].chains['INPUT'].rules[0].target = 'ACCEPT'
        
        domain_ip6 = Domain('ip6')
        domain_ip6.tables['filter'] = Table('filter')
        domain_ip6.tables['filter'].chains['INPUT'] = Chain('INPUT', 'filter')
        domain_ip6.tables['filter'].chains['INPUT'].rules.append(Rule())
        domain_ip6.tables['filter'].chains['INPUT'].rules[0].target = 'DROP'
        
        result = generate_nft_rules({'ip': domain_ip, 'ip6': domain_ip6})
        assert 'table inet filter' in result
        assert 'chain input' in result
