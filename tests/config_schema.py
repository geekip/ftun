#!/usr/bin/env python3
"""TEST-CONFIG-SCHEMA-001: Draft 2020-12 shape/boundary checks, not FTUN runtime checks."""
import copy
import json
import sys
import unittest
from pathlib import Path

try:
    from jsonschema import Draft202012Validator, FormatChecker
except ImportError:
    print('SKIP: config schema tests require: python3 -m pip install -r tools/requirements-schema.txt')
    sys.exit(77)  # CTest SKIP_RETURN_CODE; never report missing validator as a pass.

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = json.loads((ROOT / 'schema.json').read_text(encoding='utf-8'))
VALIDATOR = Draft202012Validator(SCHEMA, format_checker=FormatChecker())


def tun(**values):
    return dict(type='tun', name='tun-in', interface={'name': 'ftun0'},
                ipv4={'address': '172.19.0.1/30'}, **values)


def node(**values):
    return dict(type='socks5', name='proxy', server='proxy.example.com:1080', **values)


def group(kind='select', **values):
    result = {'type': kind, 'name': 'group', 'outbounds': ['proxy'], 'default': 'proxy'}
    if kind == 'url-test':
        result['url'] = 'https://probe.example.com/204'
    result.update(values)
    return result


class ConfigSchemaTest(unittest.TestCase):
    def valid(self, value):
        errors = list(VALIDATOR.iter_errors(value))
        self.assertFalse(errors, '\n'.join(str(e) for e in errors))

    def invalid(self, value):
        self.assertTrue(list(VALIDATOR.iter_errors(value)), repr(value))

    def test_meta_schema_and_local_refs(self):
        Draft202012Validator.check_schema(SCHEMA)
        def walk(value):
            if isinstance(value, dict):
                if '$ref' in value:
                    self.assertTrue(value['$ref'].startswith('#/$defs/'))
                    self.assertIn(value['$ref'].removeprefix('#/$defs/'), SCHEMA['$defs'])
                for child in value.values():
                    walk(child)
            elif isinstance(value, list):
                for child in value:
                    walk(child)
        walk(SCHEMA)

    def test_shipped_examples(self):
        for path in sorted((ROOT / 'examples').glob('*.json')):
            with self.subTest(path=path.name):
                value = json.loads(path.read_text(encoding='utf-8'))
                self.assertEqual((path.parent / value['$schema']).resolve(), ROOT / 'schema.json')
                self.valid(value)

    def test_empty_objects_and_default_annotations(self):
        self.valid({})  # Embedding/fragments are distinct from CLI run's non-empty input requirement.
        self.valid({'base': {}, 'dns': {}, 'geo': {}, 'sniff': {}, 'rules': []})
        original = {'inbounds': [tun()]}
        value = copy.deepcopy(original)
        self.valid(value)
        self.assertEqual(value, original)  # JSON Schema defaults must not mutate the config.
        def walk(value):
            if not isinstance(value, dict):
                return
            if 'default' in value:
                validator = VALIDATOR.evolve(schema=value)
                self.assertTrue(validator.is_valid(value['default']), repr(value))
            # A property literally named "default" is not a schema annotation.
            for key in ('properties', '$defs', 'patternProperties', 'dependentSchemas'):
                for child in value.get(key, {}).values():
                    walk(child)
            for key in ('items', 'additionalProperties', 'propertyNames', 'contains', 'not', 'if', 'then', 'else'):
                walk(value.get(key))
            for key in ('allOf', 'anyOf', 'oneOf', 'prefixItems'):
                for child in value.get(key, []):
                    walk(child)
        walk(SCHEMA)

    def test_unknown_fields_and_wrong_types(self):
        cases = [[], None, {'logging': {}}, {'base': {'ipvv6': False}},
                 {'dns': {'enable': 'false'}}, {'sniff': {'sni': True}},
                 {'dns': {'fake-ip': {'pool': '198.18.0.0/15'}}},
                 {'inbounds': [{'type': 'socks5', 'name': 'in', 'listen': '127.0.0.1:1080', 'tcp': True}]},
                 {'outbounds': [dict(node(), udp=1)]}, {'outbounds': [dict(group(), tolerance=20)]}]
        for value in cases:
            with self.subTest(value=value): self.invalid(value)

    def test_future_features_are_rejected(self):
        for value in [{'api': {'enable': False}}, {'base': {'ipv6': True}},
                      {'inbounds': [{'name': 'a', 'type': 'anytls', 'listen': '127.0.0.1:443'}]},
                      {'outbounds': [{'name': 'a', 'type': 'anytls', 'server': 'example.com:443'}]},
                      {'outbounds': [{'name': 'custom', 'type': 'direct'}]},
                      {'dns': {'servers': [{'name': 'd', 'type': 'https', 'address': ['dns.example.com']}]} }]:
            with self.subTest(value=value): self.invalid(value)

    def test_ipv4_and_port_boundaries(self):
        for address in ['0.0.0.0:1', '127.0.0.1:1080', '255.255.255.255:65535']:
            self.valid({'inbounds': [{'type': 'socks5', 'name': 's', 'listen': address}]})
        for address in ['256.0.0.1:80', '127.1:80', '01.0.0.1:80', '127.0.0.1:0',
                        '127.0.0.1:65536', '127.0.0.1:080', '[::1]:80', 'localhost:80',
                        '127.0.0.1', '127.0.0.1:80\n']:
            with self.subTest(address=address):
                self.invalid({'inbounds': [{'type': 'mixed', 'name': 's', 'listen': address}]})

    def test_server_and_bootstrap_addresses(self):
        for address in ['proxy.example.com:1080', 'localhost:80', 'xn--fiqs8s.example.:65535',
                        '192.0.2.1:443', '123.local:80']:
            self.valid({'outbounds': [dict(node(), server=address)]})
        for address in ['proxy.example.com', 'http://example.com:80', '999.1.1.1:80',
                        '192.0.2.1:65536', 'proxy..example.com:80', '-proxy.example:80',
                        '代理.example:80', 'proxy.example:80\n', '[::1]:1080', 'a'*64+'.com:80']:
            with self.subTest(address=address):
                self.invalid({'outbounds': [dict(node(), server=address)]})
        self.valid({'dns': {'bootstrap': ['192.0.2.1', '192.0.2.2:65535']}})
        for address in ['resolver.example.com', '127.0.0.1:0', '::1', '999.1.1.1']:
            self.invalid({'dns': {'bootstrap': [address]}})
        for address in ['dns.example.com', 'dns.example.com:53', '192.0.2.53']:
            self.valid({'dns': {'servers': [{'name': 'd', 'type': 'tcp', 'address': [address]}]}})

    def test_domain_total_length(self):
        limit = '.'.join(['a' * 63, 'b' * 63, 'c' * 63, 'd' * 61])
        self.assertEqual(len(limit), 253)
        for domain in [limit, limit + '.']:
            self.valid({'outbounds': [dict(node(), server=domain + ':80')]})
            self.valid({'rules': ['DOMAIN,' + domain + ',DIRECT']})
        for domain in [limit + 'd', limit + 'd.']:
            self.invalid({'outbounds': [dict(node(), server=domain + ':80')]})
            self.invalid({'rules': ['DOMAIN,' + domain + ',DIRECT']})

    def test_dns_shapes_and_disabled_references(self):
        self.valid({'dns': {'enable': False, 'default-server': 'missing',
                           'listeners': [{'listen': '127.0.0.1:53', 'server': 'missing'}]},
                    'outbounds': [node(**{'dns-server': 'missing'})], 'geo': {'dns-server': 'missing'},
                    'inbounds': [tun(**{'dns-hijack': True})]})
        self.valid({'dns': {'listeners': [{'listen': '127.0.0.1:53'},
                                         {'listen': '127.0.0.1:5353', 'server': ''}]}})
        for value in [{'dns': {'servers': [{'name': 'd', 'type': 'udp', 'address': []}]}},
                      {'dns': {'enable': False, 'cache': 'false'}},
                      {'dns': {'servers': [{'name': 'd', 'fake-ip': True}]}},
                      {'dns': {'listeners': [{'server': 'd'}]}}]:
            self.invalid(value)

    def test_tun_constraints_and_omitted_defaults(self):
        for value in [tun(), tun(tcp=False), tun(udp=False),
                      tun(**{'strict-route': True, 'auto-route': True})]:
            self.valid({'inbounds': [value]})
        for value in [tun(tcp=False, udp=False), tun(**{'strict-route': True}),
                      tun(**{'strict-route': True, 'auto-route': False}), tun(users={}),
                      tun(listen='127.0.0.1:80'), dict(tun(), stack='gvisor'),
                      dict(tun(), interface={'name': 'ftun0', 'mtu': 0}),
                      dict(tun(), ipv4={}), dict(tun(), interface={})]:
            with self.subTest(value=value): self.invalid({'inbounds': [value]})
        self.invalid({'inbounds': [tun(), dict(tun(), name='tun2')]})

    def test_cidr_limits(self):
        for cidr in ['0.0.0.0/0', '198.18.0.0/15', '255.255.255.255/32']:
            self.valid({'dns': {'fake-ip': {'range': cidr}}})
        for cidr in ['198.18.0.0/33', '::/0', '999.0.0.0/8', '198.18.0.0', '198.18.0.0/15\n']:
            self.invalid({'dns': {'fake-ip': {'range': cidr}}})

    def test_credentials_and_auth_pair(self):
        self.valid({'outbounds': [node(username='user', password='password')]})
        self.valid({'inbounds': [{'type': 'mixed', 'name': 'in', 'listen': '127.0.0.1:80',
                                 'users': {'user': 'secret'}}]})
        for fields in [{'username': 'u'}, {'password': 'p'}, {'username': '', 'password': 'p'},
                       {'username': 'u', 'password': 'p'*256}]:
            self.invalid({'outbounds': [node(**fields)]})
        self.invalid({'inbounds': [{'type': 'socks5', 'name': 'in', 'listen': '127.0.0.1:80', 'users': {'': 'p'}}]})

    def test_groups_names_and_required_fields(self):
        self.valid({'outbounds': [node(), group(), group('url-test', name='auto')]})
        self.valid({'outbounds': [dict(node(), name='香港 01')]})
        for value in [dict(node(), name='DIRECT'), dict(node(), name='REJECT'),
                      dict(node(), name='bad,name'), dict(node(), name='bad\n'),
                      group(outbounds=[]), group(default=''), group('url-test', tolerance=-1),
                      group('url-test', **{'expected-status': 600})]:
            with self.subTest(value=value): self.invalid({'outbounds': [value]})
        for key in ['name', 'type', 'outbounds', 'default']:
            value = group(); del value[key]
            self.invalid({'outbounds': [value]})

    def test_duration_and_http_url(self):
        for duration in ['1ms', '5s', '5m', '24h']:
            self.valid({'outbounds': [group('url-test', interval=duration)]})
        for duration in ['0s', '-1s', '5', '1.5s', '1d', '5m\n']:
            self.invalid({'outbounds': [group('url-test', timeout=duration)]})
        for url in ['https://example.com', 'http://192.0.2.1:65535/a?b=c', 'https://example.com./204']:
            self.valid({'outbounds': [group('url-test', url=url)]})
        for url in ['ftp://example.com', 'https://', 'https://example.com:65536',
                    'https://999.1.1.1/', 'https://[::1]/', 'https://exa mple.com/',
                    'https://example.com/\n']:
            self.invalid({'outbounds': [group('url-test', url=url)]})

    def test_geo_activation_and_updates(self):
        self.valid({'geo': {'geoip': {}, 'geosite': {}}})  # Unused objects have no file dependency.
        self.valid({'geo': {'geoip': {'path': 'geo.ftgeo'}}, 'rules': ['GEOIP,CN,DIRECT']})
        self.valid({'geo': {'auto-update': True, 'geoip': {'path': 'geo.ftgeo', 'url': 'https://example.com/geo'}}})
        for value in [{'rules': ['GEOIP,CN,DIRECT']},
                      {'geo': {'geosite': {}}, 'rules': ['GEOSITE,private,DIRECT']},
                      {'geo': {'auto-update': True, 'geoip': {'path': 'geo.ftgeo'}}},
                      {'geo': {'auto-update': True, 'geosite': {'url': 'https://example.com/geo'}}}]:
            self.invalid(value)

    def test_all_rule_kinds_and_boundaries(self):
        rules = ['SRC-IP-CIDR,192.168.0.1/32,REJECT', 'IP-CIDR,0.0.0.0/0,DIRECT',
                 'DOMAIN,A.COM.,proxy', 'DOMAIN-SUFFIX,xn--fiqs8s.com,proxy',
                 'DOMAIN-KEYWORD,google,proxy', 'DST-PORT,1,DIRECT', 'DST-PORT,65535,DIRECT',
                 'NETWORK,tcp,proxy', 'NETWORK,udp,DIRECT', 'MATCH,香港 01']
        self.valid({'rules': rules})
        for rule in ['IP-CIDR,10.0.0.0/33,DIRECT', 'IP-CIDR,10.0.0.0/8,DIRECT,no-resolve',
                     'DOMAIN-REGEX,.*example.*,proxy', 'DOMAIN,*.example.com,proxy',
                     'DOMAIN,中文.com,proxy', 'DOMAIN,,DIRECT', 'DOMAIN-KEYWORD,,DIRECT',
                     'DOMAIN-KEYWORD,中文,DIRECT', 'GEOSITE-REGEX,private,proxy',
                     'SRC-IP-CIDR,::/0,DIRECT', 'DST-PORT,0,DIRECT', 'DST-PORT,80-90,DIRECT',
                     'DST-PORT,65536,DIRECT', 'NETWORK,icmp,DIRECT', 'MATCH,',
                     'INBOUND,tun-in,proxy', 'MATCH,DIRECT\n']:
            with self.subTest(rule=rule): self.invalid({'rules': [rule]})

    def test_runtime_only_relationships_are_not_fake_schema_checks(self):
        # These intentionally pass structural validation; runtime MUST reject active invalid references.
        self.valid({'outbounds': [group(default='not-a-member')]})
        self.valid({'outbounds': [group(outbounds=['group'], default='group')]})
        self.valid({'outbounds': [node(), dict(node(), server='other.example.com:80')]})
        self.valid({'dns': {'default-server': 'missing'}})
        self.valid({'outbounds': [group('url-test', timeout='10m', interval='1s')]})


if __name__ == '__main__':
    unittest.main(verbosity=2)
