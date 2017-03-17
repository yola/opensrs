from unittest import TestCase

from mock import Mock, patch

from opensrs import opensrsapi, xcp, errors
from opensrs.constants import OrderProcessingMethods
from test_settings import CONNECTION_OPTIONS


def disabletest(func):
    func.__test__ = False
    return func


class DictAttrs(object):
    def __init__(self, mappings=None, **kw):
        if mappings is None:
            mappings = kw
        for k, v in mappings.items():
            setattr(self, k, v)


class XCPChannelPlaygroundTest(TestCase):
    """This is a temporary class to allow fiddling with the actual test server.

    It is currently not intended for running actual tests.
    """

    @disabletest
    def _disabled_test_make_request(self):
        lookup_msg = opensrsapi.XCPMessage(
            action='LOOKUP', object='DOMAIN',
            attributes={'domain': 'example.com'})
        channel = opensrsapi.XCPChannel(**CONNECTION_OPTIONS)
        self.assertEqual(
            '1', channel.make_request(lookup_msg).get_data()['is_success'])

    @disabletest
    def test_suggest(self):
        lookup_msg = opensrsapi.XCPMessage(action='NAME_SUGGEST',
                                           object='DOMAIN',
                                           attributes={
                                               'searchstring': 'foo',
                                               'tlds': ['.COM', '.ORG', '.NET',
                                                        '.INFO'],
                                               'maximum': '4',
                                           })
        channel = opensrsapi.XCPChannel(**CONNECTION_OPTIONS)
        rsp = channel.make_request(lookup_msg)
        print rsp.get_data()
        self.assertEqual('1', rsp.get_data()['is_success'])
        raise Exception()

    @disabletest
    def test_make_request_bad_auth(self):
        lookup_msg = opensrsapi.XCPMessage(
            action='LOOKUP', object='DOMAIN',
            attributes={'domain': 'example.com'})
        connection_options = CONNECTION_OPTIONS.copy()
        connection_options['private_key'] = 'bad_key'
        channel = opensrsapi.XCPChannel(**connection_options)
        self.assertRaises(errors.XCPError, channel.make_request, lookup_msg)

    @disabletest
    def test_register(self):
        class Nonce(object):
            pass
        user = Nonce()
        for k, v in {
            'first_name': 'first_name',
            'last_name': 'last_name',
            'email': 'email@example.com',
            'phone': '5551234',
            'fax': None,
            'address1': 'address1',
            'address2': 'address2',
            'address3': 'address3',
            'city': 'city',
            'state': 'state',
            'country_code': 'ZA',
            'postal_code': None,
        }.items():
            setattr(user, k, v)
        oapi = opensrsapi.OpenSRS(**CONNECTION_OPTIONS)
        rsp = oapi.sw_register_domain('foo.badtld', '1', user, 'foo', 'bar')
        self.assertEqual('1', rsp.get_data()['is_success'])
        raise Exception()


class MockXCPChannelFactory(opensrsapi.XCPChannel):
    """Mock channel factory.

    Allows protocol testing without requiring network access.
    """

    def __init__(self, test):
        self.test = test
        self.requests = []
        self.responses = []

    def add_req(self, req, resp):
        self.requests.append(req)
        self.responses.append(resp)

    def __call__(self, host, port, username, private_key, timeout):
        self.private_key = private_key
        return self

    def make_request(self, message):
        self.test.assertEqual(self.requests.pop(0),
                              message.ops_message.get_data())
        message = xcp.OPSMessage(data=self.responses.pop(0))
        if message.get_data()['is_success'] == '0':
            raise errors.XCPError(message)
        return message


class OpenSRSTest(TestCase):

    def setUp(self):
        self.mcf = MockXCPChannelFactory(self)
        self.real_channel = opensrsapi.XCPChannel
        opensrsapi.XCPChannel = self.mcf

    def tearDown(self):
        opensrsapi.XCPChannel = self.real_channel

    # Helpers for building request and response data.

    def _xcp_data(self, action, object, attributes, **kw):
        data = {'protocol': 'XCP',
                'action': action,
                'object': object,
                'attributes': attributes,
                }
        data.update(kw)
        return data

    def _xcp_reply(self, object, code, text, attributes, **kw):
        return self._xcp_data('REPLY', object, attributes,
                              is_success='1',
                              response_code=code,
                              response_text=text,
                              **kw)

    def _xcp_error(self, code, text, **kw):
        data = {'protocol': 'XCP',
                'is_success': '0',
                'response_text': text,
                'response_code': code,
                }
        data.update(kw)
        return data

    def _data_domain_lookup(self, domain):
        return self._xcp_data('LOOKUP', 'DOMAIN', {'domain': domain})

    def _data_domain_reply(self, code, text, attributes, success='1'):
        return self._xcp_reply('DOMAIN', code, text, attributes)

    def _data_suggest_domains(self, search_string, maximum):
        return self._xcp_data('NAME_SUGGEST', 'DOMAIN', {
            'searchstring': search_string,
            'services': ['lookup', 'suggestion'],
            'tlds': ['.COM', '.ORG', '.NET', '.INFO'],
            'maximum': str(maximum),
        })

    def _data_user_contact(self):
        return {
            'org_name': 'first_name last_name',
            'city': 'city',
            'first_name': 'first_name',
            'last_name': 'last_name',
            'address1': 'address1',
            'address2': 'address2',
            'address3': 'address3',
            'fax': '',
            'phone': '5551234',
            'state': 'state',
            'postal_code': '',
            'country': 'ZA',
            'email': 'email@example.com'
        }

    def _objdata_user_contact(self):
        user_data = self._data_user_contact()
        user_data['country_code'] = user_data['country']
        del user_data['country']
        return DictAttrs(user_data)

    def _data_domain_reg(self, domain, period, username, password,
                         **attribute_overrides):
        attributes = {
            'reg_username': username,
            'reg_password': password,
            'domain': domain,
            'auto_renew': '0',
            'custom_tech_contact': '1',
            'period': period,
            'custom_nameservers': '0',
            'contact_set': {
                'owner': self._data_user_contact(),
                'admin': self._data_user_contact(),
                'tech': self._data_user_contact(),
                'billing': self._data_user_contact()},
            'f_lock_domain': '1',
            'f_whois_privacy': '0',
            'reg_type': 'new',
            'handle': OrderProcessingMethods.SAVE
        }
        attributes.update(attribute_overrides)
        return self._xcp_data('SW_REGISTER', 'DOMAIN', attributes)

    def _data_process_pending(self, order_id, cancel):
        attributes = {'order_id': order_id}
        if cancel:
            attributes['command'] = 'cancel'
        return self._xcp_data('PROCESS_PENDING', 'DOMAIN', attributes)

    # Utility methods.

    def safe_opensrs(self, req, resp):
        self.mcf.add_req(req, resp)
        osrs = opensrsapi.OpenSRS('host', 'port', 'user', 'key', 'timeout')
        return osrs

    # Tests.

    def test_domain_available_bad_auth(self):
        opensrs = self.safe_opensrs(
            self._data_domain_lookup('example.com'),
            self._xcp_error('401', 'Authentication Failed'))
        self.assertRaises(errors.XCPError, opensrs.domain_available,
                          'example.com')

    def test_domain_available_210(self):
        opensrs = self.safe_opensrs(
            self._data_domain_lookup('example.com'),
            self._xcp_reply('DOMAIN', '210', 'Domain available', {}))
        self.assertTrue(opensrs.domain_available('example.com'))

    def test_domain_available_211(self):
        opensrs = self.safe_opensrs(
            self._data_domain_lookup('example.com'),
            self._xcp_reply('DOMAIN', '211', 'Domain taken', {}))
        self.assertFalse(opensrs.domain_available('example.com'))

    def test_suggest_domains(self):
        response_data = {
            'response_text': 'Command completed successfully',
            'protocol': 'XCP',
            'response_code': '200',
            'action': 'REPLY',
            'attributes': {
                'lookup': {
                    'count': '4',
                    'response_text': None,
                    'response_code': '0',
                    'is_success': '1',
                    'items': [
                        {'status': 'taken', 'domain': 'foo.com'},
                        {'status': 'taken', 'domain': 'foo.net'},
                        {'status': 'taken', 'domain': 'foo.org'},
                        {'status': 'taken', 'domain': 'foo.info'}
                    ]},
                'suggestion': {
                    'count': '4',
                    'response_text': None,
                    'response_code': '0',
                    'is_success': '1',
                    'items': [
                        {'status': 'available', 'domain': 'fooonline.com'},
                        {'status': 'available', 'domain': 'fooonline.net'},
                        {'status': 'available', 'domain': 'fooonline.org'},
                        {'status': 'available', 'domain': 'fooonline.info'}
                    ]
                }
            },
            'is_success': '1'}
        expected = {
            'lookup': [
                {'status': 'taken', 'domain': 'foo.com'},
                {'status': 'taken', 'domain': 'foo.net'},
                {'status': 'taken', 'domain': 'foo.org'},
                {'status': 'taken', 'domain': 'foo.info'},
            ],
            'suggestion': [
                {'status': 'available', 'domain': 'fooonline.com'},
                {'status': 'available', 'domain': 'fooonline.net'},
                {'status': 'available', 'domain': 'fooonline.org'},
                {'status': 'available', 'domain': 'fooonline.info'},
            ]
        }
        opensrs = self.safe_opensrs(self._data_suggest_domains('foo', 4),
                                    response_data)
        self.assertEquals(expected,
                          opensrs.suggest_domains(
                              'foo', ['.COM', '.ORG', '.NET', '.INFO'], 4))

    def test_register_fail_taken(self):
        response_data = {
            'response_text': 'Domain taken',
            'protocol': 'XCP',
            'response_code': '485',
            'object': 'DOMAIN',
            'action': 'REPLY',
            'attributes': {'forced_pending': '1064637'},
            'is_success': '0',
            'transaction_id': '2009-06-29 08:47:20 27585 101'}
        opensrs = self.safe_opensrs(
            self._data_domain_reg('foo.com', '1', 'foo', 'bar',
                                  handle=OrderProcessingMethods.PROCESS),
            response_data)
        try:
            opensrs.register_domain('foo.com', 1, self._objdata_user_contact(),
                                    'foo', 'bar')
            self.fail('Expected DomainTaken exception.')
        except errors.DomainTaken:
            pass

    def test_register_fail_timed_out(self):
        response_data = {
            'response_text': 'Timed out, resubmit request.',
            'protocol': 'XCP',
            'response_code': '705',
            'object': 'DOMAIN',
            'action': 'REPLY',
            'attributes': {},
            'is_success': '0'
        }
        opensrs = self.safe_opensrs(
            self._data_domain_reg('foo.com', '1', 'foo', 'bar',
                                  handle=OrderProcessingMethods.PROCESS),
            response_data)
        try:
            opensrs.register_domain(
                'foo.com', 1, self._objdata_user_contact(), 'foo', 'bar')
            self.fail('Expected DomainRegistrationTimedOut exception.')
        except errors.DomainRegistrationTimedOut:
            pass

    def test_register_succeed(self):
        response_data = {
            'response_text': 'Registration successful',
            'protocol': 'XCP',
            'response_code': '200',
            'object': 'DOMAIN',
            'action': 'REPLY',
            'attributes': {
                'admin_email': 'email@example.com',
                'id': '1065034'
            },
            'is_success': '1'}
        opensrs = self.safe_opensrs(
            self._data_domain_reg('foo.com', '1', 'foo', 'bar',
                                  handle=OrderProcessingMethods.PROCESS),
            response_data)
        expected = {
            'domain_name': 'foo.com',
            'registrar_data': {
                'ref_number': '1065034'
            }
        }
        self.assertEquals(expected, opensrs.register_domain(
            'foo.com', 1, self._objdata_user_contact(), 'foo', 'bar'))

    def test_register_succeed_nameservers(self):
        response_data = {
            'response_text': 'Registration successful',
            'protocol': 'XCP',
            'response_code': '200',
            'object': 'DOMAIN',
            'action': 'REPLY',
            'attributes': {
                'admin_email': 'email@example.com',
                'id': '1065034'
            },
            'is_success': '1'}
        nameservers = ['ns1.example.com', 'ns2.example.com']
        opensrs = self.safe_opensrs(
            self._data_domain_reg(
                'foo.com', '1', 'foo', 'bar', custom_nameservers='1',
                handle=OrderProcessingMethods.PROCESS,
                nameserver_list=[
                    {'name': 'ns1.example.com', 'sortorder': '1'},
                    {'name': 'ns2.example.com', 'sortorder': '2'}]
            ),
            response_data)
        expected = {
            'domain_name': 'foo.com',
            'registrar_data': {
                'ref_number': '1065034'
            }
        }
        self.assertEquals(expected, opensrs.register_domain(
            'foo.com', 1, self._objdata_user_contact(), 'foo', 'bar',
            nameservers=nameservers))

    def test_create_pending_domain_registration_succeeds(self):
        response_data = {
            'response_text': 'Registration successful',
            'protocol': 'XCP',
            'response_code': '200',
            'object': 'DOMAIN',
            'action': 'REPLY',
            'attributes': {
                'admin_email': 'email@example.com',
                'id': '1065034'
            },
            'is_success': '1'}
        opensrs = self.safe_opensrs(
            self._data_domain_reg('foo.com', '1', 'foo', 'bar'),
            response_data)
        expected = {
            'domain_name': 'foo.com',
            'registrar_data': {
                'ref_number': '1065034'
            }
        }
        self.assertEquals(expected, opensrs.create_pending_domain_registration(
            'foo.com', 1, self._objdata_user_contact(), 'foo', 'bar'))

    def test_is_auto_renewed(self):
        osrs = opensrsapi.OpenSRS('host', 'port', 'user', 'key', 'timeout')
        error = Mock(response_code=osrs.CODE_RENEWAL_IS_NOT_ALLOWED)

        self.assertTrue(osrs._is_auto_renewed(error, 'foo.co.za'))
        self.assertTrue(osrs._is_auto_renewed(error, 'bar.de'))
        self.assertFalse(osrs._is_auto_renewed(error, 'test.com'))


class OpenSRSTestCase(TestCase):
    def setUp(self):
        XCPMessage_patcher = patch.object(
            opensrsapi, 'XCPMessage', spec_set=opensrsapi.XCPMessage)
        XCPChannel_patcher = patch.object(
            opensrsapi, 'XCPChannel', spec_set=opensrsapi.XCPChannel)
        self.m_xcp_channel = XCPChannel_patcher.start()
        self.m_xcp_message = XCPMessage_patcher.start()
        self.addCleanup(XCPChannel_patcher.stop)
        self.addCleanup(XCPMessage_patcher.stop)
        self.opensrs = opensrsapi.OpenSRS(
            'host', 'port', 'user', 'key', 'timeout')

    @property
    def user(self):
        return type('User', (object,), {
            'org_name': 'first_name last_name',
            'city': 'city',
            'first_name': 'first_name',
            'last_name': 'last_name',
            'address1': 'address1',
            'address2': 'address2',
            'address3': 'address3',
            'fax': '',
            'phone': '5551234',
            'state': 'state',
            'postal_code': '',
            'country_code': 'ZA',
            'email': 'email@example.com'
        })


class OpenSRSSetContactTestCase(OpenSRSTestCase):
    def test_does_not_send_billing_info_for_ca_domains(self):
        self.opensrs.set_contacts('cookie', self.user, 'foo.ca')
        null, null, attributes = self.m_xcp_message.call_args[0]
        self.assertNotIn('billing', attributes['contact_set'])
