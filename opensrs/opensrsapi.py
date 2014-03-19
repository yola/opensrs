import logging

import errors
from xcp import XCPMessage, XCPChannel

log = logging.getLogger(__name__)


def format_date(date):
    return date.strftime('%Y-%m-%d')


class OpenSRS(object):
    CODE_DOMAIN_AVAILABLE = '210'
    CODE_DOMAIN_TAKEN = '211'
    CODE_DOMAIN_TAKEN_AWAITING_REGISTRATION = '221'

    CODE_DOMAIN_REGISTRATION_TAKEN = '485'
    CODE_DOMAIN_REGISTRATION_FAILED = '465'

    CODE_DOMAIN_NOT_TRANSFERABLE = '487'

    CODE_DOMAIN_INVALID = '465'

    CODE_AUTHENTICATION_FAILED = '415'

    CODE_OVER_QUOTA = '3001'

    CODE_ALREADY_RENEWED = '555'
    CODE_ALREADY_RENEWED_SANDBOX = '465'
    CODE_RENEWAL_IS_NOT_ALLOWED = '480'
    CODE_CANNOT_REDEEM_DOMAIN = '400'
    CODE_CANNOT_PUSH_DOMAIN = '465'

    MSG_ALREADY_RENEWED_SANDBOX = 'Domain Already Renewed'
    channel_factory = XCPChannel

    def __init__(self, host, port, username, private_key, default_timeout):
        self.host = host
        self.port = port
        self.username = username
        self.private_key = private_key
        self.default_timeout = default_timeout

    def _get_channel(self):
        return self.channel_factory(self.host, self.port, self.username,
                                    self.private_key, self.default_timeout)

    def _req(self, action, object, attributes, **kw):
        msg = XCPMessage(action, object, attributes, **kw)
        return self._get_channel().make_request(msg)

    def make_contact(self, user, domain, **kw):
        org_name = kw.get('orgname') or ' '.join([user.first_name,
                                                  user.last_name])
        return {
            'first_name': user.first_name,
            'last_name': user.last_name,
            'email': user.email,
            'phone': user.phone,
            'fax': user.fax or '',
            'org_name': org_name,
            'address1': user.address1,
            'address2': user.address2,
            'address3': user.address3,
            'city': user.city,
            'state': user.state,
            'country': user.country_code,
            'postal_code': user.postal_code or '',
        }

    def make_nameserver_list(self, nameservers):
        return [{'sortorder': str(i + 1), 'name': ns} for i, ns in
                enumerate(nameservers)]

    # Basic API calls. These return raw XCPMessage objects.

    def _lookup_domain(self, domain):
        return self._req(action='LOOKUP', object='DOMAIN',
                         attributes={'domain': domain})

    def _check_transfer(self, domain):
        return self._req(action='CHECK_TRANSFER', object='DOMAIN',
                         attributes={'domain': domain})

    def _make_common_reg_attrs(self, domain, user, username, password,
                               reg_domain, **kw):
        contact = self.make_contact(user, domain, **kw)
        # .eu domains require GB instead of UK as the country code
        if domain.lower().endswith('.eu') and contact['country'] == 'UK':
            contact['country'] = 'GB'
        attributes = {
            'auto_renew': '0',
            'contact_set': {
                'owner': contact,
                'admin': contact,
                'billing': contact,
                'tech': contact,
            },
            'custom_tech_contact': '1',
            'domain': domain,
            'reg_username': username,
            'reg_password': password,
            'reg_type': 'new',
            'f_lock_domain': '1',
            'handle': 'save',
        }
        if reg_domain is not None:
            attributes['reg_domain'] = reg_domain
        return attributes

    def _make_domain_reg_attrs(self, domain, period, user, username, password,
                               nameservers, private, reg_domain, **kw):
        attributes = self._make_common_reg_attrs(domain, user, username,
                                                 password, reg_domain, **kw)
        attributes.update({
            'reg_type': 'new',
            'period': str(period),
            'f_whois_privacy': {True: '1', False: '0'}[private],
            'custom_nameservers': '0',
        })
        if nameservers is not None:
            attributes['custom_nameservers'] = '1'
            attributes['nameserver_list'] = self.make_nameserver_list(
                nameservers)
        return attributes

    def _make_domain_transfer_attrs(self, domain, user, username, password,
                                    nameservers, reg_domain):
        attributes = self._make_common_reg_attrs(domain, user, username,
                                                 password, reg_domain)
        attributes.update({
            'reg_type': 'transfer',
            'custom_transfer_nameservers': '0',
        })
        if nameservers is not None:
            attributes['custom_transfer_nameservers'] = '1'
            attributes['nameserver_list'] = self.make_nameserver_list(
                nameservers)
        return attributes

    def _sw_register_domain(self, attributes):
        return self._req(action='SW_REGISTER', object='DOMAIN',
                         attributes=attributes)

    def _advanced_update_nameservers(self, cookie, nameservers):
        attributes = {
            'assign_ns': nameservers,
            'op_type': 'assign',
        }
        return self._req(action='ADVANCED_UPDATE_NAMESERVERS', object='DOMAIN',
                         cookie=cookie, attributes=attributes)

    def _name_suggest_domain(self, search_string, tlds, maximum=None,
                             max_wait_time=None, search_key=None):
        attributes = {
            'searchstring': search_string,
            'tlds': tlds,
            'services': ['lookup', 'suggestion'],
        }
        if max_wait_time is not None:
            attributes['max_wait_time'] = str(max_wait_time)
        if search_key is not None:
            attributes['search_key'] = search_key
        if maximum is not None:
            attributes['maximum'] = str(maximum)
        return self._req(action='NAME_SUGGEST',
                         object='DOMAIN',
                         attributes=attributes)

    def _process_pending(self, order_id, cancel=False):
        attributes = {
            'order_id': order_id,
        }
        if cancel:
            attributes['command'] = 'cancel'
        return self._req(action='PROCESS_PENDING', object='DOMAIN',
                         attributes=attributes)

    def _set_cookie(self, domain, reg_username, reg_password):
        attributes = {
            'domain': domain,
            'reg_username': reg_username,
            'reg_password': reg_password,
        }
        return self._req(action='SET', object='COOKIE', attributes=attributes)

    def _set_domain_status(self, cookie, status):
        attributes = {
            'data': 'status',
            'lock_state': status,
        }
        return self._req(action='MODIFY', object='DOMAIN', cookie=cookie,
                         attributes=attributes)

    def _get_domain_status(self, cookie):
        attributes = {
            'type': 'status',
        }
        return self._req(action='GET', object='DOMAIN', cookie=cookie,
                         attributes=attributes)

    def _get_domain_info(self, cookie, type='all_info'):
        return self._req(action='GET', object='DOMAIN', cookie=cookie,
                         attributes={'type': type})

    def _set_domain_whois_privacy(self, cookie, privacy):
        attributes = {
            'data': 'whois_privacy_state',
            'affect_domains': '0',
            'state': privacy,
        }
        return self._req(action='MODIFY', object='DOMAIN', cookie=cookie,
                         attributes=attributes)

    def _send_authcode(self, domain_name):
        return self._req(action='SEND_AUTHCODE', object='DOMAIN',
                         attributes={'domain_name': domain_name})

    def _renew_domain(self, domain_name, current_expiration_year, period):
        attributes = {
            'auto_renew': '0',
            'currentexpirationyear': current_expiration_year,
            'domain': domain_name,
            'handle': 'save',
            'period': str(period),
        }
        return self._req(action='RENEW', object='DOMAIN',
                         attributes=attributes)

    def _get_domains_by_expiredate(self, exp_from, exp_to, page):
        attributes = {
            'exp_from': format_date(exp_from),
            'exp_to': format_date(exp_to),
            'page': str(page),
        }
        return self._req(action='GET_DOMAINS_BY_EXPIREDATE', object='DOMAIN',
                         attributes=attributes, timeout=300)

    def _get_domains_contacts(self, domains):
        return self._req(action='GET_DOMAINS_CONTACTS', object='DOMAIN',
                         attributes={'domain_list': domains})

    def _get_transfers_in(self, transfer_id=None, req_from=None, req_to=None):
        attributes = {}
        if transfer_id is not None:
            attributes['transfer_id'] = transfer_id
        if req_from is not None:
            attributes['req_from'] = format_date(req_from)
        if req_to is not None:
            attributes['req_to'] = format_date(req_to)
        return self._req(action='GET_TRANSFERS_IN', object='DOMAIN',
                         attributes=attributes)

    def _change_ownership(self, cookie, username, password, reg_domain):
        attributes = {
            'username': username,
            'password': password,
        }
        if reg_domain is not None:
            attributes['reg_domain'] = reg_domain
        return self._req(action='CHANGE', object='OWNERSHIP', cookie=cookie,
                         attributes=attributes)

    def _set_domain_contacts(self, cookie, user, domain):
        contact = self.make_contact(user, domain)
        attributes = {
            'affect_domains': '0',
            'data': 'contact_info',
            'contact_set': {
                'owner': contact,
                'admin': contact,
                'billing': contact,
                'tech': contact,
            },
        }
        return self._req(action='MODIFY', object='DOMAIN', cookie=cookie,
                         attributes=attributes)

    def _get_transfers_away(self, page):
        return self._req(action='GET_TRANSFERS_AWAY', object='DOMAIN',
                         attributes={'status': 'completed', 'page': str(page)})

    def _revoke_domain(self, domain_name):
        attributes = {
            'domain': domain_name,
            'reseller': self.username
        }
        return self._req(action='REVOKE', object='DOMAIN',
                         attributes=attributes)

    def _get_user_info(self, cookie, type='all_info'):
        return self._req(action='GET', object='USERINFO', cookie=cookie,
                         attributes={'type': type})

    def _get_domain_notes(self, domain, type='domain'):
        return self._req(action='GET_NOTES', object='DOMAIN',
                         attributes={'domain': domain, 'type': type})

    def _get_orders_by_domain(self, domain):
        return self._req(action='GET_ORDERS_BY_DOMAIN', object='DOMAIN',
                         attributes={'domain': domain})

    def _get_order_info(self, order_id):
        return self._req(action='GET_ORDER_INFO', object='DOMAIN',
                         attributes={'order_id': order_id})

    def _activate_domain(self, cookie, domain_name):
        return self._req(action='ACTIVATE', object='DOMAIN', cookie=cookie,
                         attributes={'domainname': domain_name})

    # Higher leverl API calls. These parse the response into a
    # (hopefully) useful form.

    def get_auth_cookie(self, domain, username, password):
        try:
            rsp = self._set_cookie(domain, username, password)
        except errors.XCPError, e:
            if e.response_code == self.CODE_AUTHENTICATION_FAILED:
                raise errors.AuthenticationFailure(e)
            raise
        return rsp.get_data()['attributes']['cookie']

    def domain_available(self, domain):
        try:
            rsp = self._lookup_domain(domain)
        except errors.XCPError, e:
            if e.response_code == self.CODE_DOMAIN_INVALID:
                raise errors.InvalidDomain(e)
            raise
        code = rsp.get_data()['response_code']
        if code == self.CODE_DOMAIN_AVAILABLE:
            return True
        if code in [self.CODE_DOMAIN_TAKEN,
                    self.CODE_DOMAIN_TAKEN_AWAITING_REGISTRATION]:
            return False
        raise errors.OperationFailure(rsp)

    def domain_transferable(self, domain):
        try:
            rsp = self._check_transfer(domain)
        except errors.XCPError, e:
            if e.response_code == self.CODE_DOMAIN_INVALID:
                raise errors.InvalidDomain(e)
            raise
        attribs = rsp.get_data()['attributes']
        return (attribs['transferrable'] == '1', attribs.get('reason', None))

    def suggest_domains(self, search_string, tlds, maximum=None,
                        max_wait_time=None, search_key=None):
        rsp = self._name_suggest_domain(search_string, tlds, maximum,
                                        max_wait_time, search_key)
        data = rsp.get_data()
        domains = {}
        for k in ['lookup', 'suggestion']:
            domrsp = data['attributes'].get(k, None)
            domains[k] = []
            if domrsp is None:
                log.debug('Missing "%s" section in name suggestions.', k)
                continue
            if domrsp.get('is_success', '0') != '1':
                rsp_code = domrsp.get('response_code')
                rsp_text = domrsp.get('response_text')
                if rsp_code == '500':
                    # These are typically temporary
                    log.info('Unsuccessful lookup component "%s": %s: %s', k,
                             rsp_code, rsp_text)
                    raise errors.DomainLookupUnavailable(rsp, rsp_code,
                                                         rsp_text)
                log.warn('Unsuccessful lookup component "%s": %s: %s', k,
                         rsp_code, rsp_text)
                raise errors.DomainLookupFailure(rsp, rsp_code, rsp_text)
            domains[k] = [{'domain': i['domain'], 'status': i['status']}
                          for i in domrsp['items']]
        if data.get('is_search_completed', '1') == '0':
            domains['search_key'] = data['search_key']
        return domains

    def register_domain(self, domain, purchase_period, user, user_id,
                        password, nameservers=None, private_reg=None,
                        reg_domain=None, extras=None):
        extras = extras or {}
        attrs = self._make_domain_reg_attrs(domain, purchase_period, user,
                                            user_id, password, nameservers,
                                            private_reg, reg_domain, **extras)
        if extras:
            attrs.update(extras)
        try:
            rsp = self._sw_register_domain(attrs)
            order_id = rsp.get_data()['attributes']['id']
            return {
                'domain_name': domain,
                'registrar_data': {'ref_number': order_id}
            }
        except errors.XCPError, e:
            if e.response_code == self.CODE_DOMAIN_REGISTRATION_TAKEN:
                raise errors.DomainTaken(e)
            if e.response_code == self.CODE_DOMAIN_REGISTRATION_FAILED:
                if (e.response_text.startswith('Invalid domain syntax') or
                        e.response_text.startswith(
                            'Invalid syntax on domain')):
                    raise errors.InvalidDomain(e)
                raise errors.DomainRegistrationFailure(e)
            raise

    def process_pending(self, order_id, cancel=False):
        try:
            rsp = self._process_pending(order_id, cancel=cancel)
            return rsp.get_data().get('attributes')
        except errors.XCPError, e:
            if self._already_renewed(e):
                raise errors.DomainAlreadyRenewed(e)
            raise

    def update_nameservers(self, nameservers, cookie):
        self._advanced_update_nameservers(cookie, nameservers)
        return True

    def is_locked(self, cookie):
        rsp = self._get_domain_status(cookie)
        return {'0': False,
                '1': True}[rsp.get_data()['attributes']['lock_state']]

    def set_locked(self, cookie, locked):
        self._set_domain_status(cookie, {True: '1', False: '0'}[locked])
        return True

    def send_auth_code(self, domain):
        self._send_authcode(domain)
        return True

    def set_domain_privacy(self, cookie, privacy_enabled):
        self._set_domain_whois_privacy(
            cookie, {True: 'enable', False: 'disable'}[privacy_enabled])
        return True

    def renew_domain(self, domain, current_expiration_year, period):
        try:
            rsp = self._renew_domain(domain, current_expiration_year, period)
            return rsp.get_data()['attributes']['order_id']
        except errors.XCPError, e:
            # We cannot renew .de domains right now (they are
            # auto-renewed automatically on registar side).
            # Therefore consider each .de domain renewal
            # attempt as successful
            if self._already_renewed(e) or self._is_de_domain_case(e, domain):
                raise errors.DomainAlreadyRenewed(e)
            raise

    def _already_renewed(self, e):
        return (e.response_code == self.CODE_ALREADY_RENEWED or
                (e.response_code == self.CODE_ALREADY_RENEWED_SANDBOX and
                 e.response_text.startswith(self.MSG_ALREADY_RENEWED_SANDBOX)))

    def _is_de_domain_case(self, e, domain):
        return (e.response_code == self.CODE_RENEWAL_IS_NOT_ALLOWED and
                domain.lower().endswith('.de'))

    def get_domains_by_expiredate(self, start_date, end_date, page=None):
        domains = []
        qpage = page
        if qpage is None:
            qpage = 1
        while qpage is not None:
            rsp = self._get_domains_by_expiredate(start_date, end_date, qpage)
            data = rsp.get_data()
            for domain in data['attributes']['exp_domains']:
                domains.append({
                    'domain': domain['name'],
                    'domain_expiration': domain['expiredate'],
                })
            if data['attributes']['remainder'] == '0':
                qpage = None
            else:
                qpage += 1
        return domains

    def get_domains_contacts(self, domains, limit=100):
        domain_data = {}
        while len(domains) > 0:
            qdomains = domains[:limit]
            domains = domains[limit:]
            rsp = self._get_domains_contacts(qdomains)
            data = rsp.get_data()
            for domain, contact_set in data['attributes'].items():
                owner = contact_set['contact_set']['owner']
                domain_data[domain] = {
                    'first_name': owner['first_name'],
                    'last_name': owner['last_name'],
                    'email': owner['email'],
                }
        return domain_data

    def transfer_domain(self, domain, user, user_id, password,
                        nameservers=None, reg_domain=None, extras=None):
        try:
            attrs = self._make_domain_transfer_attrs(
                domain, user, user_id, password, nameservers, reg_domain)
            if extras:
                attrs.update(extras)
            rsp = self._sw_register_domain(attrs)
            order_id = rsp.get_data()['attributes']['id']
            return {
                'domain_name': domain,
                'registrar_data': {'ref_number': order_id},
            }
        except errors.XCPError, e:
            if e.response_code == self.CODE_DOMAIN_NOT_TRANSFERABLE:
                raise errors.DomainNotTransferable(e)
            if e.response_code == self.CODE_DOMAIN_REGISTRATION_FAILED:
                if (e.response_text.startswith('Invalid domain syntax') or
                        e.response_text.startswith(
                            'Invalid syntax on domain')):
                    raise errors.InvalidDomain(e)
                raise errors.DomainTransferFailure(e)
            raise

    def list_transfers(self, transfer_id=None, start_date=None, end_date=None):
        rsp = self._get_transfers_in(transfer_id=transfer_id,
                                     req_from=start_date, req_to=end_date)
        transfers = rsp.get_data()['attributes'].get('transfers', [])
        return transfers

    def get_domain_info(self, cookie):
        rsp = self._get_domain_info(cookie)
        return rsp.get_data()['attributes']

    def get_privacy_state(self, cookie):
        rsp = self._get_domain_info(cookie, type='whois_privacy_state')
        return rsp.get_data()['attributes']

    def change_ownership(self, cookie, username, password, domain=None):
        self._change_ownership(cookie, username, password, domain)
        return True

    def set_contacts(self, cookie, user, domain):
        self._set_domain_contacts(cookie, user, domain)
        return True

    def get_transfers_away(self, page):
        rsp = self._get_transfers_away(page)
        return rsp.get_data()['attributes'].get('transfers', [])

    def revoke_domain(self, domain):
        return self._revoke_domain(domain).get_data()

    def get_user_info(self, cookie):
        return self._get_user_info(cookie).get_data()['attributes']

    def get_domain_notes(self, domain_name):
        return self._get_domain_notes(
            domain_name).get_data()['attributes']['notes']

    def get_orders_by_domain(self, domain):
        rsp = self._get_orders_by_domain(domain)
        return rsp.get_data()['attributes']['orders']

    def get_order_info(self, order_id):
        rsp = self._get_order_info(order_id)
        return rsp.get_data()['attributes']['field_hash']

    def activate_domain(self, cookie, domain):
        return self._activate_domain(cookie, domain).get_data()

    def bulk_domain_transfer(self, domains_list, recipient):
        attributes = {
            'change_items': domains_list,
            'gaining_reseller_username': recipient,
            'change_type': 'push_domains',
            'apply_to_locked_domains': '1',
        }
        return self._req(action='SUBMIT', object='BULK_CHANGE',
                         attributes=attributes)

    def rsp_domain_transfer(self, domain, recipient):
        attributes = {
            'domain': domain,
            'grsp': recipient,
        }
        try:
            resp = self._req(
                action='RSP2RSP_PUSH_TRANSFER', object='DOMAIN',
                attributes=attributes)
            log.info('opensrsapi.rsp_domain_transfer domain_name=%s, resp=%s',
                     domain, resp)
            return resp
        except errors.XCPError, e:
            log.error(
                'opensrsapi.rsp_domain_transfer fail domain_name=%s error=%s',
                domain, e.response_text)
            if e.response_code == self.CODE_CANNOT_REDEEM_DOMAIN:
                return e.response_text
            raise

    def redeem_domain(self, domain):
        log.info('opensrsapi.redeem_domain domain_name=%s', domain)
        attributes = {'domain': domain}
        redeem_resp = {'redeem_success': False}
        try:
            rsp = self._req(action='REDEEM', object='DOMAIN',
                            attributes=attributes)
            data = rsp.get_data()
            if int(data.get('is_success')) == 1:
                redeem_resp['redeem_success'] = True
                return redeem_resp
        except errors.XCPError, e:
            if e.response_code == self.CODE_CANNOT_REDEEM_DOMAIN:
                log.info(('opensrsapi.redeem_domain fail domain_name=%s '
                          'error=%s code=%s'), domain, e.response_text,
                         e.response_code)
                return redeem_resp
            log.error(('opensrsapi.redeem_domain fail domain_name=%s '
                       'error=%s code=%s'), domain, e.response_text,
                      e.response_code)
            raise

    def get_registrant_verification_status(self, domain_name):
        return self._make_registrant_verification_call(
            domain_name,
            'get_registrant_verification_status'
        )['attributes']

    def send_registrant_verification_email(self, domain_name):
        return self._make_registrant_verification_call(
            domain_name,
            'send_registrant_verification_email'
        )['response_text']

    def _make_registrant_verification_call(self, domain_name, operation):
        try:
            return self._req(
                action=operation, object='domain',
                attributes={'domain': domain_name}
            ).get_data()
        except errors.XCPError, e:
            if e.response_code == self.CODE_AUTHENTICATION_FAILED:
                raise errors.DomainNotFound(e)
            raise
