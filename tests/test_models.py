from datetime import date
from unittest import TestCase

from opensrs.models import Domain


class DomainTestCase(TestCase):
    def setUp(self):
        domain_data = {
            'f_let_expire': 'N',
            'expiredate': '2016-11-02 12:17:12',
            'f_auto_renew': 'N',
            'name': 'foo.co.za'
        }
        self.domain = Domain(domain_data)

    def test_has_expiry_date_attribute(self):
        self.assertEqual(self.domain.expiry_date, date(2016, 11, 2))

    def test_has_tld_attribute(self):
        self.assertEqual(self.domain.tld, 'za')

    def test_has_name_attribute(self):
        self.assertEqual(self.domain.name, 'foo.co.za')

    def test_has_auto_renew_attribute(self):
        self.assertFalse(self.domain.auto_renew)
