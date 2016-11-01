from datetime import date, datetime, timedelta

from unittest import TestCase

from opensrs.models import Domain
from opensrs.opensrsapi import OpenSRS
from test_settings import CONNECTION_OPTIONS


class IterateDomainsTestCase(TestCase):
    def setUp(self):
        opensrs = OpenSRS(**CONNECTION_OPTIONS)
        expiry_from = datetime.utcnow().date()
        expiry_to = expiry_from + timedelta(360)
        self.iterable_results = opensrs.iterate_domains(
            expiry_from, expiry_to)

    def test_returns_iterable_domain_data(self):
        for domain_data in self.iterable_results:
            domain = Domain(domain_data)
            self.assertIsInstance(domain.expiry_date, date)
            break


class ListDomainsTestCase(TestCase):
    @classmethod
    def setUpClass(cls):
        cls.first_page = cls._list_domains()

    @classmethod
    def _list_domains(cls, page=1):
        opensrs = OpenSRS(**CONNECTION_OPTIONS)
        expiry_from = datetime.utcnow().date()
        expiry_to = expiry_from + timedelta(360)
        return opensrs.list_domains(
            expiry_from, expiry_to, page, 2)['exp_domains']

    def test_respects_page_size(self):
        self.assertEqual(len(self.first_page), 2)

    def test_respects_page_number(self):
        second_page = self._list_domains(2)
        self.assertNotEqual(self.first_page, second_page)

    def test_returns_domain_data(self):
        Domain(self.first_page[0])
