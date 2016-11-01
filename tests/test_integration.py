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

    def test_returns_iterable_results(self):
        for domain_data in self.iterable_results:
            domain = Domain(domain_data)
            self.assertIsInstance(domain.expiry_date, date)
            break
