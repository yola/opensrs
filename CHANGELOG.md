# [Changelog](https://github.com/yola/opensrs/releases)

## 4.3.2
* Fix using non-ascii symbols for "org_name" generated from user's name.

## 4.3.1
* Allow blank 'orgname' param.

## 4.3.0
* Add Python 3.9 support.
* Add `OpenSRS.get_balance()` method.

## 4.2.0
* Allow to specify `services` to `OpenSRS.suggest_domains()`.

## 4.1.0
* Add `OpenSRS.disable_parked_pages_service()`.

## 4.0.0
* Add Python 3 support
* Add `OpenSRS.simple_transfer()` and `OpenSRS.get_simple_transfer_status()`
  methods
* Rename `OpenSRS.bulk_domain_transfer()` to `OpenSRS.bulk_domain_change()`

## 3.0.2
* Fix `transfer_id` KeyError on pending domain transfer orders

## 3.0.1
* Return `transfer_id` from `transfer_domain` and
    `create_pending_domain_transfer`

## 3.0.0
* Add `create_pending_domain_registration` method
* Add `create_pending_domain_renewal` method
* Add `create_pending_domain_transfer` method
* Change `register_domain` to immediately process the order
* Change `transfer_domain` to immediately process the order
* Change `renew_domain` to immediately process the order

## 2.2.0
* Add `order_processing_method` parameter to `register_domain` method

## 2.1.0
* Add `OpenSRS.list_domains()`
* Add `Domain.to_dict()`

## 2.0.0
* Add `OpenSRS.iterate_domains()`
* Add `Domain` model
* Start to depend on `demands` and `python-dateutil`
* Move out tests from the package

## 1.1.1
* Fix wrong types in API call (`enable/disable_domain_auto_renewal`).

## 1.1.0
* Add methods to enable/disable domain auto-renewal.

## 1.0.2
* Add special handling in contact update for CA domains

## 1.0.1
* Added more auto-renewed TLDs (.at and .fr) ([#9][9])

[9]: https://github.com/yola/opensrs/pull/9

## 1.0.0
* Decided it's stable enough for 1.0.0
* Added more auto-renewed TLDs (.za and .dk) ([#6][6])

[6]: https://github.com/yola/opensrs/pull/6

## 0.1.0
* Renamed `get_transfers_away` to `get_transferred_away_domains`
* Now `get_transferred_away_domains` accepts optional `domain` param
    to narrow search to the given domain
