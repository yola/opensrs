# [Changelog](https://github.com/yola/opensrs/releases)

## 1.0.0
* Decided it's stable enough for 1.0.0 [relevant discussion][prod2976]
* Added more auto-renewed TLDs (.za and .dk) ([#6][6])

[prod2976]: https://github.com/yola/production/issues/2976
[6]: https://github.com/yola/opensrs/pull/6

## 0.1.0
* Renamed `get_transfers_away` to `get_transferred_away_domains`
* Now `get_transferred_away_domains` accepts optional `domain` param
    to narrow search to the given domain
