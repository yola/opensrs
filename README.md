# OpenSRS

## Usage

Looking up statuses of domains
```python
>>> from opensrs import OpenSRS
>>> client = OpenSRS(host, port, username, private_key, default_timeout)
>>> client.suggest_domains('foo', ['.COM', '.ORG', '.NET', '.INFO'], 4))
{
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
```

## Configuration

The service client is configured on initialization.

```python
from opensrs import OpenSRS
client = OpenSRS(host, port, username, private_key, default_timeout)
```

## Testing

Install requirements:

    pip install -r requirements.txt

Create the `test_settings.py` file in the root directory, with a `USERNAME` and `PRIVATE_KEY`

```python
USERNAME = 'USERNAME'
PRIVATE_KEY = 'PRIVATE_KEY'
```

Run the tests with:

    nosetests

Or you can easily run tests on Python 2.7 with tox:

    tox
