from dateutil.parser import parse


class Domain(object):
    def __init__(self, data):
        self.name = data['name']
        self.auto_renew = (data['f_auto_renew'] == 'Y')
        self.expiry_date = parse(data['expiredate']).date()

    @property
    def tld(self):
        return self.name.split('.')[-1]

    def to_dict(self):
        return {
            'name': self.name,
            'auto_renew': self.auto_renew,
            'expiry_date': self.expiry_date
        }
