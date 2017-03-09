class OpenSRSError(Exception):
    """Base class for errors in this library."""
    pass


class XCPError(OpenSRSError):
    def __init__(self, response_message):
        self.response_message = response_message
        self.message_data = response_message.get_data()
        self.response_code = self.message_data['response_code']
        self.response_text = self.message_data['response_text']

    def __str__(self):
        return "%s: %s" % (self.response_code, self.response_text)


class BadResponseError(OpenSRSError):
    def __init__(self, xcp_error):
        self.response_message = xcp_error.response_message
        self.message_data = xcp_error.message_data
        self.response_code = xcp_error.response_code
        self.response_text = xcp_error.response_text

    def __str__(self):
        return "%s: %s" % (self.response_code, self.response_text)


class OperationFailure(OpenSRSError):
    def __init__(self, response_message, response_code=None,
                 response_text=None):
        self.response_message = response_message
        self.message_data = response_message.get_data()
        self.response_code = response_code or \
            self.message_data['response_code']
        self.response_text = response_text or \
            self.message_data['response_text']

    def __str__(self):
        return "%s: %s" % (self.response_code, self.response_text)


class InvalidDomain(BadResponseError):
    pass


class AuthenticationFailure(BadResponseError):
    pass


class DomainRegistrationFailure(BadResponseError):
    pass


class DomainTaken(DomainRegistrationFailure):
    pass


class DomainTransferFailure(BadResponseError):
    pass


class DomainNotTransferable(DomainTransferFailure):
    pass


class DomainLookupFailure(OperationFailure):
    pass


class DomainAlreadyRenewed(BadResponseError):
    pass


class DomainLookupUnavailable(OperationFailure):
    pass


class DomainRegistrationTimedOut(BadResponseError):
    pass
