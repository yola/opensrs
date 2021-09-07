import hashlib
import logging
try:
    from urllib.request import urlopen, Request
except ImportError:
    from urllib2 import urlopen, Request
from xml.etree import ElementTree as ET

from opensrs.errors import XCPError


log = logging.getLogger(__name__)


class OPSMessage(object):
    """
    Wrapper to translate between an XML OPS message and a nested data
    structure.

    OPS messages are essentially XML nested list/dict/string data
    structures with some header information. This class translates
    bidirectionally between native Python data structures and the XML
    OPS message suitable for putting on the wire.
    """

    VERSION = '0.9'

    def __init__(self, data=None, xml=None):
        if xml is not None:
            if data is not None:
                raise RuntimeError('Please use either data or xml, not both.')
            self.parse_message_xml(xml)
        else:
            self.create_empty_message()
            if data is not None:
                self.set_data(data)

    def parse_message_xml(self, message_xml):
        self.message_xml = message_xml
        self.message_root = ET.XML(message_xml)
        self.data_elem = self.message_root.find('body/data_block')

    def get_version(self):
        return self.message_root.find('header/version')

    def create_empty_message(self):
        self.message_root = ET.Element('OPS_envelope')
        ver_elem = ET.SubElement(ET.SubElement(self.message_root, 'header'),
                                 "version")
        ver_elem.text = self.VERSION
        body_elem = ET.SubElement(self.message_root, 'body')
        self.data_elem = ET.SubElement(body_elem, 'data_block')

    def set_data(self, data, base_node=None, wrap_scalar=None):
        if wrap_scalar is None:
            wrap_scalar = True
        if base_node is None:
            base_node = self.data_elem
        if isinstance(data, list):
            list_node = ET.SubElement(base_node, 'dt_array')
            for key, value in enumerate(data):
                self.set_data(
                    value, ET.SubElement(list_node, 'item', key=str(key)),
                    wrap_scalar=False)
            return
        if isinstance(data, dict):
            dict_node = ET.SubElement(base_node, 'dt_assoc')
            # For testing purposes, having a deterministic order is useful,
            # so we sort the dict items.
            for key, value in sorted(data.items()):
                self.set_data(
                    value, ET.SubElement(dict_node, 'item', key=str(key)),
                    wrap_scalar=False)
            return
        if wrap_scalar:
            base_node = ET.SubElement(base_node, 'dt_scalar')
        base_node.text = data

    def to_string(self):
        xmlheader = '<?xml version="1.0" encoding="UTF-8" standalone="no" ?>\n'
        xmlheader += '<!DOCTYPE OPS_envelope SYSTEM "ops.dtd">\n'
        return xmlheader + ET.tostring(self.message_root).decode('UTF-8')

    def get_data(self, base_node=None):
        if base_node is None:
            base_node = self.data_elem[0]
        if not ET.iselement(base_node):
            return base_node
        if base_node.tag == 'item':
            if list(base_node) == []:
                return base_node.text
            return self.get_data(base_node[0])
        if base_node.tag == 'dt_array':
            indexed_children = [(e.get('key'), e) for e in base_node]
            indexed_children.sort()
            return [self.get_data(e) for i, e in indexed_children]
        if base_node.tag == 'dt_assoc':
            data = {}
            for e in base_node:
                data[e.get('key')] = self.get_data(e)
            return data
        if base_node.tag == 'dt_scalar':
            return base_node.text


class XCPMessage(object):
    """This is a higher-level wrapper with more protocol stuff in it."""

    def __init__(self, action, object, attributes=None, timeout=None, **kw):
        data = {
            'protocol': 'XCP',
            'action': action,
            'object': object,
        }
        if attributes is not None:
            data['attributes'] = attributes

        data.update(kw)

        self.ops_message = OPSMessage(data=data)
        self.timeout = timeout

    def get_content(self):
        return self.ops_message.to_string().encode('UTF-8')

    def sign(self, private_key):
        firstpass = hashlib.md5(self.get_content() + private_key).hexdigest()
        return hashlib.md5(firstpass.encode('UTF-8') + private_key).hexdigest()


class XCPChannel(object):
    def __init__(self, host, port, username, private_key, default_timeout):
        self.host = host
        self.port = port
        self.username = username
        self.private_key = private_key.encode('UTF-8')
        self.default_timeout = default_timeout

    def _make_call(self, message):
        """All network interaction is isolated here for stubbing out."""
        request = Request('https://%s:%s/' % (self.host, self.port))
        headers = {
            'Content-Type': 'text/xml',
            'X-Username': self.username,
            'X-Signature': message.sign(self.private_key),
        }
        [request.add_header(k, v) for k, v in headers.items()]

        timeout = message.timeout or self.default_timeout
        log.debug('Making XCP call with timeout = %s', timeout)
        xml = urlopen(request, message.get_content(), timeout).read()
        return OPSMessage(xml=xml)

    def make_request(self, message):
        log.debug('OpenSRS Request: %s' % repr(message.get_content()))
        response = self._make_call(message)
        log.debug('OpenSRS Response: %s' % repr(response.message_xml))
        if response.get_data()['is_success'] == '0':
            raise XCPError(response)
        return response
