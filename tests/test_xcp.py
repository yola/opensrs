from unittest import TestCase

from opensrs import xcp


class OPSMessageTest(TestCase):

    # First, some higher-level assertions to make our lives a little easier.

    def assert_encode_decode_invariant(self, data):
        self.assertEqual(data, xcp.OPSMessage(data=data).get_data())

    def assert_decoded_xml(self, data, xml):
        self.assertEqual(data, xcp.OPSMessage(xml=xml).get_data())

    # Next, some helper methods.

    def wrap_message_xml(self, data_xml):
        xml_template = """<?xml version='1.0' encoding='UTF-8' standalone='no'
        ?>
        <!DOCTYPE OPS_envelope SYSTEM 'ops.dtd'>
        <OPS_envelope>
          <header><version>1.0</version></header>
          <body><data_block>%s</data_block></body>
        </OPS_envelope>"""
        return xml_template % data_xml

    # Now the tests.

    def test_create_string_message(self):
        self.assert_encode_decode_invariant("foo")

    def test_create_list_message(self):
        self.assert_encode_decode_invariant(["foo", "bar"])

    def test_create_dict_message(self):
        self.assert_encode_decode_invariant({"foo": "bar", "baz": "quux"})

    def test_create_list_message_with_none(self):
        self.assert_encode_decode_invariant(["foo", None])

    def test_create_dict_message_with_none(self):
        self.assert_encode_decode_invariant({"foo": "bar", "baz": None})

    def test_create_complex_dict_message(self):
        data = {
            "foo": ["bar", ["b1", {"b1": "b2"}]],
            "baz": {"bk1": ["bv1a", "bv1b"], "bk2": "bv2"},
            "text": "value",
            "none": None,
        }
        self.assert_encode_decode_invariant(data)

    def test_create_complex_list_message(self):
        data = [
            "foo",
            ["bar", ["b1", {"b1": "b2"}]],
            None,
            {"bk1": ["bv1a", "bv1b"], "bk2": "bv2"},
            "text",
        ]
        self.assert_encode_decode_invariant(data)

    def test_parse_string_message(self):
        xml = self.wrap_message_xml("""<dt_scalar>foo</dt_scalar>""")
        self.assert_decoded_xml("foo", xml)

    def test_parse_list_message(self):
        xml = self.wrap_message_xml("""<dt_array>
          <item key='0'>foo</item>
          <item key='1'>bar</item>
        </dt_array>""")
        self.assert_decoded_xml(["foo", "bar"], xml)

    def test_parse_list_message_unordered(self):
        xml = self.wrap_message_xml("""<dt_array>
          <item key='1'>bar</item>
          <item key='0'>foo</item>
        </dt_array>""")
        self.assert_decoded_xml(["foo", "bar"], xml)

    def test_parse_dict_message(self):
        xml = self.wrap_message_xml("""<dt_assoc>
          <item key='foo'>bar</item>
          <item key='baz'>quux</item>
        </dt_assoc>""")
        self.assert_decoded_xml({"foo": "bar", "baz": "quux"}, xml)

    def test_parse_complex_dict_message(self):
        data = {
            "foo": ["bar", ["b1", {"b1": "b2"}]],
            "baz": {"bk1": ["bv1a", "bv1b"], "bk2": "bv2"},
            "text": "value",
            "none": None,
        }
        xml = self.wrap_message_xml("""<dt_assoc>
          <item key='foo'><dt_array>
            <item key='0'>bar</item>
            <item key='1'><dt_array>
              <item key='1'><dt_assoc>
                <item key='b1'>b2</item>
              </dt_assoc></item>
              <item key='0'>b1</item>
            </dt_array></item>
          </dt_array></item>
          <item key='text'>value</item>
          <item key='none'/>
          <item key='baz'><dt_assoc>
            <item key='bk1'><dt_array>
              <item key='0'>bv1a</item>
              <item key='1'>bv1b</item>
            </dt_array></item>
            <item key='bk2'>bv2</item>
          </dt_assoc></item>
        </dt_assoc>""")
        self.assert_decoded_xml(data, xml)

    def test_parse_complex_list_message(self):
        data = [
            "None",
            ["bar", ["b1", {"b1": "b2"}]],
            None,
            {"bk1": ["bv1a", "bv1b"], "bk2": "bv2"},
            "text",
        ]
        xml = self.wrap_message_xml("""<dt_array>
          <item key='1'><dt_array>
            <item key='0'>bar</item>
            <item key='1'><dt_array>
              <item key='1'><dt_assoc>
                <item key='b1'>b2</item>
              </dt_assoc></item>
              <item key='0'>b1</item>
            </dt_array></item>
          </dt_array></item>
          <item key='0'>None</item>
          <item key='2' />
          <item key='4'>text</item>
          <item key='3'><dt_assoc>
            <item key='bk1'><dt_array>
              <item key='0'>bv1a</item>
              <item key='1'>bv1b</item>
            </dt_array></item>
            <item key='bk2'>bv2</item>
          </dt_assoc></item>
        </dt_array>""")
        self.assert_decoded_xml(data, xml)


class XCPMessageTest(TestCase):

    def test_create_message(self):
        data = {
            'protocol': 'XCP',
            'action': 'LOOKUP',
            'object': 'DOMAIN',
            'attributes': {'domain': 'jerith.org'},
        }
        lookup_msg = xcp.XCPMessage(action='LOOKUP',
                                    object='DOMAIN',
                                    attributes={'domain': 'jerith.org'})
        self.assertEqual(data, lookup_msg.ops_message.get_data())

    def test_sign_message(self):
        lookup_msg = xcp.XCPMessage(action='LOOKUP',
                                    object='DOMAIN',
                                    attributes={'domain': 'jerith.org'})
        self.assertEqual('001806d5425a40aaaec238ffe23bc8f2',
                         lookup_msg.sign('somekey'.encode('UTF-8')))
