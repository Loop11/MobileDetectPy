import unittest

from ..detect import MobileDetect


class TestHeaders(unittest.TestCase):
    def test_mobile_headers(self):
        mobile_headers = [{
            'HTTP_ACCEPT': 'application/x-obml2d'
        }, {
            'HTTP_ACCEPT': 'application/vnd.wap.xhtml+xml'
        }, {
            'HTTP_X_WAP_PROFILE': 'anything'
        }, {
            'HTTP_X_ATT_DEVICEID': 'anything'
        }, {
            'HTTP_UA_CPU': 'ARM'
        }]
        for headers in mobile_headers:
            md = MobileDetect(headers=headers)
            self.assertTrue(md.is_mobile())
