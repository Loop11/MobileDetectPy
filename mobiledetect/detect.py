#!/usr/bin/env python
"""
Mobile Detect - Python detection mobile phone and tablet devices

Thanks to:
    https://github.com/serbanghita/Mobile-Detect/blob/master/Mobile_Detect.php
"""

import re
import six
import json
import pkgutil
from hashlib import sha1


class MobileDetectRuleFileError(Exception):
    pass


class MobileDetectError(Exception):
    pass


# works in Python 2 & 3
class _Singleton(type):
    """ A metaclass that creates a Singleton base class when called. """
    _instances = {}

    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(_Singleton, cls).__call__(*args,
                                                                  **kwargs)
        return cls._instances[cls]


class Singleton(_Singleton('SingletonMeta', (object, ), {})):
    pass


class Rules(Singleton):
    def __init__(self):
        self.load_rules()

    def load_rules(self, filename=None):
        if filename is None:
            rules = json.loads(
                pkgutil.get_data(__name__, "Mobile_Detect.json").decode())
        else:
            with open(filename) as f:
                rules = json.load(f)

        if "version" not in rules:
            raise MobileDetectRuleFileError(
                "version not found in rule file: %s" % filename)
        if "headerMatch" not in rules:
            raise MobileDetectRuleFileError(
                "section 'headerMatch' not found in rule file: %s" % filename)
        if "uaHttpHeaders" not in rules:
            raise MobileDetectRuleFileError(
                "section 'uaHttpHeaders' not found in rule file: %s" %
                filename)
        if "uaMatch" not in rules:
            raise MobileDetectRuleFileError(
                "section 'uaMatch' not found in rule file: %s" % filename)
        if "properties" not in rules:
            raise MobileDetectRuleFileError(
                "section 'properties' not found in rule file: %s" % filename)

        self.mobile_headers = dict(
            (http_header, matches)
            for http_header, matches in six.iteritems(rules["headerMatch"]))

        self.ua_http_headers = rules['uaHttpHeaders']

        self.operating_systems = dict(
            (name, re.compile(match, re.IGNORECASE | re.DOTALL))
            for name, match in six.iteritems(rules['uaMatch']['os']))

        self.phone_devices = dict(
            (name, re.compile(match, re.IGNORECASE | re.DOTALL))
            for name, match in six.iteritems(rules['uaMatch']['phones']))

        self.tablet_devices = dict(
            (name, re.compile(match, re.IGNORECASE | re.DOTALL))
            for name, match in six.iteritems(rules['uaMatch']['tablets']))

        self.browsers = dict(
            (name, re.compile(match, re.IGNORECASE | re.DOTALL))
            for name, match in six.iteritems(rules['uaMatch']['browsers']))

        self.utilities = dict(
            (name, re.compile(match, re.IGNORECASE | re.DOTALL))
            for name, match in six.iteritems(rules['uaMatch']['utilities']))

        properties = rules['properties']
        for name, prop in six.iteritems(properties):
            if type(prop) is not list:
                properties[name] = [properties[name]]
        self.properties = properties

        self.all_rules = {}
        self.all_rules.update(self.operating_systems)
        self.all_rules.update(self.phone_devices)
        self.all_rules.update(self.tablet_devices)
        self.all_rules.update(self.browsers)

        self.all_rules_extended = {}
        self.all_rules_extended.update(self.all_rules)
        self.all_rules_extended.update(self.utilities)

        self.all_rules_extended = dict(
            (k.lower(), v) for k, v in six.iteritems(self.all_rules_extended))


class MobileDetect(object):
    MOBILE_GRADE_A = 'A'
    MOBILE_GRADE_B = 'B'
    MOBILE_GRADE_C = 'C'
    VERSION_TYPE_FLOAT = 'float'

    def __init__(self, request=None, user_agent=None, headers=None):
        self.request = request
        self.user_agent = user_agent
        self.headers = {}

        if self.request is not None:
            if self.user_agent is None:
                for http_header in Rules().ua_http_headers:
                    if http_header in request.META:
                        self.user_agent = request.META[http_header]
                        break

            for http_header, matches in six.iteritems(Rules().mobile_headers):
                if http_header not in request.META:
                    continue

                header_value = request.META[http_header]
                if matches and isinstance(matches,
                                          dict) and 'matches' in matches:
                    if header_value not in matches['matches']:
                        continue

                self.headers[http_header] = header_value

            if 'HTTP_X_OPERAMINI_PHONE_UA' in request.META:
                self.user_agent = "%s %s" % (
                    self.user_agent, request.META['HTTP_X_OPERAMINI_PHONE_UA'])

        if headers is not None:
            self.headers.update(headers)

        if self.user_agent is None:
            self.user_agent = ""

    def __getitem__(self, key):
        try:
            if Rules().all_rules[key].search(self.user_agent):
                return True
        except KeyError:
            pass
        return False

    def __contains__(self, key):
        try:
            if Rules().all_rules[key].search(self.user_agent):
                return True
        except KeyError:
            pass
        return False

    @property
    def device_hash(self):
        if not hasattr(self, '_device_hash'):
            hsh = sha1(self.user_agent)
            for k, v in self.headers.iteritems():
                hsh.update("%s:%s" % (k, v))
            self._device_hash = hsh.hexdigest()
        return self._device_hash

    def mobile_by_headers(self):
        """
        Check the HTTP Headers for signs of mobile devices.

        This is the fastest mobile check but probably also the most unreliable.
        """

        for header_name, rule in six.iteritems(Rules().mobile_headers):
            if header_name in self.headers:
                if rule is not None:
                    matches = rule['matches']
                    header_value = self.headers[header_name]
                    for match in matches:
                        if match in header_value:
                            return True
                    return False
                else:
                    return True

        return False

    def mobile_by_useragent(self):
        return self.is_phone() or self.is_tablet() or self.is_mobile_os(
        ) or self.is_mobile_ua()

    def is_phone(self):
        if self.detect_phone():
            return True
        return False

    def is_tablet(self):
        if self.detect_tablet():
            return True
        return False

    def is_mobile_os(self):
        if self.detect_mobile_os():
            return True
        return False

    def is_mobile_ua(self):
        if self.detect_mobile_ua():
            return True
        return False

    def detect_phone(self):
        """ Is Phone Device """
        for name, rule in six.iteritems(Rules().phone_devices):
            if rule.search(self.user_agent):
                return name
        return False

    def detect_tablet(self):
        """ Is Tabled Device """
        for name, rule in six.iteritems(Rules().tablet_devices):
            if rule.search(self.user_agent):
                return name
        return False

    def detect_mobile_os(self):
        """ Is Mobile OperatingSystem """
        for name, rule in six.iteritems(Rules().operating_systems):
            if rule.search(self.user_agent):
                return name
        return False

    def detect_mobile_ua(self):
        """ Is Mobile User-Agent """
        for name, rule in six.iteritems(Rules().browsers):
            if rule.search(self.user_agent):
                return name
        return False

    def is_mobile(self):
        if self.mobile_by_headers():
            return True

        return self.mobile_by_useragent()

    def is_rule(self, rule):
        rule = rule.lower()
        if rule in Rules().all_rules_extended:
            if Rules().all_rules_extended[rule].search(self.user_agent):
                return True
        return False

    def prepare_version_no(self, ver):
        ver = ver.replace('_', '.').replace(' ', '.').replace('/', '.')
        ver_list = ver.split('.', 1)
        if len(ver_list) > 1:
            ver_list[1] = ver_list[1].replace('.', '')
        try:
            result = float('.'.join(ver_list))
        except ValueError:
            result = 0
        return result

    def version(self, property_name):
        if not property_name or property_name not in Rules().properties:
            return False

        for property_match_string in Rules().properties[property_name]:
            property_pattern = property_match_string.replace('[VER]',
                                                             '([\w._\+]+)')

            matches = re.search(property_pattern, self.user_agent,
                                re.IGNORECASE | re.DOTALL)
            if matches is not None and len(matches.groups()) > 0:
                return self.prepare_version_no(matches.group(1))

        return False

    def match(self, rule):
        if re.search(rule, self.user_agent):
            return True
        return False

    def grade(self):
        """
        Return the browser 'grade'
        """
        isMobile = self.is_mobile()

        if (
                # Apple iOS 4-7.0 - Tested on the original iPad (4.3 / 5.0), iPad 2 (4.3 / 5.1 / 6.1), iPad 3 (5.1 / 6.0),
                # iPad Mini (6.1), iPad Retina (7.0), iPhone 3GS (4.3), iPhone 4 (4.3 / 5.1), iPhone 4S (5.1 / 6.0),
                # iPhone 5 (6.0), and iPhone 5S (7.0)
                self.is_rule('iOS') and self.version('iPad') >= 4.3 or
                self.is_rule('iOS') and self.version('iPhone') >= 4.3 or
                self.is_rule('iOS') and self.version('iPod') >= 4.3 or
                # Android 2.1-2.3 - Tested on the HTC Incredible (2.2), original Droid (2.2), HTC Aria (2.1),
                # Google Nexus S (2.3). Functional on 1.5 & 1.6 but performance may be sluggish, tested on Google G1 (1.5)
                # Android 3.1 (Honeycomb)  - Tested on the Samsung Galaxy Tab 10.1 and Motorola XOOM
                # Android 4.0 (ICS)  - Tested on a Galaxy Nexus. Note: transition performance
                # can be poor on upgraded devices
                # Android 4.1 (Jelly Bean)  - Tested on a Galaxy Nexus and Galaxy 7
            (self.version('Android') > 2.1 and self.is_rule('Webkit')) or
                # Windows Phone 7.5-8 - Tested on the HTC Surround (7.5), HTC Trophy (7.5), LG-E900 (7.5), Nokia 800 (7.8),
                # HTC Mazaa (7.8), Nokia Lumia 520 (8), Nokia Lumia 920 (8), HTC 8x (8)
                self.version('Windows Phone OS') >= 7.5 or
                # Tested on the Torch 9800 (6) and Style 9670 (6), BlackBerry Torch 9810 (7), BlackBerry Z10 (10)
                self.is_rule('BlackBerry') and
                self.version('BlackBerry') >= 6.0 or
                # Blackberry Playbook (1.0-2.0) - Tested on PlayBook
                self.match('Playbook.*Tablet') or
                # Palm WebOS (1.4-3.0) - Tested on the Palm Pixi (1.4), Pre (1.4), Pre 2 (2.0), HP TouchPad (3.0)
            (self.version('webOS') >= 1.4 and self.match('Palm|Pre|Pixi')) or
                # Palm WebOS 3.0  - Tested on HP TouchPad
                self.match('hp.*TouchPad') or
                # Firefox Mobile 18 - Tested on Android 2.3 and 4.1 devices
            (self.is_rule('Firefox') and self.version('Firefox') >= 18) or
                # Chrome for Android - Tested on Android 4.0, 4.1 device
            (self.is_rule('Chrome') and self.is_rule('AndroidOS') and
             self.version('Android') >= 4.0) or
                # Skyfire 4.1 - Tested on Android 2.3 device
            (self.is_rule('Skyfire') and self.version('Skyfire') >= 4.1 and
             self.is_rule('AndroidOS') and self.version('Android') >= 2.3) or
                # Opera Mobile 11.5-12: Tested on Android 2.3
            (self.is_rule('Opera') and self.version('Opera Mobi') >= 11.5 and
             self.is_rule('AndroidOS')) or
                # Meego 1.2 - Tested on Nokia 950 and N9
                self.is_rule('MeeGoOS') or
                # Tizen (pre-release) - Tested on early hardware
                self.is_rule('Tizen') or
                # Samsung Bada 2.0 - Tested on a Samsung Wave 3, Dolphin browser
                # @todo: more tests here!
                self.is_rule('Dolfin') and self.version('Bada') >= 2.0 or
                # UC Browser - Tested on Android 2.3 device
            ((self.is_rule('UC Browser') or self.is_rule('Dolfin')) and
             self.version('Android') >= 2.3) or
                # Kindle 3 and Fire  - Tested on the built-in WebKit browser for each
            (self.match('Kindle Fire') or self.is_rule('Kindle') and
             self.version('Kindle') >= 3.0) or
                # Nook Color 1.4.1 - Tested on original Nook Color, not Nook Tablet
                self.is_rule('AndroidOS') and self.is_rule('NookTablet') or
                # Chrome Desktop 16-24 - Tested on OS X 10.7 and Windows 7
                self.version('Chrome') >= 16 and not isMobile or
                # Safari Desktop 5-6 - Tested on OS X 10.7 and Windows 7
                self.version('Safari') >= 5.0 and not isMobile or
                # Firefox Desktop 10-18 - Tested on OS X 10.7 and Windows 7
                self.version('Firefox') >= 10.0 and not isMobile or
                # Internet Explorer 7-9 - Tested on Windows XP, Vista and 7
                self.version('IE') >= 7.0 and not isMobile or
                # Opera Desktop 10-12 - Tested on OS X 10.7 and Windows 7
                self.version('Opera') >= 10 and not isMobile):
            return self.MOBILE_GRADE_A

        if (self.is_rule('iOS') and self.version('iPad') < 4.3 or
                self.is_rule('iOS') and self.version('iPhone') < 4.3 or
                self.is_rule('iOS') and self.version('iPod') < 4.3 or
                # Blackberry 5.0: Tested on the Storm 2 9550, Bold 9770
                self.is_rule('Blackberry') and
                self.version('BlackBerry') >= 5 and
                self.version('BlackBerry') < 6 or
                # Opera Mini (5.0-6.5) - Tested on iOS 3.2/4.3 and Android 2.3
            (5.0 <= self.version('Opera Mini') <= 7.0 and
             (self.version('Android') >= 2.3 or self.is_rule('iOS'))) or
                # Nokia Symbian^3 - Tested on Nokia N8 (Symbian^3), C7 (Symbian^3), also works on N97 (Symbian^1)
                self.match('NokiaN8|NokiaC7|N97.*Series60|Symbian/3') or
                # @todo: report this (tested on Nokia N71)
                self.version('Opera Mobi') >= 11 and
                self.is_rule('SymbianOS')):
            return self.MOBILE_GRADE_B

        if (
                # Blackberry 4.x - Tested on the Curve 8330
                self.version('BlackBerry') <= 5.0 or
                # Windows Mobile - Tested on the HTC Leo (WinMo 5.2)
                self.match('MSIEMobile|Windows CE.*Mobile') or
                self.version('Windows Mobile') <= 5.2 or
                # Tested on original iPhone (3.1), iPhone 3 (3.2)
                self.is_rule('iOS') and self.version('iPad') <= 3.2 or
                self.is_rule('iOS') and self.version('iPhone') <= 3.2 or
                self.is_rule('iOS') and self.version('iPod') <= 3.2 or
                # Internet Explorer 7 and older - Tested on Windows XP
                self.version('IE') <= 7.0 and not isMobile):
            return self.MOBILE_GRADE_C

        # All older smartphone platforms and featurephones - Any device that doesn't support media queries
        # will receive the basic, C grade experience.
        return self.MOBILE_GRADE_C
