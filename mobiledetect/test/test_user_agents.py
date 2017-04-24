import os
import json
import unittest

from ..detect import MobileDetect


class TestUserAgents(unittest.TestCase):
    def setUp(self):
        filename = os.path.join(
            os.path.dirname(os.path.realpath(__file__)),
            "test_data.json")
        with open(filename) as f:
            self.user_agents = json.load(f)

    def test_is_mobile(self):
        for entry in self.user_agents["user_agents"]:
            if "mobile" not in entry:
                continue
            user_agent = entry["user_agent"]
            md = MobileDetect(user_agent=user_agent)

            self.check_versions(md, entry)
            is_mobile = md.is_mobile()
            if entry["mobile"]:
                self.assertTrue(
                    is_mobile,
                    msg="Failed mobile user-agent string: '%s'" % user_agent)
            else:
                self.assertFalse(
                    is_mobile,
                    msg="Failed mobile user-agent string: '%s'" % user_agent)

    def test_is_tablet(self):
        for entry in self.user_agents["user_agents"]:
            if "tablet" not in entry:
                continue
            user_agent = entry["user_agent"]
            md = MobileDetect(user_agent=user_agent)

            self.check_versions(md, entry)
            is_tablet = md.is_tablet()
            if entry["tablet"]:
                self.assertTrue(
                    is_tablet,
                    msg="Failed tablet useragent string: '%s'" % user_agent)
            else:
                self.assertFalse(
                    is_tablet,
                    msg="Failed tablet useragent string: '%s'" % user_agent)

    def check_versions(self, md, entry):
        try:
            for key, version in entry["version"].iteritems():
                self.assertEqual(
                    md.prepare_version_no(version), md.version(key))
        except KeyError:
            # skip version check when no version entry
            pass
