import sys
sys.path.append("..")
import unittest
from libljlt.LnkHandler import Uuid


class UuidTests(unittest.TestCase):
    def test_to_string(self):
        uuid = Uuid(b"\x01\x14\x02\x00\x00\x00\x00\x00\xC0\x00\x00\x00\x00\x00\x00\x46")
        uuid_str = str(uuid)
        self.assertEqual(uuid_str, "00021401-0000-0000-c000-000000000046")


if __name__ == '__main__':
    unittest.main()
