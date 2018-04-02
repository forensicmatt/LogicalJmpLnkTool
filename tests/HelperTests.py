import sys
sys.path.append("..")
import struct
import unittest
from libljlt import Helpers


class DateTimeFunctionTests(unittest.TestCase):
    def test_to_string(self):
        raw_timestamp = b"\xBF\x8B\x9A\x52\x96\xCE\xCE\x01"
        u64_int = struct.unpack("<Q", raw_timestamp)[0]

        dt_object = Helpers.datetime_from_u64(u64_int)
        dt_str = dt_object.strftime("%Y-%m-%d %H:%M:%S")
        self.assertEqual(dt_str, "2013-10-21 19:47:06")


if __name__ == '__main__':
    unittest.main()
