import unittest

from bsd_syslog_message_utils import parse
from bsd_syslog_message_utils.core import SyslogMessage


class TestParse(unittest.TestCase):
    def test_basic_with_pid(self):
        raw = "<34>Oct 11 22:14:15 mymachine su: 'su root' failed"
        m = parse(raw)
        self.assertEqual(m.priority, 34)
        self.assertEqual(m.facility, 4)
        self.assertEqual(m.severity, 2)
        self.assertEqual(m.timestamp, "Oct 11 22:14:15")
        self.assertEqual(m.hostname, "mymachine")
        self.assertEqual(m.tag, "su")
        self.assertEqual(m.message, "'su root' failed")

    def test_basic_without_pid(self):
        raw = "<13>Oct 11 22:14:15 mymachine app: hello world"
        m = parse(raw)
        self.assertEqual(m.priority, 13)
        self.assertEqual(m.facility, 1)
        self.assertEqual(m.severity, 5)
        self.assertEqual(m.hostname, "mymachine")
        self.assertEqual(m.tag, "app")
        self.assertEqual(m.message, "hello world")

    def test_priority_boundary_max(self):
        raw = "<191>Oct 11 22:14:15 host tag: msg"
        m = parse(raw)
        self.assertEqual(m.priority, 191)
        self.assertEqual(m.facility, 23)
        self.assertEqual(m.severity, 7)

    def test_priority_boundary_min(self):
        raw = "<0>Oct 11 22:14:15 host tag: msg"
        m = parse(raw)
        self.assertEqual(m.priority, 0)
        self.assertEqual(m.facility, 0)
        self.assertEqual(m.severity, 0)

    def test_single_digit_day(self):
        raw = "<34>Oct  1 22:14:15 host su: failed"
        m = parse(raw)
        self.assertEqual(m.timestamp, "Oct  1 22:14:15")

    def test_trailing_newline_stripped(self):
        raw = "<34>Oct 11 22:14:15 host su: failed\n"
        m = parse(raw)
        self.assertEqual(m.message, "failed")

    def test_empty_message(self):
        raw = "<34>Oct 11 22:14:15 host su:"
        m = parse(raw)
        self.assertEqual(m.tag, "su")
        self.assertEqual(m.message, "")

    def test_missing_pri_raises(self):
        with self.assertRaises(ValueError):
            parse("Oct 11 22:14:15 host su: failed")

    def test_bad_month_raises(self):
        with self.assertRaises(ValueError):
            parse("<34>Xoc 11 22:14:15 host su: failed")

    def test_day_out_of_range(self):
        with self.assertRaises(ValueError):
            parse("<34>Oct 32 22:14:15 host su: failed")

    def test_priority_out_of_range(self):
        with self.assertRaises(ValueError):
            parse("<200>Oct 11 22:14:15 host su: failed")

    def test_missing_hostname_section(self):
        with self.assertRaises(ValueError):
            parse("<34>Oct 11 22:14:15")

    def test_message_with_colon(self):
        raw = "<34>Oct 11 22:14:15 host app: path: /var/log"
        m = parse(raw)
        self.assertEqual(m.tag, "app")
        self.assertEqual(m.message, "path: /var/log")

    def test_tag_with_slash_and_pid(self):
        raw = "<34>Oct 11 22:14:15 host my-app/worker[123]: starting"
        m = parse(raw)
        self.assertEqual(m.tag, "my-app/worker")
        self.assertEqual(m.message, "starting")

    def test_message_empty_after_colon(self):
        raw = "<34>Oct 11 22:14:15 host app: "
        m = parse(raw)
        self.assertEqual(m.tag, "app")
        self.assertEqual(m.message, "")

    def test_return_type(self):
        raw = "<34>Oct 11 22:14:15 host su: failed"
        m = parse(raw)
        self.assertIsInstance(m, SyslogMessage)
        self.assertIsInstance(m.priority, int)
        self.assertIsInstance(m.facility, int)
        self.assertIsInstance(m.severity, int)
        self.assertIsInstance(m.timestamp, str)
        self.assertIsInstance(m.hostname, str)
        self.assertIsInstance(m.tag, str)
        self.assertIsInstance(m.message, str)


if __name__ == "__main__":
    unittest.main()
