"""Offline Python 2.7 checks: never import Main or open a socket."""
import os
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))
import IcmpHandler
import IpHandler


class HelperChecks(unittest.TestCase):
    def test_source_address_round_trip(self):
        packet = IpHandler.change_src_adr("\x00" * 42, "192.0.2.1")
        self.assertEqual(IpHandler.get_src_adr(packet), "192.0.2.1")

    def test_destination_address_round_trip(self):
        packet = IpHandler.change_dst_adr("\x00" * 42, "198.51.100.2")
        self.assertEqual(IpHandler.get_dst_adr(packet), "198.51.100.2")

    def test_reference_from_another_working_directory(self):
        packet = "\x00" * 34 + "\x08" + "\x00" * 7
        expected = IcmpHandler.icmp_type(packet)
        self.assertTrue(expected)
        original = os.getcwd()
        directory = tempfile.mkdtemp()
        try:
            os.chdir(directory)
            self.assertEqual(IcmpHandler.icmp_type(packet), expected)
        finally:
            os.chdir(original)
            os.rmdir(directory)

    def test_checksum_reset(self):
        packet = "\xff" * 42
        self.assertEqual(IcmpHandler.reset_icmp_check(packet)[36:38], "\x00\x00")


if __name__ == "__main__":
    unittest.main()
