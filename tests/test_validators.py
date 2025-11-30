import unittest

from scanner import port_scanner


class TestValidators(unittest.TestCase):
    # Unit tests for input validation functions

    def test_validate_ip_address_valid_ipv4(self):
        # Testing common valid IP addresses to ensure they pass validation
        self.assertTrue(port_scanner.validate_ip_address("192.168.1.1"))
        self.assertTrue(port_scanner.validate_ip_address("10.0.0.1"))
        self.assertTrue(port_scanner.validate_ip_address("127.0.0.1"))

    def test_validate_ip_address_invalid(self):
        # These should all fail validation - testing edge cases
        self.assertFalse(port_scanner.validate_ip_address("256.1.1.1"))
        self.assertFalse(port_scanner.validate_ip_address("192.168.1"))
        self.assertFalse(port_scanner.validate_ip_address("not_an_ip"))
        self.assertFalse(port_scanner.validate_ip_address(""))

    def test_validate_ip_address_valid_ipv6(self):
        # I included IPv6 tests because the ipaddress library supports both
        self.assertTrue(port_scanner.validate_ip_address("::1"))
        self.assertTrue(port_scanner.validate_ip_address("2001:db8::1"))

    def test_get_service_name_normalized(self):
        # Testing that service names get properly mapped to CVE database format
        self.assertEqual(
            port_scanner.get_service_name_normalized("ssh", "OpenSSH"),
            "OpenSSH"
        )
        self.assertEqual(
            port_scanner.get_service_name_normalized("http", "Apache httpd"),
            "Apache HTTP"
        )
        self.assertEqual(
            port_scanner.get_service_name_normalized("http", "nginx"),
            "nginx"
        )


if __name__ == '__main__':
    unittest.main()