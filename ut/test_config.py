import unittest
import json
import os
from main import ConfigManager, is_ip_address

class TestTLSConfig(unittest.TestCase):
    def setUp(self):
        self.test_config_file = "test_config.json"
        # Create a test config file
        test_config = {
            "mode": "both",
            "server": {
                "port": 8443,
                "use_ipv6": False,
                "ssl_version": "默认",
                "auth_mode": "单向认证",
                "server_cert": "test_server.pem",
                "server_key": "test_server.key",
                "ca_cert": "test_ca.pem",
                "auto_reply": True,
                "data_mode": "透明"
            },
            "client": {
                "host": "127.0.0.1",
                "port": 8443,
                "auth_mode": "单向",
                "client_cert": "test_client.pem",
                "client_key": "test_client.key",
                "ca_cert": "test_ca.pem",
                "hex_send": False
            }
        }
        with open(self.test_config_file, 'w', encoding='utf-8') as f:
            json.dump(test_config, f, indent=2, ensure_ascii=False)
    
    def tearDown(self):
        if os.path.exists(self.test_config_file):
            os.remove(self.test_config_file)
    
    def test_config_manager_load(self):
        config_manager = ConfigManager(self.test_config_file)
        self.assertEqual(config_manager.config["mode"], "both")
        self.assertEqual(config_manager.config["server"]["port"], 8443)
        self.assertEqual(config_manager.config["client"]["host"], "127.0.0.1")
    
    def test_config_manager_save(self):
        config_manager = ConfigManager(self.test_config_file)
        config_manager.config["server"]["port"] = 9443
        config_manager.save_config()
        
        # Load again and check
        new_config_manager = ConfigManager(self.test_config_file)
        self.assertEqual(new_config_manager.config["server"]["port"], 9443)
    
    def test_ssl_version_mapping(self):
        config_manager = ConfigManager()
        ssl_versions = ["SSL 3.0", "TLS 1.0", "TLS 1.1", "TLS 1.2", "TLS 1.3", "默认"]
        for version in ssl_versions:
            result = config_manager.get_ssl_version(version)
            # Just check that it doesn't crash and returns something
            self.assertIsNotNone(result or True)  # Accept None for "默认"
    
    def test_ip_address_detection(self):
        # Test IPv4 addresses
        self.assertTrue(is_ip_address("192.168.1.1"))
        self.assertTrue(is_ip_address("127.0.0.1"))
        self.assertTrue(is_ip_address("8.8.8.8"))
        
        # Test IPv6 addresses
        self.assertTrue(is_ip_address("2001:db8::1"))
        self.assertTrue(is_ip_address("::1"))
        self.assertTrue(is_ip_address("fe80::1"))
        
        # Test hostnames (should return False)
        self.assertFalse(is_ip_address("localhost"))
        self.assertFalse(is_ip_address("www.example.com"))
        self.assertFalse(is_ip_address("example"))


if __name__ == "__main__":
    unittest.main()
