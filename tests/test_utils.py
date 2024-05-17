from illumination import utils
import requests
import unittest
from unittest.mock import Mock


class TestUtils(unittest.TestCase):

    def test_validate_file_hash(self):

        # Validates true SHA256 hash
        self.assertTrue(utils.validate_file_hash("9930e58ec9ff55edb27281ed06cc68bf7fb31593eabdaad88d928c4c2a13973b"))

        # Validates incorrect length
        self.assertFalse(utils.validate_file_hash("9930e"))

        # Validates Incorrect character set

        self.assertFalse(False, utils.validate_file_hash("9930e58ec9ff55edb27281ed0*cc68bf7fb31593eabdaad88d928c4c2a13973b"))


    def test_validate_ip_address(self):

        # Validates private IP Address
        self.assertEqual(False, utils.validate_ip_address("10.0.0.1"))

        # Validates public IP Address
        self.assertEqual(True, utils.validate_ip_address("193.23.90.191"))
    

    @unittest.mock.patch('requests.Session.get')
    def test_get_JSON_response(self, mock_get):
        mock_response = Mock()
        mock_response.json.return_value = {
            'data': {
                'ipAddress': '193.12.12.10',
                'isPublic': True,
                'ipVersion': 4,
                'isWhitelisted': None,
                'abuseConfidenceScore': 0,
                'usageType': None,
                'isTor': False,
                'totalReports': 0,
                'numDistinctUsers': 0,
                'lastReportedAt': None
            }
        }

        mock_get.return_value = mock_response

        s = requests.Session()
        url = f"https://api.example.com/"
        headers = {
            "API_KEY": "78bf9j235kbxm834636n"
        }
        params = {
            "id" : "0"
        }

        patched_response = utils.get_JSON_response(s,url=url, headers=headers, params=params)
        s.close()
        
        mock_get.assert_called_with(url='https://api.example.com/', params={'id': '0'}, headers={'API_KEY': '78bf9j235kbxm834636n'})
        self.assertEqual(patched_response, mock_response.json())

        
if __name__ == "__main__":
    unittest.main()
