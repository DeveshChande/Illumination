import requests
from typing import Optional
import utils

ABUSEIPDB_API_KEY = ""

"""
Fetches the attributes associated with the IP object stored in the AbuseIPDB database for the desired IP Address.

Args:
    s (requests.Session): The requests Session object to use for the HTTP connection.
    ip (str): The desired IP Address for which the details are fetched.

Returns:
    str: A JSON object
"""

def get_abuseipdb_ip_object(s: requests.Session, ip: Optional[str] = None) -> str:
    url = "https://api.abuseipdb.com/api/v2/check"
    query_string = {
        "ipAddress": ip,
        "maxAgeInDays": "7"
    }
    headers = {
        "Accept": "application/json",
        "Key": ABUSEIPDB_API_KEY 
    }

    
    return utils.get_JSON_response(s, url=url, headers=headers, params=query_string)

"""
Fetches attributes for the specific object from the VirusTotal database.

Args:
    ip (str, Optional): The IP Address about which to fetch details.
    hash (str, Optional): The file hash about which to fetch details.

Raises:
    RunTimeError to catch ambiguous errors during request processing.
"""
def abuseipdb(ip: Optional[str] = None):
    try:
        s = requests.Session()
        if ip is not None and utils.validate_ip_address(ip):
            ip_object = get_abuseipdb_ip_object(s, ip)
            print(ip_object)
        else:
            print("Check URL.\n")
        
        s.close()
    except RuntimeError as e:
        print(e)
        print("An ambiguous error occurred.\n")