import requests
from typing import Optional
import utils

class InternetProtocolAddress:

    def __init__(self) -> None:
        self.abuseipdb = ""
        self.virustotal = ""

    """
    Fetches the attributes associated with the IP object stored in the AbuseIPDB database for the desired IP Address.

    Args:
        s (requests.Session): The requests Session object to use for the HTTP connection.
        ip (str): The desired IP Address for which the details are fetched.

    Returns:
        str: A JSON object
    """

    def retrieve_abuseipdb_ip_object(self, ABUSEIPDB_API_KEY: str, s: requests.Session, ip: Optional[str] = None) -> None:
        url = "https://api.abuseipdb.com/api/v2/check"
        query_string = {
            "ipAddress": ip,
            "maxAgeInDays": "7"
        }
        headers = {
            "Accept": "application/json",
            "Key": ABUSEIPDB_API_KEY 
        }

        
        self.abuseipdb = utils.get_JSON_response(s, url=url, headers=headers, params=query_string)
    
    """
    Fetches the attributes associated with the IP object stored in the VirusTotal database for the desired IP Address.

    Args:
        s (requests.Session): The requests Session object to use for the HTTP connection.
        ip (str): The desired IP Address for which the details are fetched.

    Returns:
        str: A JSON object
    """

    def retrieve_virustotal_ip_object(self, VIRUSTOTAL_API_KEY: str, s: requests.Session, ip: Optional[str] = None) -> None:
        
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        headers = {
        "accept":"application/json","x-apikey":f"{VIRUSTOTAL_API_KEY}"}

        self.virustotal = utils.get_JSON_response(s, url=url, headers=headers)