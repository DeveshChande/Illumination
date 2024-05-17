from censys.search import CensysHosts
import ipinfo
from json import dumps
import requests
from typing import Optional
import utils

class InternetProtocolAddress:

    def __init__(self) -> None:
        self.abuseipdb = ""
        self.virustotal = ""
        self.censys = ""
        self.maxmind = ""
        self.ipinfo = ""

    def retrieve_abuseipdb_ip_object(self, ABUSEIPDB_API_KEY: str, s: requests.Session, ip: Optional[str] = None) -> None:
        """
        Fetches the attributes associated with the IP object stored in the AbuseIPDB database for the desired IP Address.

        Args:
            s (requests.Session): The requests Session object to use for the HTTP connection.
            ip (str): The desired IP Address for which the details are fetched.

        Returns:
            str: A JSON object
        """

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

    def retrieve_virustotal_ip_object(self, VIRUSTOTAL_API_KEY: str, s: requests.Session, ip: Optional[str] = None) -> None:
        """
        Fetches the attributes associated with the IP object stored in the VirusTotal database for the desired IP Address.

        Args:
            VIRUSTOTAL_API_KEY (str): VirusTotal API Key
            s (requests.Session): The requests Session object to use for the HTTP connection.
            ip (str): The desired IP Address for which the details are fetched.

        Returns:
            None
        """

        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        headers = {
        "accept":"application/json","x-apikey":f"{VIRUSTOTAL_API_KEY}"}

        self.virustotal = utils.get_JSON_response(s, url=url, headers=headers)

    def retrieve_censys_ip_object(self, ip: Optional[str] = None) -> None:
        """
        Enriches information from the Censys API.

        Args:
            ip (str): The IP Address to enrich.
        """
        h = CensysHosts()
        host = h.view(ip)
        self.censys = dumps(host)

    def retrieve_maxmind_ip_object(self, ACCOUNT_ID: str, LICENSE_KEY:str, ip: Optional[str] = None) -> None:
        """
        Enriches information from the MaxMind API.

        Args:
            ip (str): The IP Address to enrich.
        """
        url = f"https://geolite.info/geoip/v2.1/country/{ip}"
        headers = {"accept":"application/json"}
        self.maxmind = requests.get(url, headers, auth=(ACCOUNT_ID, LICENSE_KEY), timeout=5).text

    def retrieve_ipinfo_ip_object(self, ACCESS_TOKEN: str, ip: Optional[str] = None) -> None:
        """
        Enriches information from the IPInfo API.

        Args:
            ip (str): The IP Address to enrich.
        """

        handler = ipinfo.getHandler(ACCESS_TOKEN)
        self.ipinfo = dumps(handler.getDetails(ip).all)
