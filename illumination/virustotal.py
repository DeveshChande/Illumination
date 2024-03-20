import requests
from typing import Optional
import utils


VIRUSTOTAL_API_KEY = ""

"""
Fetches the attributes associated with the IP object stored in the VirusTotal database for the desired IP Address.

Args:
    s (requests.Session): The requests Session object to use for the HTTP connection.
    ip (str): The desired IP Address for which the details are fetched.

Returns:
    str: A JSON object
"""
def get_virustotal_ip_object(s: requests.Session, ip: Optional[str] = None) -> str:
    
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {
    "accept":"application/json","x-apikey":f"{VIRUSTOTAL_API_KEY}"}

    return utils.get_JSON_response(s, url, headers)



"""
Fetches the attributes associated with the file object stored in the VirusTotal database for the desired SHA256 hash.

Args:
    s (requests.Session): The requests Session object to use for the HTTP connection.
    file_hash (str): The desired SHA256 hash for which the details are fetched.

Returns:
    str: A JSON object
"""
def get_virustotal_file_object(s: requests.Session, file_hash: Optional[str] = None) -> str:
    
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {
    "accept":"application/json","x-apikey":f"{VIRUSTOTAL_API_KEY}"}

    return utils.get_JSON_response(s, url, headers)



"""
Fetches attributes for the specific object from the VirusTotal database.

Args:
    ip (str, Optional): The IP Address about which to fetch details.
    hash (str, Optional): The file hash about which to fetch details.

Raises:
    RunTimeError to catch ambiguous errors during request processing.
"""
def virustotal(ip: Optional[str] = None, file_hash: Optional[str] = None):
    try:
        s = requests.Session()
        if ip is not None and utils.validate_ip_address(ip):
            ip_object = get_virustotal_ip_object(s, ip)
            print(ip_object)
        elif file_hash is not None and utils.validate_file_hash(file_hash):
            file_hash_object = get_virustotal_file_object(s, file_hash)
            print(file_hash_object)
        else:
            print("Check URL.\n")
        s.close()
    except RuntimeError as e:
        print(e)
        print("An ambiguous error occurred.\n")