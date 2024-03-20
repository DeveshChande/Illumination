import requests
from typing import Optional
import utils

class FileHash:
    def __init__(self) -> None:
        self.virustotal = ""

    """
    Fetches the attributes associated with the file object stored in the VirusTotal database for the desired SHA256 hash.

    Args:
        s (requests.Session): The requests Session object to use for the HTTP connection.
        file_hash (str): The desired SHA256 hash for which the details are fetched.

    Returns:
        str: A JSON object
    """

    def retrieve_virustotal_file_object(self, VIRUSTOTAL_API_KEY: str, s: requests.Session, sha256hash: Optional[str] = None) -> None:
        
        url = f"https://www.virustotal.com/api/v3/files/{sha256hash}"
        headers = {
        "accept":"application/json","x-apikey":f"{VIRUSTOTAL_API_KEY}"}

        self.virustotal = utils.get_JSON_response(s, url, headers)
    
    