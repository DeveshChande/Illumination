import argparse
import requests
from typing import Optional
import ipaddress


ABUSEIPDB_API_KEY = ""
VIRUSTOTAL_API_KEY = ""


"""
Determines whether the specified file hash is a valid SHA256 hash.

Args:
    file_hash (str): The file hash to validate.

Returns:
    bool: A boolean value.
"""
def validate_file_hash(file_hash: str) -> bool:
    if len(file_hash) != 64:
        return False
    try:
        if int(file_hash, 16):
            return True
    except ValueError as ve:
        print(ve)
        print("The provided file hash does not subscribe to the SHA256 hash format.\n")
        return False



"""
Determines whether the specified IP Address is allocated for private networks.

Args:
    ip (str): The IP Address to validate.

Returns:
    bool: A boolean value.
"""
def validate_ip_address(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ipaddress.AddressValueError as address_value_err:
        print(address_value_err)
        print("Invalid IP Address.\n")

"""
Fetches the appropriate JSON response from the concerned API endpoint.

Args:
    s (requests.Session): The requests Session object to use for the HTTP connection.

    url (str): The URL of the API Endpoint.

    headers (dict): The key-value pairs in the header associated with the request.
"""
def get_JSON_response(s: requests.Session, url: str, headers: dict) -> str:
    try:
        object_response = s.get(url=url, headers=headers)
        return object_response.json()
    except requests.exceptions.ConnectTimeout as conn_timeout:
        print(conn_timeout)
        print("Connection timed out.\n")
    except requests.exceptions.ConnectionError as conn_err:
        print(conn_err)
        print("Failed to connect to the VirusTotal API endpoint.\n")
    except requests.ReadTimeout as read_timeout:
        print(read_timeout)
        print("Server failed to respond in appropriate time.\n")
    except requests.exceptions.HTTPError as http_err:
        print(http_err)
        print("HTTP error occurred.\n")
    except requests.exceptions.JSONDecodeError as json_decode_err:
        print(json_decode_err)
        print("Failed to decode the response received into JSON.\n")
    except requests.exceptions.RequestException as re:
        print(re)
        print("Something went wrong.\n")




"""
Fetches the attributes associated with the IP object stored in the VirusTotal database for the desired IP Address.

Args:
    s (requests.Session): The requests Session object to use for the HTTP connection.
    ip (str): The desired IP Address for which the details are fetched.

Returns:
    str: A JSON object

Raises:
    ConnectTimeout: The request timed out while trying to connect to the remote server.
    ConnectionError: A Connection error occurred.
    ReadTimeout: The server did not send any data in the allotted amount of time.
    HTTPError: An HTTP error occurred.
    JSONDecodeError: Could not decode the text into json.

"""
def get_virustotal_ip_object(s: requests.Session, ip: Optional[str] = None) -> str:
    
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {
    "accept":"application/json","x-apikey":f"{VIRUSTOTAL_API_KEY}"}

    return get_JSON_response(s, url, headers)
    

"""
Fetches the attributes associated with the file object stored in the VirusTotal database for the desired SHA256 hash.

Args:
    s (requests.Session): The requests Session object to use for the HTTP connection.
    file_hash (str): The desired SHA256 hash for which the details are fetched.

Returns:
    str: A JSON object

Raises:
    ConnectTimeout: The request timed out while trying to connect to the remote server.
    ConnectionError: A Connection error occurred.
    ReadTimeout: The server did not send any data in the allotted amount of time.
    HTTPError: An HTTP error occurred.
    JSONDecodeError: Could not decode the text into json.

"""
def get_virustotal_file_object(s: requests.Session, file_hash: Optional[str] = None) -> str:
    
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {
    "accept":"application/json","x-apikey":f"{VIRUSTOTAL_API_KEY}"}

    return get_JSON_response(s, url, headers)



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
        if ip is not None and validate_ip_address(ip):
            ip_object = get_virustotal_ip_object(s, ip)
            print(ip_object)
        elif file_hash is not None and validate_file_hash(file_hash):
            file_hash_object = get_virustotal_file_object(s, file_hash)
            print(file_hash_object)
        else:
            print("Check URL.\n")
    except RuntimeError as e:
        print(e)
        print("An ambiguous error occurred.\n")


"""
Parses command-line arguments securely using argparse.

Returns:
    argparse.Namespace: An object containing parsed arguments.
"""
def parse_arguments():
    parser = argparse.ArgumentParser(description="Illumination is a CLI tool to enrich atomic data.\n",
                                     epilog="Written by Devesh Chande.\n", 
                                     usage="python3 illumination.py [options]")
    
    parser.add_argument('-i', '--ip', help="Specify IP Address.")
    parser.add_argument('-f', '--file', help="Specify SHA256 Hash.")
    parser.add_argument('-v', '--virustotal', action="store_true", default=False, help="Enable VirusTotal analysis.")
    parser.add_argument('-a', '--abuseipdb', action="store_true", default=False, help="Enable AbuseIPDB analysis.")
    
    args = parser.parse_args()
    return args
    

if __name__ == "__main__":
    try:
        arguments = parse_arguments()

        if arguments.virustotal:
            virustotal(arguments.ip, arguments.file)
    except argparse.ArgumentError as arg_err:
        print(arg_err)
        print("Failed to parse arguments.\n\n")
