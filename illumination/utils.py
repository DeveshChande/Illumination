import ipaddress
import requests
from typing import Optional


def validate_file_hash(file_hash: str) -> bool:
    """
    Determines whether the specified file hash is a valid SHA256 hash.

    Args:
        file_hash (str): The file hash to validate.

    Returns:
        bool: A boolean value.
    """
    if len(file_hash) != 64:
        return False
    try:
        if int(file_hash, 16):
            return True
    except ValueError as ve:
        print(ve)
        print("The provided file hash does not subscribe to the SHA256 hash format.\n")
        return False


def validate_ip_address(ip: str) -> bool:
    """
    Determines whether the specified IP Address is allocated for private networks.

    Args:
        ip (str): The IP Address to validate.

    Returns:
        bool: A boolean value.
    """
    try:
        return not ipaddress.ip_address(ip).is_private
    except ipaddress.AddressValueError as address_value_err:
        print(address_value_err)
        print("Invalid IP Address.\n")


def get_JSON_response(s: requests.Session, url: str, headers: dict, params: Optional[dict] = None) -> str:
    """
    Fetches the appropriate JSON response from the concerned API endpoint.

    Args:
        s (requests.Session): The requests Session object to use for the HTTP connection.

        url (str): The URL of the API Endpoint.

        headers (dict): The key-value pairs in the header associated with the request.
    """
    try:
        object_response = s.get(url=url, params=params, headers=headers)
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