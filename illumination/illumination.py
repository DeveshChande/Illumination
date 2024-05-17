import argparse
import file_hash
import ip_address
from os import environ
import requests
import utils


ABUSEIPDB_API_KEY = ""
VIRUSTOTAL_API_KEY = ""
CENSYS_API_ID = ""
CENSYS_API_SECRET = ""

def file_hash_analysis(program_arguments: dict, VIRUSTOTAL_API_KEY: str, sha256hash: str) -> None:
    """
    Performs hash based information retrieval from trusted sources.

    Args:
        program_arguments (dict): Dictionary representing the arguments passed by the user.
        VIRUSTOTAL_API_KEY (str): User-defined VirusTotal API Key.
        sha256hash (str): User specified SHA256 hash.

    Returns:
        None
    """

    try:
        file_hash_object = file_hash.FileHash()
        s = requests.Session()

        if program_arguments["virustotal"]:
            file_hash_object.retrieve_virustotal_file_object(VIRUSTOTAL_API_KEY, s, sha256hash)

        s.close()
        print(file_hash_object.virustotal)
    except RuntimeError as re:
        print(re)
        print("Ambiguous error occurred.\n")


def ip_analysis(program_arguments: dict, ABUSEIPDB_API_KEY: str, VIRUSTOTAL_API_KEY: str, ip: str):
    """
    Performs IP Address based information retrieval from trusted sources.

    Args:
        program_arguments (dict): Dictionary representing the arguments passed by the user.
        ABUSEIPDB_API_KEY (str): User-defined AbuseIPDB API Key.
        VIRUSTOTAL_API_KEY (str): User-defined VirusTotal API Key.
        ip (str): User specified IP Address.

    Returns:
        None
    """

    try:
        ip_address_object = ip_address.InternetProtocolAddress()
        s = requests.Session()

        if program_arguments["abuseipdb"]:
            ip_address_object.retrieve_abuseipdb_ip_object(ABUSEIPDB_API_KEY, s, ip)

        if program_arguments["virustotal"]:
            ip_address_object.retrieve_virustotal_ip_object(VIRUSTOTAL_API_KEY, s, ip)

        if program_arguments["censys"]:
            environ['CENSYS_API_ID'] = CENSYS_API_ID
            environ['CENSYS_API_SECRET'] = CENSYS_API_SECRET
            ip_address_object.retrieve_censys_ip_object(ip)

        s.close()
        print(ip_address_object.abuseipdb)
        print(ip_address_object.virustotal)
        print(ip_address_object.censys)

    except RuntimeError as re:
        print(re)
        print("Ambiguous error occurred.\n")


def parse_arguments():
    """
    Parses command-line arguments securely using argparse.

    Returns:
        argparse.Namespace: An object containing parsed arguments.
    """

    parser = argparse.ArgumentParser(description="Illumination is a CLI tool to enrich atomic data.\n",
                                     epilog="Written by Devesh Chande.\n",
                                     usage="python3 illumination.py [-i {IP_ADDR} | -s {SHA256_HASH}] [-a] [-v]")

    parser.add_argument('-i', '--ip', help="Specify IP Address.")
    parser.add_argument('-s', '--sha256hash', help="Specify SHA256 Hash.")
    parser.add_argument('-v', '--virustotal', action="store_true", default=False, help="Enrich data from VirusTotal API.")
    parser.add_argument('-a', '--abuseipdb', action="store_true", default=False, help="Enrich data from AbuseIPDB API.")
    parser.add_argument('-c', '--censys', action='store_true', default=False, help="Enrich data from Censys API.")
    
    args = parser.parse_args()
    return args
    

if __name__ == "__main__":
    try:
        arguments = parse_arguments()

        if arguments.ip is not None and utils.validate_ip_address(arguments.ip):
            ip_analysis(arguments.__dict__, ABUSEIPDB_API_KEY, VIRUSTOTAL_API_KEY, arguments.ip)

        if arguments.sha256hash is not None and utils.validate_file_hash(arguments.sha256hash):
            file_hash_analysis(arguments.__dict__, VIRUSTOTAL_API_KEY, arguments.sha256hash)

    except argparse.ArgumentError as arg_err:
        print(arg_err)
        print("Failed to parse arguments.\n")
