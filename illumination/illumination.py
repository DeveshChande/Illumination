import abuseipdb
import argparse
import virustotal


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
            virustotal.virustotal(arguments.ip, arguments.file)
        
        if arguments.abuseipdb:
            abuseipdb.abuseipdb(arguments.ip)
    except argparse.ArgumentError as arg_err:
        print(arg_err)
        print("Failed to parse arguments.\n")
