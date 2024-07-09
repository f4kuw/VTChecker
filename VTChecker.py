import time
import requests
import argparse
import configparser
from colorama import init, Fore, Style

# Initialize colorama
init(autoreset=True)

# Initialize API_KEYS, need a file called api_keys.ini (example provided on github)
config = configparser.ConfigParser()
config.read('api_keys.ini')

VIRUSTOTAL_API_KEY = config['API_KEYS']['VIRUSTOTAL_API_KEY']

#Formatting response for output
def format_response(results):
    formatted_response = ""
    if results["safe"]:
        formatted_response += "Safe files:\n"
        for safe_hash, internal_name in results["safe"]:
            formatted_response += f"Hash: {safe_hash} - Internal Name: {internal_name} - Virus Total URL: [VT](https://www.virustotal.com/gui/file/{safe_hash})\n"
    
    if results["malicious"]:
        formatted_response += "\nMalicious files:\n"
        for malicious_hash, internal_name in results["malicious"]:
            formatted_response += f"Hash: {malicious_hash} - Internal Name: {internal_name} - Virus Total URL: [VT](https://www.virustotal.com/gui/file/{malicious_hash})\n"
    
    if results["unknown"]:
        formatted_response += "\nUnknown files:\n"
        for unknown_hash, internal_name in results["unknown"]:
            formatted_response += f"Hash: {unknown_hash} - Internal Name: {internal_name} - Virus Total URL: [VT](https://www.virustotal.com/gui/file/{unknown_hash})\n"
    
    return formatted_response

def write_to_file(output_filename, results):
    formatted_results = format_response(results)
    with open(output_filename, 'w') as file:
        file.write(formatted_results)

def main(file_path, output_filename):
    headers = {
        'x-apikey': VIRUSTOTAL_API_KEY
    }
    
    results = {
        "malicious": [],
        "safe": [],
        "unknown": []
    }

    with open(file_path, 'r') as file:
        for line in file:
            file_hash = line.strip()  # Remove any whitespace
            if file_hash:  # Ensure the hash is not empty
                url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
                print(f"Checking hash: {file_hash}")
                response = requests.get(url, headers=headers)
                if response.status_code == 200:
                    result = response.json()
                    attributes = result.get('data', {}).get('attributes', {})
                    internal_name = attributes.get('names', [None])[0] if attributes.get('names') else 'N/A'
                    
                    if attributes.get('last_analysis_stats', {}).get('malicious', 0) > 0:
                        results["malicious"].append((file_hash, internal_name))
                    else:
                        results["safe"].append((file_hash, internal_name))
                elif response.status_code == 404:
                    results["unknown"].append((file_hash, 'N/A'))
                else: # Handling errors
                    print(f"{Fore.YELLOW}Unexpected error for hash {file_hash}: {response.status_code} - {response.text}")
    
    if results["safe"]:
        print(f"\n{Fore.GREEN}Safe files:")
        for safe_hash, internal_name in results["safe"]:
            print(f"{Fore.GREEN}Hash: {safe_hash} - Internal Name: {internal_name} - Virus Total URL: [VT](https://www.virustotal.com/gui/file/{safe_hash})")
        
    if results["malicious"]:
        print(f"\n{Fore.RED}Malicious files:")
        for malicious_hash, internal_name in results["malicious"]:
            print(f"{Fore.RED}Hash: {malicious_hash} - Internal Name: {internal_name} - Virus Total URL: [VT](https://www.virustotal.com/gui/file/{malicious_hash})")
        
    if results["unknown"]:
        print(f"\n{Fore.YELLOW}Unknown files:")
        for unknown_hash, internal_name in results["unknown"]:
            print(f"{Fore.YELLOW}Hash: {unknown_hash} - Internal Name: {internal_name} - Virus Total URL: [VT](https://www.virustotal.com/gui/file/{unknown_hash})")
    
    print(f"\n{Fore.GREEN}VirusTotal analysis completed!")
    print(f"{Fore.BLUE}Writing data into file {output_filename}")
    write_to_file(output_filename, results)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=f"Welcome to VTChecker. Please provide your API key in a file called api_keys.ini, in the same directory than VTChecker.py (example provided on github)")
    parser.add_argument('file_path', help="Path to the file containing the hashes to be analyzed")
    args = parser.parse_args()
    
    output_filename = "VTCheck_output.txt"
    print("""
            Welcome to VTChecker ! 
            This script aims to check multiple hashes in a .txt file with Virus Total API. 


                            ⢀⣴⣶⣤⣤⣤⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
                            ⢸⣿⣿⣿⣿⠇⠈⠉⠳⢦⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
                            ⠸⣿⡃⠀⠀⠀⠀⠀⠀⠀⠉⠳⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣀⣠⣤⣤⣤⣀⣀⠀⠀
                            ⠀⣯⣧⠀⠀⠀⠀⠀⠀⠤⠔⠒⠛⠉⠉⠛⠛⠒⠶⢤⣠⠴⠒⠋⠉⠉⠀⠀⠀⠈⢿⣿⣿⡿⠀⠀
                            ⠀⠸⣿⣧⠀⠀⣠⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠑⠀⠀⠀⠀⠀⠀⠀⠀⠈⣩⣿⠁⠀⠀
                            ⠀⠀⠹⣟⠧⡴⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⡀⠀⠀⠀⢠⣾⣱⠇⠀⠀⠀
                            ⠀⠀⠀⠙⢦⠇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢧⠀⢀⡴⠋⣰⠋⠀⠀⠀⠀
                            ⠀⠀⠀⢀⡞⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⠖⠋⣠⡞⠁⠀⠀⠀⠀⠀
                            ⠀⠀⠀⣸⢣⣾⣿⣧⠀⠀⠀⠀⠀⢀⣀⣀⣀⠀⠀⠀⠀⢀⣤⣤⡄⠸⣦⠶⠋⠀⠀⠀⠀⠀⠀⠀
                            ⠀⠀⠀⢿⣤⠿⠛⠛⠒⠉⠉⠁⣿⠟⠒⠚⣷⠈⠉⠒⠤⢸⣿⣿⡇⢀⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀
                            ⠀⠀⠀⠀⠈⠙⠲⢤⣀⣀⠀⠀⠹⣄⣀⣠⠎⠀⠀⠀⠀⠀⣀⣠⡴⠟⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀
                            ⠀⠀⠀⠀⠀⠀⠀⢸⠁⠉⣹⣤⡆⠀⠀⣤⣀⣖⠒⠒⠈⢻⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
                            ⠀⠀⠀⠀⠀⠀⠀⡏⠰⢺⣿⣿⣿⠀⠀⣿⣿⡿⠋⠀⠀⠸⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
                            ⠀⠀⠀⠀⠀⠀⢰⠇⠀⠀⠁⠉⡟⠀⠀⢻⡛⠁⠀⠀⠀⠀⢳⣠⠶⠾⠧⠤⣄⣀⠀⠀⠀⠀⠀⠀
                            ⠀⠀⠀⠀⠀⠀⡾⠀⠀⠀⠀⣴⡃⠀⠀⣀⣧⠀⠀⠀⠀⠀⠈⢧⠀⠀⠀⠀⠀⠉⠳⣄⠀⠀⠀⠀
                            ⠀⠀⠀⠀⠀⢸⠃⠀⠀⠀⠈⠁⠻⠓⢄⡇⠀⠳⡄⠀⠀⠀⠀⠘⣇⠀⠀⠀⠀⠀⠀⢘⣆⠀⠀⠀
                            ⠀⠀⠀⠀⠀⡟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣄⣤⣄⡀⠀⢰⣿⢿⡄⠀⠀
                            ⠀⠀⠀⠀⠐⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⡇⠉⠉⠉⠙⠿⣅⡀⢧⡀⠀
                            ⠀⠀⠀⠀⠀⠙⠒⠦⠤⠤⠤⠤⠤⠤⠤⠤⠤⠤⠤⠴⠶⠖⠒⠛⠉⠀⠀⠀⠀⠀⠀  ⠾⠷⠀⠀⠀⠀⠀⠀⠀⠀

                            I hope you'll enjoy this little script !⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
                                        Twitter: @_f4ku
                                        Github: f4kuw
    """

      )

    main(args.file_path, output_filename)
