import time
import requests
import argparse
import configparser
import base64
from colorama import init, Fore, Style

# Initialize colorama
init(autoreset=True)

# Initialize API_KEYS, need a file called api_keys.ini (example provided on GitHub)
config = configparser.ConfigParser()
config.read('api_keys.ini')

VIRUSTOTAL_API_KEY = config['API_KEYS']['VIRUSTOTAL_API_KEY']

# Formatting response for output
def format_response(results, is_url=False):
    formatted_response = ""
    
    if results["safe"]:
        formatted_response += "## Safe files:  \n"
        for safe_item, internal_name in results["safe"]:
            formatted_response += f"- Hash/URL: ``{safe_item}`` - Internal Name: {internal_name} - [VT](https://www.virustotal.com/gui/url/{safe_item})  "
            if is_url:
                formatted_response += f" - [Browserling](https://browserling.com/browse/win10/chrome127/{safe_item})  "
            formatted_response += "\n"
    
    if results["malicious"]:
        formatted_response += "\n## Malicious files:  \n"
        for malicious_item, internal_name in results["malicious"]:
            formatted_response += f"- Hash/URL: ``{malicious_item}`` - Internal Name: {internal_name} - [VT](https://www.virustotal.com/gui/url/{malicious_item}) "
            if is_url:
                formatted_response += f" - [Browserling](https://browserling.com/browse/win10/chrome127/{malicious_item})  "
            formatted_response += "\n"
    
    if results["unknown"]:
        formatted_response += "\n## Unknown files:  \n"
        for unknown_item, internal_name in results["unknown"]:
            formatted_response += f"- Hash/URL: ``{unknown_item}`` - Internal Name: {internal_name} - [VT](https://www.virustotal.com/gui/url/{unknown_item})  "
            if is_url:
                formatted_response += f" - [Browserling](https://browserling.com/browse/win10/chrome127/{unknown_item})  "
            formatted_response += "\n"
    
    return formatted_response


def write_to_file(output_filename, results, is_url_check):
    formatted_results = format_response(results, is_url_check)
    with open(output_filename, 'w') as file:
        file.write(formatted_results)

def hash_checker(file_path, output_filename): # Hash checker function, sends a md5 or sha256 to check if it's known by VT
    headers = {'x-apikey': VIRUSTOTAL_API_KEY}
    results = {"malicious": [], "safe": [], "unknown": []}
    
    with open(file_path, 'r') as file:
        for line in file:
            file_hash = line.strip()  # Remove any whitespace
            if file_hash:  # Ensure the hash is not empty
                url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
                print(f"{Fore.BLUE}Checking hash: {file_hash}")
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
                else:  # Handling errors
                    print(f"{Fore.YELLOW}Unexpected error for hash {file_hash}: {response.status_code} - {response.text}")

    if results["safe"]:
        print(f"\n{Fore.GREEN}Safe files:")
        for safe_hash, internal_name in results["safe"]:
            print(f"{Fore.GREEN}Hash: {safe_hash} - Internal Name: {internal_name} - [VT](https://www.virustotal.com/gui/file/{safe_hash})  ")
        
    if results["malicious"]:
        print(f"\n{Fore.RED}Malicious files:")
        for malicious_hash, internal_name in results["malicious"]:
            print(f"{Fore.RED}Hash: {malicious_hash} - Internal Name: {internal_name} - [VT](https://www.virustotal.com/gui/file/{malicious_hash})  ")
        
    if results["unknown"]:
        print(f"\n{Fore.YELLOW}Unknown files:")
        for unknown_hash, internal_name in results["unknown"]:
            print(f"{Fore.YELLOW}Hash: {unknown_hash} - Internal Name: {internal_name} - [VT](https://www.virustotal.com/gui/file/{unknown_hash})  ")
    
    print(f"\n{Fore.GREEN}VirusTotal analysis completed!  ")
    print(f"{Fore.BLUE}Writing data into file {output_filename}")
    write_to_file(output_filename, results, is_url_check=False)

def url_checker(file_path, output_filename):
    headers = {'x-apikey': VIRUSTOTAL_API_KEY}
    results = {"malicious": [], "safe": [], "unknown": []}
    
    with open(file_path, 'r') as file:
        for line in file:
            url = line.strip()  # Remove any whitespace
            if url:  # Ensure the URL is not empty
                byte_url = url.encode('utf-8')
                id_url = base64.urlsafe_b64encode(byte_url).decode('utf-8').rstrip("=")
                api_url = f"https://www.virustotal.com/api/v3/urls/{id_url}"
                print(f"{Fore.BLUE}Checking URL: {url}")
                response = requests.get(api_url, headers=headers)
                if response.status_code == 200:
                    result = response.json()
                    attributes = result.get('data', {}).get('attributes', {})
                    internal_name = attributes.get('names', [None])[0] if attributes.get('names') else 'N/A'
                    
                    if attributes.get('last_analysis_stats', {}).get('malicious', 0) > 0:
                        results["malicious"].append((url, internal_name))
                    else:
                        results["safe"].append((url, internal_name))
                elif response.status_code == 404:
                    results["unknown"].append((url, 'N/A'))
                else:  # Handling errors
                    print(f"{Fore.YELLOW}Unexpected error for URL {url}: {response.status_code} - {response.text}")

    if results["safe"]:
        print(f"\n{Fore.GREEN}Safe URLs:")
        for safe_url, internal_name in results["safe"]:
            print(f"{Fore.GREEN}URL: {safe_url} - Virus Total URL: [VT](https://www.virustotal.com/gui/url/{safe_url}) - [Browserling](https://browserling.com/browse/win10/chrome127/{safe_url})  ")
            
        
    if results["malicious"]:
        print(f"\n{Fore.RED}Malicious URLs:")
        for malicious_url, internal_name in results["malicious"]:
            print(f"{Fore.RED}URL: {malicious_url} - Virus Total URL: [VT](https://www.virustotal.com/gui/url/{malicious_url}) - [Browserling](https://browserling.com/browse/win10/chrome127/{malicious_url})  ")
        
    if results["unknown"]:
        print(f"\n{Fore.YELLOW}Unknown URLs:")
        for unknown_url, internal_name in results["unknown"]:
            print(f"{Fore.YELLOW}URL: {unknown_url} - Virus Total URL: [VT](https://www.virustotal.com/gui/url/{unknown_url}) - [Browserling](https://browserling.com/browse/win10/chrome127/{unknown_url})  ")
    
    print(f"\n{Fore.GREEN}VirusTotal analysis completed!")
    print(f"{Fore.BLUE}Writing data into file {output_filename}")
    write_to_file(output_filename, results, is_url_check=True)

def main(file_path, output_filename):
    if args.m and not args.u:
        hash_checker(file_path, output_filename)
    elif args.u and not args.m:
        url_checker(file_path, output_filename)
    elif args.m and args.u:
        print(f"{Fore.YELLOW}Both -m and -u options are selected. Only one can be used at a time.")
    else:
        print(f"{Fore.YELLOW}No valid option selected. Use -m for hash checking or -u for URL checking.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Welcome to VTChecker. Please provide your API key in a file called api_keys.ini, in the same directory as VTChecker.py (example provided on GitHub)")
    parser.add_argument('file_path', help="Path to the file containing the hashes or URLs to be analyzed")
    parser.add_argument('-u', action="store_true", help="To check URLs")
    parser.add_argument('-m', action="store_true", help="To check hashes")
    args = parser.parse_args()
    
    output_filename = "VTCheck_output.md"
    file_path = args.file_path 
    print(f"""
{Fore.GREEN}
Welcome to VTChecker! 
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

I hope you'll enjoy this little script!
Twitter: @_f4ku
Github: f4kuw
    """)

    main(file_path, output_filename)
