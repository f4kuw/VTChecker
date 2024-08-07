# VTChecker

This script aims to check multiple hashes or URLs with Virus Total API.

-----------------------------------------------------------------------------

## Usage

### Virus Total API: 

To use this tool, you'll need a VirusTotal API key. You can register to VirusTotal in order to get one, it's free. Check [here](https://docs.virustotal.com/docs/api-scripts-and-client-libraries).  

You need to create a file called api_keys.ini, in order to store your api key locally, in the same directory as VTChecker.py. Please see the example provided on the repo.


### Checking hashes:   

This will check on Virus total if it's malicious or not, and will give you the link of the search.   

``python3 VTChecker.py -m hashes.txt``   

### Checking URLs: 

This will check on Virus total if the URL is considered as malicious or not, and will give you a link to VT and Browserling in order to check by yourself safely.   
 
``python3 VTChecker.py -u urls.txt``


### Output:  

This script generate an output .md file that allow you to c/c it wherever you want.  


