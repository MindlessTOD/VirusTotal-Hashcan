import re
import requests
import json
"""Validates user input a valid md5 hash and returns it to def main()"""
def get_md5(input_str):
    output = re.search('[0-9a-fA-F]{32}', input_str.lower())
    if output:
        return output.group(0)


"""Validates user input a valid sha256 hash and returns it to def main()"""
def get_sha256(input_str):
    output = re.search('[0-9a-fA-F]{64}', input_str.lower())
    if output:
        return output.group(0)


def main():
    api = input("Enter your VirusTotal API key.\n"
         "https://www.virustotal.com/gui/my-apikey\n"
          ": ")
    if api == "":
        print('API key is required please try again.')
        return main()
    sample = input('Enter your MD5 or SHA256 Hash:\n '
            'EXAMPLE: \n'
            '32char, a-f0-9 MD5: db349b97c37d22f5ea1d1841e3c89eb4\n'
            '64char, a-f0-9 SHA: 24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c\n'
            ': ')
    """If the user input is exactly 32 or 64 characters,
    Then we send the string to be tested as either a MD5 hash or a SHA256 hash"""
    try:
        if len(sample) == 32:
            print("\nMD5 detected: " + get_md5(sample))
        elif len(sample) == 64:
            print("sha256 detected: " + get_sha256(sample))
        else:
            print("oops...That's not a valid hash please try again...")
            return
    except TypeError:
        print("oops...That's not a valid hash please try again...")
        return

    #Here begins the request appending the sample hash to the end of the API url so get a json report.#
    url = "https://www.virustotal.com/api/v3/files/"+ sample
    headers = {"Accept": "application/json", "x-apikey": api}
    response = requests.get(url, headers=headers)
    """Get the response in JSON format."""
    res = json.loads(response.text)

    if (response.status_code == 200) is True:

        print('Status Code:',str(response.status_code))
        if(res['data']['attributes']['total_votes']['malicious']) >= 5:
                print('Hash matches Malicious Signatures on: '+ str(res['data']['attributes']['total_votes']['malicious']) +' Search Engines.')

        elif(res['data']['attributes']['total_votes']['malicious']) ==0:
            print('Hash does NOT match any known Malicious Signatures on Virus Total')

        elif(res['data']['attributes']['total_votes']['malicious'])in range(1,3):
            print('Hash matches ',str(res['data']['attributes']['total_votes']['malicious']))
     #Status code not = 200, output reason/status_code
    elif response.status_code != 200:
        print('\nStatus Code:',str(response.status_code))
        print(str(res['error']['message']))
main()
