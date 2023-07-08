from dotenv import load_dotenv
import os
import requests
import sys
import json

#Loads API Keys
load_dotenv("api-keys.env")

def virus_total_ip_check(ip):
    virus_total_api_key = os.getenv("virus_total_api_key")

    if virus_total_api_key == None:
        print("No Virus Total API Key Configured - Skipping Check")
        pass
    else:
        headers = {
            "accept": "application/json",
            "x-apikey": virus_total_api_key
        }

        url = "https://www.virustotal.com/api/v3/ip_addresses/" + ip
        response = requests.get(url, headers=headers)
        parse = json.loads(response.text)
        
        malicious = parse['data']['attributes']['last_analysis_stats']['malicious']
        suspicious = parse['data']['attributes']['last_analysis_stats']['suspicious']
        harmless = parse['data']['attributes']['last_analysis_stats']['harmless']
        undetected = parse['data']['attributes']['last_analysis_stats']['undetected']

        print("\033[1m" + "VirusTotal Report" + "\033[0m")

        print('\033[94m' + "Vendor Dispositions:" + '\033[0m')
        print("Malicious: " + '\033[91m' + str(malicious) + '\033[0m')
        print("Suspicious: " + '\033[93m' + str(suspicious) + '\033[0m')
        print("Harmless/Undetected: " + '\033[92m' + str(harmless + undetected) + '\033[0m')

        url = "https://www.virustotal.com/api/v3/ip_addresses/" + ip + "/communicating_files?limit=10"
        response = requests.get(url, headers=headers)
        parse = json.loads(response.text)

        print('\033[94m' + '\nCommunicating Files' + '\033[0m' + " (" + str(parse["meta"]["count"]) + "):")
        for f in parse["data"]:
            malicious = f["attributes"]["last_analysis_stats"]["malicious"]
            suspicious = f["attributes"]["last_analysis_stats"]["suspicious"]
            harmless = f["attributes"]["last_analysis_stats"]["harmless"]
            undetected = f["attributes"]["last_analysis_stats"]["undetected"]

            if malicious or suspicious > 0:
                print(f["attributes"]["md5"] + " (" + '\033[91m' + (str(malicious + suspicious)) + "\033[0m" + "/" + str(malicious + suspicious + harmless + undetected) +")")
            else:
                print(f["attributes"]["md5"] + " (" + '\033[92m' + (str(malicious + suspicious)) + "\033[0m" + "/" + str(malicious + suspicious + harmless + undetected) +")")

        url = "https://www.virustotal.com/api/v3/ip_addresses/" + ip  + "/resolutions?limit=40"
        response = requests.get(url, headers=headers)
        parse = json.loads(response.text)

        print('\033[94m' + "\nDomain Resolutions" + '\033[0m' + " (" + str(parse["meta"]["count"]) + "):")
        for f in parse['data']:
            
            malicious = f["attributes"]["host_name_last_analysis_stats"]["malicious"]
            suspicious = f["attributes"]["host_name_last_analysis_stats"]["suspicious"]
            harmless = f["attributes"]["host_name_last_analysis_stats"]["harmless"]
            undetected = f["attributes"]["host_name_last_analysis_stats"]["undetected"]
            
            if malicious or suspicious > 0:
                print(f["id"] + " (" + '\033[91m' + str(malicious + suspicious) + "\033[0m" +"/" + str(malicious + suspicious + harmless + undetected) + ")")
            else:
                print(f["id"] + " (" + '\033[92m' + str(malicious + suspicious) + "\033[0m" +"/" + str(malicious + suspicious + harmless + undetected) + ")")

'''
def greynoise_ip_check():
    pass

def abuse_ipdb_ip_check():
    pass

def talos_ip_check():
    #No Talos api, maybe scrape off web query? ex https://talosintelligence.com/reputation_center/lookup?search=4.2.2.1
    pass

def tor_exit_node_check():
    pass
'''




def start_script():
    try:
        ip = sys.argv[1]
    except:
        print("No IP given, try again")
        exit()
    virus_total_ip_check(ip)

print("\n")
start_script()
print('\n')