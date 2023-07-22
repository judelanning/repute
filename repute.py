#Used to grab API keys from .env file.
from dotenv import load_dotenv
import os

#Used to make API requests.
import requests

#Used to read IP address from CLI.
import sys

#Used to verify IP address format
import ipaddress

#Used to parse API response.
import json

#Used to get list of Tor exit nodes from torproject.com.
import urllib.request

#Loads API Keys.
load_dotenv("api-keys.env")

#Checks VirusTotal for vendor dispositions, communicating files, and domain resolutions associated with given IP.
def virus_total_ip_check(ip):
    virus_total_api_key = os.getenv("virus_total_api_key")
    print("\033[1m" + "VirusTotal Report" + "\033[0m")

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

        print('\033[94m' + "Vendor Dispositions:" + '\033[0m')
        print("Malicious: " + '\033[91m' + str(malicious) + '\033[0m')
        print("Suspicious: " + '\033[93m' + str(suspicious) + '\033[0m')
        print("Harmless/Undetected: " + '\033[92m' + str(harmless + undetected) + '\033[0m')

        url = "https://www.virustotal.com/api/v3/ip_addresses/" + ip + "/communicating_files?limit=50"
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

#Checks GreyNoise for IP classification, noise, RIOT status, and last seen date.
def greynoise_ip_check(ip):
    greynoise_api_key = os.getenv("greynoise_api_key")
    print("\033[1m" + "\nGreyNoise Report" + "\033[0m")

    if greynoise_api_key == None:
        print("No Greynoise API Key Configured - Skipping Check")
    else:
        headers = {
            "accept": "application/json",
            "key": greynoise_api_key
        }

        url = "https://api.greynoise.io/v3/community/" + ip

        response = requests.get(url, headers=headers)
        parse = json.loads(response.text)

        try:
            classification = parse["classification"]
            print('\033[94m' + "Classification: " + '\033[0m' + classification)
        except:
            print('\033[94m' + "Classification:" + '\033[0m' + " None")

        noise = parse["noise"]
        riot = parse["riot"]

        try:
            name = parse["name"]
        except:
            name = 'Unknown'
        
        try:
            last_seen = parse["last_seen"]
        except:
            last_seen = "Unknown"

        print('\033[94m' + "Noise: " + '\033[0m' + str(noise))
        
        if riot == True:
            print('\033[94m' + "RIOT: " + '\033[0m' + str(riot) + ", " + name)
        else:
            print('\033[94m' + "RIOT:" + '\033[0m' + " False")
        
        print('\033[94m' + "Last Seen: " + '\033[0m' + str(last_seen))

#Gets list of Tor exit node IPs from TorProject and checks if provided IP is in the list.
def tor_exit_node_check(ip):
    print("\033[1m" + "\nTor Check" + "\033[0m")
    try:
        with urllib.request.urlopen('https://check.torproject.org/torbulkexitlist') as f:
            ips_string = f.read().decode('utf-8')

            ips_list = list(ips_string.split("\n"))

            if ip in ips_list:
                print('\033[94m' + "Tor Exit Node:" + '\033[0m' + " True")
            else:
                print('\033[94m' + "Tor Exit Node:" + '\033[0m' + " False")
    except:
        print("Couldn't Reach Tor Exit Node List")

#Grabs IP from CLI and passes it to script functions.
def start_script():
    try:
        ip = sys.argv[1]
    except:
        print("No IP given, try again")
        exit()
    check_ip(ip)
    virus_total_ip_check(ip)
    greynoise_ip_check(ip)
    tor_exit_node_check(ip)

#Checks for proper IP address format.
def check_ip(ip):
    #Checks for proper IPv4/6 Formatting. Will return error if not correct format.
    try:
        ipaddress.ip_address(ip)

    #If an error is returned, the user input is not a valid IP address.
    except:
        print("Not a valid IP address, try again.")
        exit()

    #Checks to see if the IP address is private. If so, the script will exit.
    if ipaddress.ip_address(ip).is_private == True:
        print(ip + " is a private IP address. Please try again with a public IP address.")
        exit()

#Starts script.
start_script()