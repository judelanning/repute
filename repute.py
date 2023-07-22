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
    print(colors.BOLD + "VirusTotal Report" + colors.BLACK)

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

        print(colors.BLUE + "Vendor Dispositions:" + colors.BLACK)
        print("Malicious: " + colors.RED + str(malicious) + colors.BLACK)
        print("Suspicious: " + colors.YELLOW + str(suspicious) + colors.BLACK)
        print("Harmless/Undetected: " + colors.GREEN + str(harmless + undetected) + colors.BLACK)

        url = "https://www.virustotal.com/api/v3/ip_addresses/" + ip + "/communicating_files?limit=50"
        response = requests.get(url, headers=headers)
        parse = json.loads(response.text)

        print(colors.BLUE + '\nCommunicating Files' + colors.BLACK + " (" + str(parse["meta"]["count"]) + "):")
        for f in parse["data"]:
            malicious = f["attributes"]["last_analysis_stats"]["malicious"]
            suspicious = f["attributes"]["last_analysis_stats"]["suspicious"]
            harmless = f["attributes"]["last_analysis_stats"]["harmless"]
            undetected = f["attributes"]["last_analysis_stats"]["undetected"]

            if malicious or suspicious > 0:
                print(f["attributes"]["md5"] + " (" + colors.RED + (str(malicious + suspicious)) + colors.BLACK + "/" + str(malicious + suspicious + harmless + undetected) +")")
            else:
                print(f["attributes"]["md5"] + " (" + colors.GREEN + (str(malicious + suspicious)) + colors.BLACK + "/" + str(malicious + suspicious + harmless + undetected) +")")

        url = "https://www.virustotal.com/api/v3/ip_addresses/" + ip  + "/resolutions?limit=40"
        response = requests.get(url, headers=headers)
        parse = json.loads(response.text)

        print(colors.BLUE + "\nDomain Resolutions" + colors.BLACK + " (" + str(parse["meta"]["count"]) + "):")
        for f in parse['data']:
            
            malicious = f["attributes"]["host_name_last_analysis_stats"]["malicious"]
            suspicious = f["attributes"]["host_name_last_analysis_stats"]["suspicious"]
            harmless = f["attributes"]["host_name_last_analysis_stats"]["harmless"]
            undetected = f["attributes"]["host_name_last_analysis_stats"]["undetected"]
            
            if malicious or suspicious > 0:
                print(f["id"] + " (" + colors.RED + str(malicious + suspicious) + colors.BLACK +"/" + str(malicious + suspicious + harmless + undetected) + ")")
            else:
                print(f["id"] + " (" + colors.GREEN + str(malicious + suspicious) + colors.BLACK +"/" + str(malicious + suspicious + harmless + undetected) + ")")

#Checks GreyNoise for IP classification, noise, RIOT status, and last seen date.
def greynoise_ip_check(ip):
    greynoise_api_key = os.getenv("greynoise_api_key")
    print(colors.BOLD + "\nGreyNoise Report" + colors.BLACK)

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
            print(colors.BLUE + "Classification: " + colors.BLACK + classification)
        except:
            print(colors.BLUE + "Classification:" + colors.BLACK + " None")

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

        print(colors.BLUE + "Noise: " + colors.BLACK + str(noise))
        
        if riot == True:
            print(colors.BLUE + "RIOT: " + colors.BLACK + str(riot) + ", " + name)
        else:
            print(colors.BLUE + "RIOT:" + colors.BLACK + " False")
        
        print(colors.BLUE + "Last Seen: " + colors.BLACK + str(last_seen))

#Gets list of Tor exit node IPs from TorProject and checks if provided IP is in the list.
def tor_exit_node_check(ip):
    print(colors.BOLD + "\nTor Check" + colors.BLACK)
    try:
        with urllib.request.urlopen('https://check.torproject.org/torbulkexitlist') as f:
            ips_string = f.read().decode('utf-8')

            ips_list = list(ips_string.split("\n"))

            if ip in ips_list:
                print(colors.BLUE + "Tor Exit Node:" + colors.BLACK + " True")
            else:
                print(colors.BLUE + "Tor Exit Node:" + colors.BLACK + " False")
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

#Used to change terminal text color.
class colors:
    BLACK = "\033[0m"
    BOLD = "\033[1m"
    BLUE = "\033[94m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    GREEN = "\033[92m"

#Starts script.
start_script()