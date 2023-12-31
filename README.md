# Repute
## A tool that provides contextual information on IP addresses.

Repute is a tool that provides contextual information on IP addresses from VirusTotal, GreyNoise, and The Tor Project to assist in security investigations and/or automation.

## What information does it provide?
#### VirusTotal:
* Vendor Dispositions (Do security vendors find this IP malicious or suspicious?)
* Communicating Files (MD5 hashes of files that communicate with this IP and their vendor dispositions)
* Domain Resolutions (Domains that the IP resolves to)

#### GreyNoise
* Classification (malicious, benign, etc.)
* Noise (Is this IP scanning the internet or attempting exploits?)
* RIOT (Is this a known vendor IP?)
* Last Seen Date

#### The Tor Project
* Tor Exit Node Check (Is this IP an active Tor exit node?)

## Dependencies
* Python
    * Default libraries
        * os
        * requests
        * sys
        * json
        * urllib.request
        * ipaddress
    * Non-default libraries
        * python-dotenv (To store API keys)
* VirusTotal API Key
    * Limited to 500 lookups per day with free API ([API Documentation](https://support.virustotal.com/hc/en-us/articles/115002100149-API))
* GreyNoise API Key
    * Limited to 50 lookups per day with free API ([API Documentation](https://docs.greynoise.io/reference/get_v3-community-ip))
    
## Setup
 If dotenv isn't installed, install it
 

    pip install python-dotenv

 Clone repository

    sudo git clone https://github.com/judelanning/repute

cd into directory and run setup.py

    cd repute/
    sudo python3 setup.py

Enter API keys

    Enter VirusTotal API key:
    Enter GreyNoise API key:

## Usage
Run the script followed by IP address

    python3 repute.py #.#.#.#

Here is an example running the script to check 154.41.229.11, an IP currently being used to host a phishing website:

    python3 repute.py 179.48.251.188

The results:

![Screenshot 2023-07-09 035833](https://github.com/judelanning/repute/assets/122243110/b311bc72-952a-4fd4-8ccd-3c3037960336)

Here is another example running the script to check 209.141.57.178, an IP currently serving as a Tor exit node:

    python3 repute.py 209.141.57.178

The results:

![Screenshot 2023-07-09 040459](https://github.com/judelanning/repute/assets/122243110/881e0b02-1456-48a1-8292-a1c9df84ebbf)

Here is one more example running the script to check 185.241.208.236, another Tor node that GreyNoise has flagged as malicious for attempting to exploit log4j:

    python3 repute.py 185.241.208.236

The results:

![Screenshot 2023-07-09 040944](https://github.com/judelanning/repute/assets/122243110/5d2b62ea-5a8d-40c8-8304-fdb20cdc2b84)
