#Creates api-keys.env and stores API keys in that file.
try:
    #Tries to create api-keys.env.
    f = open("api-keys.env", "x")

    #Asks for VirusTotal API key.
    virus_total_api_key = input("Enter VirusTotal API key: ")

    #Writes VirusTotal API key to api-keys.env
    f.write("virus_total_api_key = " + virus_total_api_key + "\n")

    #Asks for GreyNoise API key.
    greynoise_api_key = input("Enter GreyNoise API key: ")

    #Writes GreyNoise API key to api-keys.env
    f.write("greynoise_api_key = " + greynoise_api_key)
    
#If an error is returned, it is assumed the file is already made and prompts the user to enter API keys manually.
except:
    print(".env file already exists, enter API keys manually")