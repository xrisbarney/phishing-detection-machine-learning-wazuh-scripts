#!/usr/bin/python3
# Copyright (C) 2015-2022, Wazuh Inc.
  
import json
import sys
import time
import os
from socket import socket, AF_UNIX, SOCK_DGRAM
import re


from urllib.parse import urlparse, urlencode
import ipaddress
# import re
from bs4 import BeautifulSoup
import whois  # https://github.com/richardpenman/whois
import urllib
import urllib.request
from datetime import datetime
import requests

import numpy as np
import joblib
from sklearn.model_selection import train_test_split
from sklearn import svm
from sklearn import preprocessing
  
try:
    import requests
    from requests.auth import HTTPBasicAuth
except Exception as e:
    print("No module 'requests' found. Install: pip install requests")
    sys.exit(1)
  
# Global vars
  
debug_enabled = True
pwd = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
json_alert = {}
now = time.strftime("%a %b %d %H:%M:%S %Z %Y")
  
# Set paths
log_file = '{0}/logs/integrations.log'.format(pwd)
socket_addr = '{0}/queue/sockets/queue'.format(pwd)
  
def main(args):
    debug("# Starting")
  
    # Read args
    alert_file_location = args[1]
  
    debug("# File location")
    debug(alert_file_location)
  
    # Load alert. Parse JSON object.
    with open(alert_file_location) as alert_file:
        json_alert = json.load(alert_file)
    debug("# Processing alert")
    debug(json_alert)
  
    # Request AbuseIPDB info
    msg = request_phishtank_info(json_alert)
  
    # If positive match, send event to Wazuh Manager
    if msg:
        send_event(msg, json_alert["agent"])
  
def debug(msg):
    if debug_enabled:
        msg = "{0}: {1}\n".format(now, msg)
  
        print(msg)
  
        f = open(log_file,"a")
        f.write(msg)
        f.close()

#feature extraction and ML start

# 1.Domain of the URL (Domain)
def getDomain(_url):
    # print("getting domain")
    domain = urlparse(_url).netloc
    if re.match(r"^www.", domain):
        domain = domain.replace("www.", "")
    return domain


# 2.Checks for IP address in URL (Have_IP)
# https://docs.python.org/3.10/library/ipaddress.html#convenience-factory-functions
def havingIP(_url):
    # try:
    #     ipaddress.ip_address(_url)
    #     ip = 1
    # except ValueError:
    #     ip = 0
    ip = 0
    return ip


# 3.Checks the presence of @ in URL (Have_At)
def haveAtSign(_url):
    if "@" in _url:
        return 1
    return 0


# 4.Finding the length of URL and categorizing (URL_Length)
def getLength(_url):
    if len(_url) < 54:
        return 0
    return 1


# 5.Gives number of '/' in URL (URL_Depth)
def getDepth(_url):
    s = urlparse(_url).path.split('/')
    depth = 0
    for j in range(len(s)):
        if len(s[j]) != 0:
            depth = depth + 1
    return depth


# 6.Checking for redirection '//' in the url (Redirection)
def redirection(_url):
    pos = _url.rfind('//')
    if pos > 6:
        if pos > 7:
            return 1
        else:
            return 0
    else:
        return 0


# 7.Existence of “HTTPS” Token in the Domain Part of the URL (https_Domain)
def httpDomain(_url):
    domain = urlparse(_url).netloc
    if 'https' in domain:
        return 1
    else:
        return 0

# listing shortening services
shortening_services = r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|" \
                      r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|" \
                      r"short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|" \
                      r"doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|db\.tt|" \
                      r"qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|q\.gs|is\.gd|" \
                      r"po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|x\.co|" \
                      r"prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|" \
                      r"tr\.im|link\.zip\.net"


# 8. Checking for Shortening Services in URL (Tiny_URL)
def tinyURL(_url):
    match = re.search(shortening_services, _url)
    if match:
        return 1
    else:
        return 0

# 9.Checking for Prefix or Suffix Separated by (-) in the Domain (Prefix/Suffix)
def prefixSuffix(_url):
    if '-' in urlparse(_url).netloc:
        return 1  # phishing
    else:
        return 0  # legitimate

# 11.DNS Record availability (DNS_Record)
# obtained in the featureExtraction function itself

# 13.Survival time of domain: The difference between termination time and creation time (Domain_Age)
def domainAge(domain_name):
    creation_date = domain_name.creation_date
    expiration_date = domain_name.expiration_date
    if isinstance(creation_date, str) or isinstance(expiration_date, str):
        try:
            creation_date = datetime.strptime(creation_date, '%Y-%m-%d')
            expiration_date = datetime.strptime(expiration_date, "%Y-%m-%d")
        except ValueError:
            return 1
    if (expiration_date is None) or (creation_date is None):
        return 1
    elif (type(expiration_date) is list) or (type(creation_date) is list):
        return 1
    else:
        ageofdomain = abs((expiration_date - creation_date).days)
        if (ageofdomain / 30) < 6:
            age = 1
        else:
            age = 0
    return age


# 14.End time of domain: The difference between termination time and current time (Domain_End)
def domainEnd(domain_name):
    expiration_date = domain_name.expiration_date
    if isinstance(expiration_date, str):
        try:
            expiration_date = datetime.strptime(expiration_date, "%Y-%m-%d")
        except ValueError:
            return 1
    if expiration_date is None:
        return 1
    elif type(expiration_date) is list:
        return 1
    else:
        today = datetime.now()
        end = abs((expiration_date - today).days)
        if (end / 30) < 6:
            end = 0
        else:
            end = 1
    return end

# importing required packages for this section

# 15. IFrame Redirection (iFrame)
def iframe(response):
    if response == "":
        return 1
    else:
        if re.findall(r"[<iframe>|<frameBorder>]", response.text):
            return 0
        else:
            return 1


# 16.Checks the effect of mouse over on status bar (Mouse_Over)
def mouseOver(response):
    if response == "":
        return 1
    else:
        if re.findall("<script>.+onmouseover.+</script>", response.text):
            return 1
        else:
            return 0



# 17.Checks the status of the right click attribute (Right_Click)
def rightClick(response):
    if response == "":
        return 1
    else:
        if re.findall(r"event.button ?== ?2", response.text):
            return 0
        else:
            return 1


# 18.Checks the number of forwardings (Web_Forwards)
def forwarding(response):
    if response == "":
        return 1
    else:
        if len(response.history) <= 2:
            return 0
        else:
            return 1



# Function to extract features
def featureExtraction(_url):
    features = [ havingIP(_url), haveAtSign(_url), getLength(_url), getDepth(_url), redirection(_url),
                httpDomain(_url), tinyURL(_url), prefixSuffix(_url)]
    # Address bar based features (10)

    # Domain based features (4)
    dns = 0
    try:
        domain_name = whois.whois(urlparse(_url).netloc)
        features.append(dns)
        features.append(domainAge(domain_name))
        features.append(domainEnd(domain_name))
    except whois.parser.PywhoisError:
        dns = 1
        features.append(dns)
        features.extend((1, 1))

    # features.append(web_traffic(url))

    # HTML & Javascript based features (4)
    try:
        response = requests.get(_url)
    except requests.exceptions.RequestException:
        response = ""
    features.append(iframe(response))
    features.append(mouseOver(response))
    features.append(rightClick(response))
    features.append(forwarding(response))
    # features.append(_label)
    print(features)
    model = joblib.load('/var/ossec/integrations/model.joblib')
    # features are gotten the getfeatures function
    # var_ = np.asarray(features)
    # var_ = var_.reshape(1, -1)
    # var_ = preprocessing.StandardScaler().fit_transform(var_)
    # output = model.predict(var_)

    var_ = np.asarray(features)
    var_ = var_.reshape(1, -1)
    scaler = joblib.load('/var/ossec/integrations/scaler.joblib')
    var_ = scaler.transform(var_)
    output = model.predict(var_)
    # print(output)
    # print(np.round(output, 2)*100)
    debug(output)
    output = np.round(output, 2)*100
    debug(abs(output[0]))
    return abs(output[0])


#feature extraction and ML end

def collect(data):
  phishtank_reference = data['phish_id']
  phishtank_detail_url = data['phish_detail_page']
  phishtank_verified = data['verified']
  phishtank_valid = data['valid']
  return phishtank_reference, phishtank_detail_url, phishtank_verified, phishtank_valid
  
def in_database(data, url):
  result = data['in_database']
  debug(result)
  if result == True:
    return True
  return False
  
def query_api(url):
  # params = {'format': 'json', 'app_key': phish_tank_key}
  # response = requests.post('http://checkurl.phishtank.com/checkurl/', params)
#   phish_tank_key = ""
  endpoint = "https://checkurl.phishtank.com/checkurl/"
  response = requests.post(endpoint, data={"url": url, "format": "json",})
  json_response = response.json()
  if json_response['results']['in_database'] == True:
      data = json_response['results']
      debug(data)
      return data
  else:
      alert_output = {}
      alert_output["phishtank"] = {}
      alert_output["phishtank"]["found"] = 1
      alert_output["integration"] = "custom-phishing"
      alert_output["phishtank"]["gotten_from"] = "ml"
      alert_output["phishtank"]["phish_percentage"] = featureExtraction(url)
      alert_output["phishtank"]["source"]["alert_id"] = json_alert["id"]
      alert_output["phishtank"]["source"]["rule"] = json_alert["rule"]["id"]
      alert_output["phishtank"]["source"]["description"] = json_alert["rule"]["description"]
      alert_output["phishtank"]["source"]["url"] = url
    #   json_response = response.json()
    #   alert_output["phishtank"]["description"] = "This URL was not found in the phishtank database."
      send_event(alert_output)
      exit(0)
  
def request_phishtank_info(alert):
    alert_output = {}
    # If there is no url present in the alert. Exit.
    if alert["data"]["win"]["eventdata"]["commandLine"] == None:
      return(0)
    extracted_url = re.search("(?P<url>https?://[^\s]+)", alert["data"]["win"]["eventdata"]["commandLine"]).group("url")
    # debug(extracted_url)
    # Request info using AbuseIPDB API
    data = query_api(extracted_url)

    # Create alert
    alert_output["phishtank"] = {}
    alert_output["integration"] = "custom-phishtank"
    alert_output["phishtank"]["found"] = 0
    alert_output["phishtank"]["source"] = {}
    alert_output["phishtank"]["source"]["alert_id"] = alert["id"]
    alert_output["phishtank"]["source"]["rule"] = alert["rule"]["id"]
    alert_output["phishtank"]["source"]["description"] = alert["rule"]["description"]
    alert_output["phishtank"]["source"]["url"] = extracted_url
    url = extracted_url
    # Check if phishtank has any info about the srcip
    if in_database(data, url):
      alert_output["phishtank"]["found"] = 1
  
    # Info about the IP found in AbuseIPDB
    if alert_output["phishtank"]["found"] == 1:
      # array('url' => 'https://www.example.org/',
      #                    'in_database' => true,
      #                    'phish_id' => 11728,
      #                    'phish_detail_page' => 'http://www.phishtank.com/phish_detail.php?phish_id=11728',
      #                    'verified' => 'y',
      #                    'verified_at' => '2006-10-01T02:32:23+00:00',
      #                    'valid' => 'y'
      #                   )
        phishtank_reference, phishtank_detail_url, phishtank_verified, phishtank_valid = collect(data)
  
        # Populate JSON Output object with AbuseIPDB request
        alert_output["phishtank"]["gotten_from"] = "phishtank"
        alert_output["phishtank"]["phishtank_reference"] = phishtank_reference
        alert_output["phishtank"]["phishtank_detail_url"] = phishtank_detail_url
        alert_output["phishtank"]["phishtank_verified"] = phishtank_verified
        alert_output["phishtank"]["phishtank_valid"] = phishtank_valid
       
  
    debug(alert_output)
  
    return(alert_output)
  
def send_event(msg, agent = None):
    if not agent or agent["id"] == "000":
        string = '1:phishtank:{0}'.format(json.dumps(msg))
    else:
        string = '1:[{0}] ({1}) {2}->phishtank:{3}'.format(agent["id"], agent["name"], agent["ip"] if "ip" in agent else "any", json.dumps(msg))
  
    debug(string)
    sock = socket(AF_UNIX, SOCK_DGRAM)
    sock.connect(socket_addr)
    sock.send(string.encode())
    sock.close()
  
if __name__ == "__main__":
    try:
        # Read arguments
        bad_arguments = False
        if len(sys.argv) >= 4:
            msg = '{0} {1} {2} {3} {4}'.format(now, sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4] if len(sys.argv) > 4 else '')
            debug_enabled = (len(sys.argv) > 4 and sys.argv[4] == 'debug')
        else:
            msg = '{0} Wrong arguments'.format(now)
            bad_arguments = True
  
        # Logging the call
        f = open(log_file, 'a')
        f.write(msg +'\n')
        f.close()
  
        if bad_arguments:
            debug("# Exiting: Bad arguments.")
            sys.exit(1)
  
        # Main function
        main(sys.argv)
  
    except Exception as e:
        debug(str(e))
        raise