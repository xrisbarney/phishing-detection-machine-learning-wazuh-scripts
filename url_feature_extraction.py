# -*- coding: utf-8 -*-
"""URL Feature Extraction.ipynb

Automatically generated by Colaboratory.

Original file is located at
    https://colab.research.google.com/drive/1-uUIUJFcyvnNWOxsE1tF1OOGW17QED5t
"""

# importing required packages for this module
import pandas as pd

# loading the phishing URLs data to dataframe


"""So, the data has thousands of phishing URLs. But the problem here is, this data gets updated hourly. Without getting into the risk of data imbalance, I am considering a margin value of 10,000 phishing URLs & 5000 legitimate URLs. 

Thereby, picking up 5000 samples from the above dataframe randomly.
"""

"""As of now we collected 5000 phishing URLs. Now, we need to collect the legitimate URLs.

From the uploaded *Benign_list_big_final.csv* file, the URLs are loaded into a dataframe.
"""

# Loading legitimate files

"""As stated above, 5000 legitimate URLs are randomaly picked from the above dataframe."""

# Collecting 5,000 Legitimate URLs randomly


"""# **3. Feature Extraction:**

In this step, features are extracted from the URLs dataset.

The extracted features are categorized into


1.   Address Bar based Features
2.   Domain based Features
3.   HTML & Javascript based Features

### **3.1. Address Bar Based Features:**

Many features can be extracted that can be consided as address bar base features. Out of them, below mentioned were considered for this project.


*   Domain of URL
*   IP Address in URL
*   "@" Symbol in URL
*   Length of URL
*   Depth of URL
*   Redirection "//" in URL
*   "http/https" in Domain name
*   Using URL Shortening Services “TinyURL”
*   Prefix or Suffix "-" in Domain

Each of these features are explained and the coded below:
"""

# importing required packages for this section
from urllib.parse import urlparse, urlencode
import ipaddress
import re

"""#### **3.1.1. Domain of the URL**
Here, we are just extracting the domain present in the URL. This feature doesn't have much significance in the training. May even be dropped while training the model.
"""


# 1.Domain of the URL (Domain)
def getDomain(_url):
    domain = urlparse(_url).netloc
    if re.match(r"^www.", domain):
        domain = domain.replace("www.", "")
    return domain


"""#### **3.1.2. IP Address in the URL**

Checks for the presence of IP address in the URL. URLs may have IP address instead of domain name. If an IP address is used as an alternative of the domain name in the URL, we can be sure that someone is trying to steal personal information with this URL.

If the domain part of URL has IP address, the value assigned to this feature is 1 (phishing) or else 0 (legitimate).


"""


# 2.Checks for IP address in URL (Have_IP)
# https://docs.python.org/3.10/library/ipaddress.html#convenience-factory-functions
def havingIP(_url):
    try:
        ipaddress.ip_address(_url)
        ip = 1
    except ValueError:
        ip = 0
    return ip


"""#### **3.1.3. "@" Symbol in URL**

Checks for the presence of '@' symbol in the URL. Using “@” symbol in the URL leads the browser to ignore everything preceding the “@” symbol and the real address often follows the “@” symbol. 

If the URL has '@' symbol, the value assigned to this feature is 1 (phishing) or else 0 (legitimate).
"""


# 3.Checks the presence of @ in URL (Have_At)
def haveAtSign(_url):
    if "@" in _url:
        return 1
    return 0


"""#### **3.1.4. Length of URL**

Computes the length of the URL. Phishers can use long URL to hide the doubtful part in the address bar. In this project, if the length of the URL is greater than or equal 54 characters then the URL classified as phishing otherwise legitimate.

If the length of URL >= 54 , the value assigned to this feature is 1 (phishing) or else 0 (legitimate).
"""


# 4.Finding the length of URL and categorizing (URL_Length)
def getLength(_url):
    if len(_url) < 54:
        return 0
    return 1


"""#### **3.1.5. Depth of URL**

Computes the depth of the URL. This feature calculates the number of sub pages in the given url based on the '/'.

The value of feature is a numerical based on the URL.
"""


# 5.Gives number of '/' in URL (URL_Depth)
def getDepth(_url):
    s = urlparse(_url).path.split('/')
    depth = 0
    for j in range(len(s)):
        if len(s[j]) != 0:
            depth = depth + 1
    return depth


"""#### **3.1.6. Redirection "//" in URL**

Checks the presence of "//" in the URL. The existence of “//” within the URL path means that the user will be redirected to another website. The location of the “//” in URL is computed. We find that if the URL starts with “HTTP”, that means the “//” should appear in the sixth position. However, if the URL employs “HTTPS” then the “//” should appear in seventh position.

If the "//" is anywhere in the URL apart from after the protocal, thee value assigned to this feature is 1 (phishing) or else 0 (legitimate).
"""


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


"""#### **3.1.7. "http/https" in Domain name**

Checks for the presence of "http/https" in the domain part of the URL. The phishers may add the “HTTPS” token to the domain part of a URL in order to trick users.

If the URL has "http/https" in the domain part, the value assigned to this feature is 1 (phishing) or else 0 (legitimate).
"""


# 7.Existence of “HTTPS” Token in the Domain Part of the URL (https_Domain)
def httpDomain(_url):
    domain = urlparse(_url).netloc
    if 'https' in domain:
        return 1
    else:
        return 0


"""#### **3.1.8. Using URL Shortening Services “TinyURL”**

URL shortening is a method on the “World Wide Web” in which a URL may be made considerably smaller in length and still lead to the required webpage. This is accomplished by means of an “HTTP Redirect” on a domain name that is short, which links to the webpage that has a long URL. 

If the URL is using Shortening Services, the value assigned to this feature is 1 (phishing) or else 0 (legitimate).
"""

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


"""#### **3.1.9. Prefix or Suffix "-" in Domain**

Checking the presence of '-' in the domain part of URL. The dash symbol is rarely used in legitimate URLs. Phishers tend to add prefixes or suffixes separated by (-) to the domain name so that users feel that they are dealing with a legitimate webpage. 

If the URL has '-' symbol in the domain part of the URL, the value assigned to this feature is 1 (phishing) or else 0 (legitimate).
"""


# 9.Checking for Prefix or Suffix Separated by (-) in the Domain (Prefix/Suffix)
def prefixSuffix(_url):
    if '-' in urlparse(_url).netloc:
        return 1  # phishing
    else:
        return 0  # legitimate


"""### **3.2. Domain Based Features:**

Many features can be extracted that come under this category. Out of them, below mentioned were considered for this project.

*   DNS Record
*   Website Traffic 
*   Age of Domain
*   End Period of Domain

Each of these features are explained and the coded below:
"""

# importing required packages for this section
import re
from bs4 import BeautifulSoup
import whois  # https://github.com/richardpenman/whois
import urllib
import urllib.request
from datetime import datetime

"""#### **3.2.1. DNS Record**

For phishing websites, either the claimed identity is not recognized by the WHOIS database or no records founded for the hostname. 
If the DNS record is empty or not found then, the value assigned to this feature is 1 (phishing) or else 0 (legitimate).
"""

# 11.DNS Record availability (DNS_Record)
# obtained in the featureExtraction function itself

"""#### **3.2.2. Web Traffic**

This feature measures the popularity of the website by determining the number of visitors and the number of pages they visit. However, since phishing websites live for a short period of time, they may not be recognized by the Alexa database (Alexa the Web Information Company., 1996). By reviewing our dataset, we find that in worst scenarios, legitimate websites ranked among the top 100,000. Furthermore, if the domain has no traffic or is not recognized by the Alexa database, it is classified as “Phishing”.

If the rank of the domain < 100000, the vlaue of this feature is 1 (phishing) else 0 (legitimate).
"""


# 12.Web traffic (Web_Traffic)
def web_traffic(_url):
    try:
        # Filling the whitespaces in the URL if any
        _url = urllib.parse.quote(_url)
        rank = BeautifulSoup(urllib.request.urlopen("http://data.alexa.com/data?cli=10&dat=s&url=" + _url).read(),
                             "xml").find("REACH")['RANK']
        rank = int(rank)
    except TypeError:
        return 1
    if rank < 100000:
        return 1
    else:
        return 0


"""#### **3.2.3. Age of Domain**

This feature can be extracted from WHOIS database. Most phishing websites live for a short period of time. The minimum age of the legitimate domain is considered to be 12 months for this project. Age here is nothing but different between creation and expiration time.

If age of domain > 12 months, the vlaue of this feature is 1 (phishing) else 0 (legitimate).
"""


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


"""#### **3.2.4. End Period of Domain**

This feature can be extracted from WHOIS database. For this feature, the remaining domain time is calculated by finding the different between expiration time & current time. The end period considered for the legitimate domain is 6 months or less  for this project. 

If end period of domain > 6 months, the vlaue of this feature is 1 (phishing) else 0 (legitimate).
"""


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


"""## **3.3. HTML and JavaScript based Features**

Many features can be extracted that come under this category. Out of them, below mentioned were considered for this project.

*   IFrame Redirection
*   Status Bar Customization
*   Disabling Right Click
*   Website Forwarding

Each of these features are explained and the coded below:
"""

# importing required packages for this section
import requests

"""### **3.3.1. IFrame Redirection**

IFrame is an HTML tag used to display an additional webpage into one that is currently shown. Phishers can make use of the “iframe” tag and make it invisible i.e. without frame borders. In this regard, phishers make use of the “frameBorder” attribute which causes the browser to render a visual delineation. 

If the iframe is empty or repsonse is not found then, the value assigned to this feature is 1 (phishing) or else 0 (legitimate).
"""


# 15. IFrame Redirection (iFrame)
def iframe(response):
    if response == "":
        return 1
    else:
        if re.findall(r"[<iframe>|<frameBorder>]", response.text):
            return 0
        else:
            return 1


"""### **3.3.2. Status Bar Customization**

Phishers may use JavaScript to show a fake URL in the status bar to users. To extract this feature, we must dig-out the webpage source code, particularly the “onMouseOver” event, and check if it makes any changes on the status bar

If the response is empty or onmouseover is found then, the value assigned to this feature is 1 (phishing) or else 0 (legitimate).
"""


# 16.Checks the effect of mouse over on status bar (Mouse_Over)
def mouseOver(response):
    if response == "":
        return 1
    else:
        if re.findall("<script>.+onmouseover.+</script>", response.text):
            return 1
        else:
            return 0


"""### **3.3.3. Disabling Right Click**

Phishers use JavaScript to disable the right-click function, so that users cannot view and save the webpage source code. This feature is treated exactly as “Using onMouseOver to hide the Link”. Nonetheless, for this feature, we will search for event “event.button==2” in the webpage source code and check if the right click is disabled.

If the response is empty or onmouseover is not found then, the value assigned to this feature is 1 (phishing) or else 0 (legitimate).



"""


# 17.Checks the status of the right click attribute (Right_Click)
def rightClick(response):
    if response == "":
        return 1
    else:
        if re.findall(r"event.button ?== ?2", response.text):
            return 0
        else:
            return 1


"""### **3.3.4. Website Forwarding**
The fine line that distinguishes phishing websites from legitimate ones is how many times a website has been redirected. In our dataset, we find that legitimate websites have been redirected one time max. On the other hand, phishing websites containing this feature have been redirected at least 4 times. 



"""


# 18.Checks the number of forwardings (Web_Forwards)
def forwarding(response):
    if response == "":
        return 1
    else:
        if len(response.history) <= 2:
            return 0
        else:
            return 1


"""## **4. Computing URL Features**

Create a list and a function that calls the other functions and stores all the features of the URL in the list. We will extract the features of each URL and append to this list.
"""


# Function to extract features
def featureExtraction(_url, _label):
    features = [getDomain(_url), havingIP(_url), haveAtSign(_url), getLength(_url), getDepth(_url), redirection(_url),
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
    features.append(_label)

    return features


"""### **4.1. Legitimate URLs:**

Now, feature extraction is done on legitimate URLs.
"""


# Extracting the feautres & storing them in a list

# converting the list to dataframe

# Storing the extracted legitimate URLs fatures to csv file

"""### **4.2. Phishing URLs:**

Now, feature extraction is performed on phishing URLs.
"""


# Extracting the feautres & storing them in a list

# converting the list to dataframe

# Storing the extracted legitimate URLs fatures to csv file

"""## **5. Final Dataset**

In the above section we formed two dataframes of legitimate & phishing URL features. Now, we will combine them to a single dataframe and export the data to csv file for the Machine Learning training done in other notebook. 
"""

# Concatenating the dataframes into one


"""## **6. Conclusion**

With this the objective of this notebook is achieved. We finally extracted 18 features for 10,000 URL which has 5000 phishing & 5000 legitimate URLs.

## **7. References**

* https://archive.ics.uci.edu/ml/datasets/Phishing+Websites
"""
