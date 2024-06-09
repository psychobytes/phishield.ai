from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import pickle
import keras

import ipaddress
from urllib.parse import urlparse
import requests
from bs4 import BeautifulSoup
import re
import pandas as pd

app = FastAPI()

with open('MultilayerPerceptron-phishing.pickle.dat', 'rb') as file:
    mlp_model = pickle.load(file)

class URLFeatures(BaseModel):
    ip: int
    url_length: int
    domain_length: int
    special_char: int
    punycode: int
    shortener: int
    url_slash: int
    prefsuffix: int
    subdomain: int
    favicon: int
    nonstandardport: int
    tls: int
    at: int
    abnormalreq: int
    anchor: int
    link: int
    detect_mailto: int
    forwarding: int
    mouse_over: int
    right_click: int
    popup: int

# URL based Features
# IP Address
def have_ip(url):
    try:
        ipaddress.ip_address(url)
        ip = 1
    except:
        ip = 0
    return ip

# URL Length
def url_length(url):
    if len(url) < 54 :
        length = 0
    else:
        length = 1
    return length

# domain length
def domain_length(url):
    domain = urlparse(url).hostname
    if len(domain) >= 25:
        dom = 1
    else:
        dom = 0
    return dom

# special char
def special_char(url):
    domain = urlparse(url).hostname
    normal_pattern = re.compile(r'^[a-zA-Z.]+$')
    if normal_pattern.match(domain):
        return 0
    return 1

# punycode
def punycode(url):
    domain = urlparse(url).hostname
    punycode_pattern = re.compile(r'xn--')
    if punycode_pattern.search(domain):
        return 1
    return 0

# url shortener
def shortener(url):
    shortening_services = r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|" \
                          r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|" \
                          r"short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|" \
                          r"doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|db\.tt|" \
                          r"qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|q\.gs|is\.gd|" \
                          r"po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|" \
                          r"prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|" \
                          r"tr\.im|link\.zip\.net"
    match=re.search(shortening_services,url)
    if match:
        return 1
    else:
        return 0

# Slashes in URL
def url_slash(url):
    s = url.count('/') - 2
    if s > 5 :
        slash = 1
    else :
        slash = 0
    return slash

# Prefix and Suffix
def prefsuffix(url):
    domain = urlparse(url).netloc
    pfsf = domain.count('-')
    if pfsf > 3 :
        prefsuf = 1
    else:
        prefsuf = 0
    return prefsuf

# Subdomain
def subdomain(url):
    domain = urlparse(url).hostname
    subdo = domain.count('.') - 1
    if subdo > 1 :
        sd = 1
    else:
        sd = 0
    return sd

# Favicon *
def favicon(url):
    parsed_url = urlparse(url)
    domain = parsed_url.scheme + '://' + parsed_url.netloc
    
    try:
        response = requests.get(domain + '/favicon.ico', timeout=5)
        if response.status_code == 200:
            icon = 0
        else:
            icon = 1
    except requests.RequestException:
        icon = 1
    return icon

# Non Standard Port Usage
def nonstandardport(url):
    parsed_url = urlparse(url)
    p = parsed_url.port
    if p == None :
        if parsed_url.scheme == 'http' or 'https':
            port = 0
        else:
            port = 1
    elif p == 80 or 8080:
        port = 0
    else:
        port = 1
    return port

# TLS (http or https)
def tls(url):
    parsed_url = urlparse(url)
    tls = parsed_url.scheme
    if tls == 'https':
        http = 0
    else:
        http = 1
    return http

# Special Char '@'
def at(url):
    at_count = url.count('@')
    if at_count > 0:
        at = 1
    else:
        at = 0
    return at

# HTML & JS Based Features
# Abnormal URL Request
def abnormalreq(url, soup):
    main_domain = urlparse(url).netloc
    tags = ['img', 'video', 'audio', 'source']
    attributes = ['src', 'data-src']
    external_assets_found = False
    for tag in tags:
        for attribute in attributes:
            for element in soup.find_all(tag):
                if element.has_attr(attribute):
                    asset_url = element[attribute]
                    asset_domain = urlparse(asset_url).netloc
                    if asset_domain and asset_domain != main_domain:
                        external_assets_found = True
                        break
            if external_assets_found:
                break
        if external_assets_found:
            break
    return 1 if external_assets_found else 0

# URL of Anchor
def anchor(soup):
    for a_tag in soup.find_all('a'):
        href = a_tag.get('href')
        if href:
            # Check if href links to an external domain
            if href.startswith('http://') or href.startswith('https://'):
                return 1
            # Check if href is one of the void types
            elif href in ['#', '#content', '#skip', 'JavaScript:void(0)', 'JavaScript::void(0)']:
                return 1
    return 0

# Link in <script> and <link>
def link(url, soup):
    base_url = '{uri.scheme}://{uri.netloc}'.format(uri=requests.utils.urlparse(url))

    def is_external_url(link_url):
        if link_url.startswith('http://') or link_url.startswith('https://'):
            return base_url not in link_url
        return False

    for script_tag in soup.find_all('script'):
        src = script_tag.get('src')
        if src and is_external_url(src):
            return 1
        
    # Check for external link tags
    for link_tag in soup.find_all('link'):
        href = link_tag.get('href')
        if href and is_external_url(href):
            return 1
    
    return 0

# Info Submit through Email
def detect_mailto(soup):
    mailto_links = soup.find_all('a', href=lambda href: href and 'mailto:' in href)
    return 1 if mailto_links else 0

# Web Forwarding
def forwarding(response):
    num_redirects = len(response.history)
    return 1 if num_redirects >= 4 else 0

# Mouseover
def mouse_over(response):
    if re.findall("<script>.+onmouseover.+</script>", response.text):
        return 1
    else:
        return 0

# Disable right-click
def right_click(response):
    if re.findall(r"event.button ?== ?2", response.text):
        return 1
    else:
        return 0

# Pop Up Window
def popup(soup):
    modal_elements = soup.find_all(class_='modal')
    popup_elements = soup.find_all(class_='popup')
        
    if modal_elements or popup_elements:
        return 1
    else:
        return 0

def extract(url):
    try:
        response = requests.get(url, allow_redirects=True, timeout=5)
        if response.status_code not in range(200, 400):
            pass
        else:
            soup = BeautifulSoup(response.content, 'html.parser')
            feature_functions = {
                'ip': have_ip(url),
                'url_length': url_length(url),
                'domain_length': domain_length(url),
                'special_char': special_char(url),
                'punycode': punycode(url),
                'shortener': shortener(url),
                'url_slash': url_slash(url),
                'prefsuffix': prefsuffix(url),
                'subdomain': subdomain(url),
                'favicon': favicon(url),
                'nonstandardport': nonstandardport(url),
                'tls': tls(url),
                'at': at(url),
                'abnormalreq': abnormalreq(url, soup),
                'anchor': anchor(soup),
                'link': link(url, soup),
                'detect_mailto': detect_mailto(soup),
                'forwarding': forwarding(response),
                'mouse_over': mouse_over(response),
                'right_click': right_click(response),
                'popup': popup(soup)
                }

            features = URLFeatures(**feature_functions)

    except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
        print(f"An error occurred: {e}")

    return features

# Define the API input model
class URLInput(BaseModel):
    url: str

@app.post("/predict")
async def predict_url(data: URLInput):
    url = data.url
    try:
        features = extract(url)
        features_df = pd.DataFrame([features.dict()])
        prediction = mlp_model.predict(features_df)
        result = int(prediction[0])
        return {
            "url": url,
            "features": features.dict(),
            "prediction": "Safe" if result < 0.5 and result <= 1 else "Phishing"
        }
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"An error occurred during prediction: {e}")
