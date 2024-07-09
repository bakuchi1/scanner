import requests,re
headers = {
    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3',
}

def get_subdomain(domain):
    s = requests.session()
    s.keep_alive = False
    try:
        result = requests.get('http://site.ip138.com/{}/domain.htm'.format(domain), headers=headers)
        sub = re.compile(r'target="_blank">(.*?)</a></p>').findall(result.text)
        return sub
    except requests.exceptions.RequestException as e:
        print(f'something wrong with the interface:{e}')
        return []

