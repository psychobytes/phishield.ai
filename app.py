from flask import Flask, request, flash, redirect, url_for, render_template
import requests

app = Flask(__name__)
app.secret_key = 'secret-key'

@app.route('/', methods=['POST', 'GET'])
def index():
    return render_template('index.html')

@app.route('/input', methods = ['POST'])
def input():
    url = request.form['url-input']

    try:
        response = requests.get(url, allow_redirects=True, timeout=5)
        if response.status_code not in range(200, 400):
            flash('URL cant be reached.', 'Error')
            return redirect(url_for('index'))
        else:
            def analyze_url(target):
                endpoint = "https://www.virustotal.com/api/v3/urls"
                headers = {
                    "accept": "application/json",
                    "content-type": "application/x-www-form-urlencoded",
                    "X-Apikey": "[YOUR VIRUSTOTAL API]"
                }
                data = {
                    "url": f"{target}"
                }
                response = requests.post(endpoint, headers=headers, data=data)
                response = response.json()
                analysis_id = response["data"]["id"]

                while True:
                    endpoint = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
                    headers = {
                        "x-apikey": "[YOUR VIRUSTOTAL API]"
                    }
                    response = requests.get(endpoint, headers=headers)
                    response.raise_for_status()
                    analysis_status = response.json()["data"]["attributes"]["status"]
                    if analysis_status == "completed":
                        break
                return response.json()
            
            target = url
            response_vt = analyze_url(target)
            stats = response_vt['data']['attributes']['stats']
            mal_count = response_vt['data']['attributes']['stats']['malicious']
            link_vt = response_vt['data']['links']['item']

            response = requests.post(
                "http://127.0.0.1:8000/predict",
                headers={"accept": "application/json", "Content-Type": "application/json"},
                json={"url": url}
            )

            results = response.json()
            res = results['prediction']
            link = results['url']
            res_ai = results

            if res == 'Phishing':
                sumres = 'Phishing'
            elif res == 'Safe' and mal_count > 0:
                sumres = 'Phishing'
            else:
                sumres = 'Safe'
            return render_template('result.html', result=res, result_ai=res_ai, url=link, stats_vt = stats, url_vt = link_vt, malicious = mal_count, sumresults = sumres)
    
    except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
        flash('URL cant be reached.', 'Error')
        return redirect(url_for('index'))

@app.route('/results', methods = ['GET'])
def result():
    return render_template('result.html')

@app.route('/about', methods=['GET'])
def about():
    return render_template('about.html')

if __name__ == '__main__':
    app.run()
