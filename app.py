from flask import Flask, request, jsonify, render_template
import requests
import base64
import time

app = Flask(__name__)
API_KEY = "c4342b817d7194c6adb02f4fdd4601d092b24dd77188c978173205770717466c" # من https://www.virustotal.com

def check_url(url):
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    headers = {"x-apikey": API_KEY}

    response = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers)

    if response.status_code == 200:
        data = response.json()
        stats = data['data']['attributes']['last_analysis_stats']

        malicious = stats['malicious']
        suspicious = stats['suspicious']
        total = sum(stats.values())

        if malicious > 0:
            return "danger", f"⚠️ خطر! {malicious} موقع قالوا ان الرابط ده خبيث من اصل {total}"
        elif suspicious > 0:
            return "warning", f"⚠️ مشبوه! {suspicious} موقع شاكين في الرابط ده"
        else:
            return "safe", f"✅ آمن! محدش بلغ عن الرابط ده. تم فحصه بواسطة {total} شركة امن"
    else:
        return "error", "حصل خطأ اثناء الفحص. جرب تاني"

def check_file(file):
    headers = {"x-apikey": API_KEY}

    files = {"file": (file.filename, file)}
    response = requests.post("https://www.virustotal.com/api/v3/files", headers=headers, files=files)

    if response.status_code == 200:
        analysis_id = response.json()['data']['id']
        time.sleep(5) # استنى التحليل يخلص

        result = requests.get(f"https://www.virustotal.com/api/v3/analyses/{analysis_id}", headers=headers)
        stats = result.json()['data']['attributes']['stats']

        malicious = stats['malicious']
        total = sum(stats.values())

        if malicious > 0:
            return "danger", f"☠️ خطر! {malicious} انتي فايرس قالوا ان الملف ده فيروس من اصل {total}"
        else:
            return "safe", f"✅ نضيف! محدش لقى فيروسات. تم فحصه بواسطة {total} شركة"
    else:
        return "error", "فشل رفع الملف"

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    url = request.json.get('url')
    if not url:
        return jsonify({"status": "error", "message": "مفيش رابط"}), 400

    status, message = check_url(url)
    return jsonify({"status": status, "message": message})

@app.route('/scan-file', methods=['POST'])
def scan_file():
    if 'file' not in request.files:
        return jsonify({"status": "error", "message": "مفيش ملف"}), 400
    file = request.files['file']
    status, message = check_file(file)
    return jsonify({"status": status, "message": message})

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8080))
    app.run(host='0.0.0.0', port=port)
