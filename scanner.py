from flask import Flask, render_template, request, Response
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
import socket

app = Flask(__name__)

# رؤوس الحماية مع تحديد مستوى خطورة فقدان كل رأس
SECURITY_HEADERS = {
    'Content-Security-Policy': 'حرج',
    'Strict-Transport-Security': 'حرج',
    'X-Frame-Options': 'متوسط',
    'X-Content-Type-Options': 'متوسط',
    'X-XSS-Protection': 'منخفض'
}

scan_history = []

def check_ports(hostname):
    ports_to_check = [80, 443, 21, 22, 3306]
    port_results = {}
    for port in ports_to_check:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.0)
            result = s.connect_ex((hostname, port))
            if result == 0:
                port_results[port] = "مفتوح"
            else:
                port_results[port] = "مغلق"
            s.close()
        except:
            port_results[port] = "مغلق"
    return port_results

def scan_target(url):
    results = {}
    sub_links = []
    server_info = "غير معروف"
    score = 0
    ports = {}
    missing_count = 0
    
    try:
        if not url.startswith('http://') and not url.startswith('https://'):
            target_url = 'https://' + url
        else:
            target_url = url

        parsed_url = urlparse(target_url)
        hostname = parsed_url.netloc

        response = requests.get(target_url, timeout=5)
        headers = response.headers

        server_info = headers.get('Server', headers.get('X-Powered-By', 'مخفي / محمي'))

        found_count = 0
        for header, severity in SECURITY_HEADERS.items():
            if header in headers:
                results[header] = {"status": "موجود", "severity": severity}
                found_count += 1
            else:
                results[header] = {"status": "مفقود", "severity": severity}
                missing_count += 1
        
        score = int((found_count / len(SECURITY_HEADERS)) * 100)

        # فحص الروابط الفرعية مع فحص بروتوكول الأمان لكل رابط
        soup = BeautifulSoup(response.text, 'html.parser')
        for a_tag in soup.find_all('a', href=True):
            href = a_tag['href']
            full_url = urljoin(target_url, href)
            if not any(d['url'] == full_url for d in sub_links):
                is_secure = full_url.startswith('https://')
                sub_links.append({
                    "url": full_url,
                    "secure": is_secure,
                    "protocol": "HTTPS" if is_secure else "HTTP (غير آمن)"
                })
                
        if hostname:
            ports = check_ports(hostname)
                
        if target_url not in scan_history:
            scan_history.insert(0, target_url)
            if len(scan_history) > 5:
                scan_history.pop()
                
    except Exception as e:
        results['Error'] = {"status": f"فشل الاتصال: {str(e)}", "severity": "حرج"}
        server_info = "خطأ في الاتصال"
        
    return results, sub_links, server_info, score, ports, missing_count

@app.route('/', methods=['GET', 'POST'])
def home():
    result = None
    sub_links = []
    server_info = ""
    security_score = 0
    ports = {}
    missing_count = 0
    url = ""
    
    if request.method == 'POST':
        url = request.form.get('url')
        result, sub_links, server_info, security_score, ports, missing_count = scan_target(url)
    
    return render_template(
        'index.html', 
        result=result, 
        sub_links=sub_links, 
        server_info=server_info, 
        security_score=security_score, 
        ports=ports,
        missing_count=missing_count,
        url=url,
        history=scan_history
    )

@app.route('/export')
def export_report():
    url = request.args.get('url')
    if not url:
        return "لا يوجد رابط لتصديره", 400
    
    result, sub_links, server_info, security_score, ports, missing_count = scan_target(url)
    
    report_content = f"=== تقرير منصة الفحص المؤسسي الشامل ===\n"
    report_content += f"الرابط المستهدف: {url}\n"
    report_content += f"نوع السيرفر: {server_info}\n"
    report_content += f"مستوى الأمان الكلي: {security_score}%\n"
    report_content += f"إجمالي الثغرات المفقودة: {missing_count}\n\n"
    report_content += "رؤوس الحماية وتصنيف الخطورة:\n"
    for header, data in result.items():
        report_content += f"- {header}: {data['status']} (خطورة: {data['severity']})\n"
        
    report_content += f"\nحالة المنافذ الحساسة:\n"
    for port, state in ports.items():
        report_content += f"- منفذ {port}: {state}\n"
        
    report_content += f"\nالروابط الفرعية المكتشفة ({len(sub_links)}):\n"
    for link in sub_links:
        report_content += f"- {link['url']} [{link['protocol']}]\n"
        
    return Response(
        report_content,
        mimetype="text/plain",
        headers={"Content-Disposition": "attachment;filename=enterprise_security_report.txt"}
    )

if __name__ == '__main__':
    app.run(debug=True)