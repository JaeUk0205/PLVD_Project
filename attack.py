import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import urllib3
import hashlib
import time

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TARGET_HOST = "http://localhost:8080/wavsep/"

START_URLS = [
    TARGET_HOST,
    urljoin(TARGET_HOST, "active/index-active.jsp"),
    urljoin(TARGET_HOST, "active/index-sql.jsp"),
    urljoin(TARGET_HOST, "active/index-xss.jsp")
]

ENABLE_LAYER_A = True  
ENABLE_LAYER_B = True  
ENABLE_LAYER_C = True  

XSS_FILE = "payloads.txt"
SQL_FILE = "sql_payloads.txt"

sess = requests.Session()
sess.headers.update({"User-Agent": "Mozilla/5.0 (PLVD-Crawler/1.0)"})

def load_payloads(filename):
    try:
        with open(filename, "r", encoding="utf-8") as f:
            return [line.strip() for line in f if line.strip() and not line.startswith("[")]
    except FileNotFoundError:
        return ["<script>alert(1)</script>", "\" OR \"1\"=\"1"]

def get_dom_fingerprint(soup):
    tags = "".join([tag.name for tag in soup.find_all(True)])
    actions = "".join([form.attrs.get("action", "") for form in soup.find_all("form")])
    inputs = "".join([tag.attrs.get("name", "") for tag in soup.find_all(["input", "textarea", "select"]) if tag.attrs.get("name")])
    fingerprint = tags + actions + inputs
    return hashlib.md5(fingerprint.encode()).hexdigest()

visited_urls = set()
visited_doms = set()
queue = START_URLS.copy()
found_vulns = set()

start_time = time.time()
vuln_count = 0
sqli_count = 0 
xss_count = 0  
request_count = 0 

print(f"[*] PLVD 실험 시작 | 타겟: {TARGET_HOST}")
print(f"[*] 초기 시드 주소 {len(START_URLS)}개 장전 완료.")

try:
    while queue:
        current_url = queue.pop(0)
        
        if current_url in visited_urls: continue
        visited_urls.add(current_url)

        try:
            if not ENABLE_LAYER_A: break 
            
            res = sess.get(current_url, timeout=3)
            request_count += 1
            
            if res.status_code == 404: continue
            
            soup = BeautifulSoup(res.text, "html.parser")
            print(f"[탐색] {current_url} (큐 대기: {len(queue)})")

            is_duplicate = False

            if ENABLE_LAYER_B:
                dom_hash = get_dom_fingerprint(soup)
                if dom_hash in visited_doms:
                    is_duplicate = True
                else:
                    visited_doms.add(dom_hash)

            # 3번 지적 반영: 중복 템플릿이면 링크 추출도 생략하여 무한 루프 차단
            if is_duplicate:
                continue

            for a_tag in soup.find_all("a", href=True):
                full_link = urljoin(current_url, a_tag.get("href", ""))
                
                if full_link.startswith(TARGET_HOST):
                    if full_link not in visited_urls and full_link not in queue:
                        priority_keywords = ["?", ".jsp", "active", "SQL", "XSS"]
                        if ENABLE_LAYER_B and any(k in full_link for k in priority_keywords):
                            queue.insert(0, full_link)
                        else:
                            queue.append(full_link)

            if ENABLE_LAYER_C and not is_duplicate:
                forms = soup.find_all("form")
                for form in forms:
                    action = urljoin(current_url, form.attrs.get("action", ""))
                    method = form.attrs.get("method", "get").lower()
                    
                    base_data = {tag.attrs.get("name"): tag.attrs.get("value", "") 
                                 for tag in form.find_all(["input", "textarea", "select"]) 
                                 if tag.attrs.get("name")}
                    
                    targets = [tag.attrs.get("name") for tag in form.find_all(["input", "textarea"]) 
                               if tag.attrs.get("name") and tag.attrs.get("type") not in ["submit", "button", "hidden"]]

                    if not targets: continue

                    # 1, 4번 지적 반영: 정상 폼 요청 한 번 보내서 기준점 측정
                    try:
                        if method == "post":
                            base_req = sess.post(action, data=base_data, timeout=5)
                        else:
                            base_req = sess.get(action, params=base_data, timeout=5)
                        request_count += 1
                        t_avg = base_req.elapsed.total_seconds()
                    except Exception:
                        t_avg = 0.5

                    for input_name in targets:
                        # SQL 에러 유발용 특수기호 동적 생성 삽입 (에러 방지용)
                        sq = chr(39)
                        payloads = load_payloads(SQL_FILE) + load_payloads(XSS_FILE)
                        if sq not in payloads: payloads.insert(0, sq)
                        
                        for code in payloads:
                            attack_data = base_data.copy()
                            attack_data[input_name] = code
                            
                            is_vuln = False
                            vuln_type = ""
                            
                            try:
                                if method == "post":
                                    req = sess.post(action, data=attack_data, timeout=t_avg + 4.0)
                                else:
                                    req = sess.get(action, params=attack_data, timeout=t_avg + 4.0)
                                request_count += 1
                                
                                resp_lower = req.text.lower()
                                
                                sql_errors = [
                                    "sql syntax", "java.sql.sqlexception", 
                                    "com.mysql.jdbc", "valid mysql result", 
                                    "ora-", "sqlserverexception", "mysql_fetch"
                                ]
                                
                                # 4번 지적 반영: 500 상태 코드 검사는 유지
                                if any(err in resp_lower for err in sql_errors) or req.status_code == 500:
                                    is_vuln = True
                                    vuln_type = "SQLi (Error)"
                                
                                # 2번 지적 반영: WAVSEP 화면 특성을 고려하여 단순 대조로 원복
                                elif code in req.text:
                                    is_vuln = True
                                    vuln_type = "XSS"
                                
                                # 1번 지적 반영: 지연 시간 측정은 유지
                                elif req.elapsed.total_seconds() >= (t_avg + 3.0):
                                    is_vuln = True
                                    vuln_type = "SQLi (Time-based)"

                            except requests.exceptions.Timeout:
                                is_vuln = True
                                vuln_type = "SQLi (Timeout)"
                                request_count += 1
                            
                            except Exception:
                                pass 

                            if is_vuln:
                                print(f"      >>> [★탐지 성공!] {input_name} (Type: {vuln_type} / Payload: {code[:15]}...)")
                                
                                vuln_category = "SQLi" if "SQLi" in vuln_type else "XSS"
                                vuln_signature = f"{current_url}_{input_name}_{vuln_category}"
                                
                                if vuln_signature not in found_vulns:
                                    found_vulns.add(vuln_signature)
                                    vuln_count += 1
                                    
                                    if vuln_category == "SQLi":
                                        sqli_count += 1
                                    elif vuln_category == "XSS":
                                        xss_count += 1

        except Exception:
            continue

except KeyboardInterrupt:
    print("\n[!] 사용자 중단")

duration = time.time() - start_time
print("\n" + "="*45)
print(f" [PLVD 스캔 현황]")
print(f" 1. 총 소요 시간 : {duration:.2f}초")
print(f" 2. 총 HTTP 요청 : {request_count}회")
print(f" 3. 발견 취약점 : 총 {vuln_count}개")
print(f"    - SQL Injection : {sqli_count}개")
print(f"    - XSS           : {xss_count}개")
print("="*45)