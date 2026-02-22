import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import urllib3
import hashlib
import time

# 경고 메시지 무시
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ==========================================
# [실험 환경 설정] - OWASP ZAP 대조 실험용
# ==========================================
# 1. 타겟 베이스 (스캔 범위를 이 호스트로 제한)
TARGET_HOST = "http://localhost:8080/wavsep/"

# 2. 시작점 설정 (Seed URLs)
START_URLS = [
    TARGET_HOST, # 루트
    urljoin(TARGET_HOST, "active/index-active.jsp"), # 액티브 공격 리스트
    urljoin(TARGET_HOST, "active/index-sql.jsp"),    # SQLi 리스트
    urljoin(TARGET_HOST, "active/index-xss.jsp")     # XSS 리스트
]

# 3. 실험 레이어 활성화
ENABLE_LAYER_A = True  # Acquisition (크롤링)
ENABLE_LAYER_B = True  # Pre-processing (우선순위 & 중복제거)
ENABLE_LAYER_C = True  # Detection (공격수행)

# 4. 페이로드 파일
XSS_FILE = "payloads.txt"
SQL_FILE = "sql_payloads.txt"
# ==========================================

# 세션 및 헤더 설정
sess = requests.Session()
sess.headers.update({'User-Agent': 'Mozilla/5.0 (PLVD-Crawler/1.0)'})

def load_payloads(filename):
    try:
        with open(filename, "r", encoding="utf-8") as f:
            return [line.strip() for line in f if line.strip() and not line.startswith("[")]
    except FileNotFoundError:
        # 파일 없을 시 테스트용 기본값
        return ["<script>alert(1)</script>", "' OR '1'='1"]

def get_dom_fingerprint(soup):
    tags = "".join([tag.name for tag in soup.find_all(True)])
    return hashlib.md5(tags.encode()).hexdigest()

# 전역 변수 초기화
visited_urls = set()
visited_doms = set()
queue = START_URLS.copy()

start_time = time.time()
vuln_count = 0
sqli_count = 0  # [추가] SQLi 개수 카운터
xss_count = 0   # [추가] XSS 개수 카운터
request_count = 0 

print(f"[*] PLVD 실험 시작 | 타겟: {TARGET_HOST}")
print(f"[*] 초기 시드 주소 {len(START_URLS)}개 장전 완료.")

try:
    while queue:
        current_url = queue.pop(0)
        
        if current_url in visited_urls: continue
        visited_urls.add(current_url)

        try:
            # [Layer A] 페이지 수집
            if not ENABLE_LAYER_A: break 
            
            res = sess.get(current_url, timeout=3)
            request_count += 1
            
            if res.status_code == 404: continue
            
            soup = BeautifulSoup(res.text, "html.parser")
            print(f"[탐색] {current_url} (큐 대기: {len(queue)})")

            is_duplicate = False

            # [Layer B] 필터링 및 우선순위 알고리즘
            if ENABLE_LAYER_B:
                dom_hash = get_dom_fingerprint(soup)
                if dom_hash in visited_doms:
                    is_duplicate = True
                else:
                    visited_doms.add(dom_hash)

            # 링크 추출 및 우선순위 스케줄링
            for a_tag in soup.find_all("a", href=True):
                full_link = urljoin(current_url, a_tag["href"])
                
                if full_link.startswith(TARGET_HOST):
                    if full_link not in visited_urls and full_link not in queue:
                        
                        # === Layer B 핵심: 우선순위 판단 ===
                        priority_keywords = ["?", ".jsp", "active", "SQL", "XSS"]
                        if ENABLE_LAYER_B and any(k in full_link for k in priority_keywords):
                            queue.insert(0, full_link)
                        else:
                            queue.append(full_link)

            # [Layer C] 취약점 공격 수행
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

                    for input_name in targets:
                        # SQL과 XSS 페이로드를 합쳐서 로드
                        payloads = load_payloads(SQL_FILE) + load_payloads(XSS_FILE)
                        for code in payloads:
                            attack_data = base_data.copy()
                            attack_data[input_name] = code
                            
                            try:
                                if method == "post":
                                    req = sess.post(action, data=attack_data, timeout=3)
                                else:
                                    req = sess.get(action, params=attack_data, timeout=3)
                                request_count += 1
                                
                                is_vuln = False
                                vuln_type = "" # 취약점 유형 저장 변수

                                # 1. SQL 에러 기반 탐지
                                if "sql" in req.text.lower() and "syntax" in req.text.lower():
                                    is_vuln = True
                                    vuln_type = "SQLi"
                                
                                # 2. XSS 반사 기반 탐지
                                elif code in req.text:
                                    is_vuln = True
                                    vuln_type = "XSS"
                                
                                # 3. 시간 기반 탐지 (3초 이상) -> Blind SQLi로 간주
                                elif req.elapsed.total_seconds() >= 3:
                                    is_vuln = True
                                    vuln_type = "SQLi"

                                if is_vuln:
                                    print(f"      >>> [★취약점 발견!] {input_name} (Type: {vuln_type} / Payload: {code[:15]}...)")
                                    vuln_count += 1
                                    
                                    # [추가] 유형별 카운트 증가
                                    if vuln_type == "SQLi":
                                        sqli_count += 1
                                    elif vuln_type == "XSS":
                                        xss_count += 1
                                        
                                    break # 해당 필드는 취약점이 확인되었으므로 다음 필드로 넘어감

                            except Exception:
                                pass

        except Exception as e:
            continue

except KeyboardInterrupt:
    print("\n[!] 사용자 중단")

# 결과 출력
duration = time.time() - start_time
print("\n" + "="*45)
print(f" [PLVD 실험 결과 리포트]")
print(f" 1. 총 소요 시간 : {duration:.2f}초")
print(f" 2. 총 HTTP 요청 : {request_count}회")
print(f" 3. 발견 취약점 : 총 {vuln_count}개")
print(f"    - SQL Injection : {sqli_count}개")
print(f"    - XSS           : {xss_count}개")
print("="*45)