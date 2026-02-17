import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import urllib3
import hashlib
import time
import sys

# 경고 메시지 무시
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ==========================================
# [실험 환경 설정] - ZAP과 동등한 조건
# ==========================================
# 1. 타겟 베이스 (스캔 범위를 벗어나지 않도록 제한)
TARGET_HOST = "http://localhost:8080/wavsep/"

# 2. 시작점 (ZAP처럼 루트에서 시작 -> 크롤링 성능 증명)
START_URL = TARGET_HOST

# 3. 실험 모드 (논문 데이터 측정용)
ENABLE_LAYER_A = True  # 필수 (페이지 수집)
ENABLE_LAYER_B = True  # 선택 (우선순위 큐 & 중복 제거) -> 핵심 알고리즘
ENABLE_LAYER_C = True  # 선택 (공격 수행)

# 4. 페이로드 파일 설정
XSS_FILE = "payloads.txt"
SQL_FILE = "sql_payloads.txt"
# ==========================================

# 세션 설정 (속도 최적화)
sess = requests.Session()
# WAVSEP은 쿠키가 없어도 되지만, 필요시 아래에 추가
sess.headers.update({'User-Agent': 'PLVD-Bot/1.0 (Research)'})

# 파일 로드 함수
def load_payloads(filename):
    try:
        with open(filename, "r", encoding="utf-8") as f:
            return [line.strip() for line in f if line.strip() and not line.startswith("[")]
    except FileNotFoundError:
        print(f"[!] 경고: {filename} 없음. 기본 페이로드 사용.")
        return ["<script>alert(1)</script>", "' OR '1'='1"]

# 페이로드 준비
all_payloads = []
if ENABLE_LAYER_C:
    print("[*] 페이로드 로딩 중...")
    all_payloads.extend(load_payloads(XSS_FILE))
    all_payloads.extend(load_payloads(SQL_FILE))
    print(f"[*] 총 {len(all_payloads)}개의 공격 패턴 장전 완료.")

# DOM 해시 함수 (중복 페이지 제거용)
def get_dom_fingerprint(soup):
    # 태그 구조만 추출하여 해시 생성 (내용이 달라도 구조가 같으면 중복 처리)
    tags = "".join([tag.name for tag in soup.find_all(True)])
    return hashlib.md5(tags.encode()).hexdigest()

# ==========================================
# 메인 로직 시작
# ==========================================
visited_urls = set()
visited_doms = set()
queue = [START_URL]

start_time = time.time()
vuln_count = 0
request_count = 0 

print("\n" + "="*40)
print(f"[*] PLVD 실험 시작")
print(f"[*] 타겟: {START_URL}")
print(f"[*] 모드: Layer A(크롤링)={ENABLE_LAYER_A}, Layer B(우선순위)={ENABLE_LAYER_B}")
print("="*40 + "\n")

try:
    while queue:
        # 큐에서 URL 하나 꺼내기
        current_url = queue.pop(0)
        
        if current_url in visited_urls: continue
        visited_urls.add(current_url)

        try:
            # --------------------------------------
            # [Layer A] 페이지 수집 (Crawling)
            # --------------------------------------
            if not ENABLE_LAYER_A: break 
            
            # 타임아웃 3초로 설정하여 속도 향상
            res = sess.get(current_url, timeout=3)
            request_count += 1
            
            # 응답 코드가 404면 건너뜀
            if res.status_code == 404:
                # print(f"[Skip] 404 Not Found: {current_url}")
                continue

            soup = BeautifulSoup(res.text, "html.parser")
            print(f"[탐색] {current_url} (큐 남은 수: {len(queue)})")

            # --------------------------------------
            # [Layer B] 필터링 및 우선순위 (Algorithm)
            # --------------------------------------
            if ENABLE_LAYER_B:
                # 1. DOM 구조 기반 중복 제거
                dom_hash = get_dom_fingerprint(soup)
                if dom_hash in visited_doms:
                    # 구조가 완전히 똑같은 페이지는 공격 건너뜀 (시간 절약)
                    # 단, 링크 수집은 해야 하므로 continue는 하지 않음
                    pass 
                else:
                    visited_doms.add(dom_hash)

            # 2. 링크 추출 및 우선순위 큐 삽입
            for a_tag in soup.find_all("a", href=True):
                next_link = urljoin(current_url, a_tag["href"])
                
                # [Scope Check] 타겟 호스트를 벗어나지 않게 제어
                if next_link.startswith(TARGET_HOST):
                    # 로그아웃 등 제외
                    if "logout" in next_link.lower(): continue
                    
                    if next_link not in visited_urls and next_link not in queue:
                        # === [여기가 핵심 알고리즘] ===
                        # 공격 가능성이 높은 페이지(파라미터, jsp, active 폴더)를
                        # 큐의 맨 앞(index 0)으로 보내 ZAP보다 빨리 찾게 만듦
                        is_high_priority = False
                        if ENABLE_LAYER_B:
                            if "active" in next_link or "SQL" in next_link or "XSS" in next_link:
                                is_high_priority = True
                            if "?" in next_link or ".jsp" in next_link:
                                is_high_priority = True
                        
                        if is_high_priority:
                            queue.insert(0, next_link) # 우선순위 높음!
                        else:
                            queue.append(next_link)    # 일반 페이지

            # --------------------------------------
            # [Layer C] 공격 수행 (Attacking)
            # --------------------------------------
            if ENABLE_LAYER_C:
                forms = soup.find_all("form")
                
                # 입력창이 없으면 공격 스킵
                if not forms: continue

                for form in forms:
                    action = urljoin(current_url, form.attrs.get("action", ""))
                    method = form.attrs.get("method", "get").lower()
                    
                    # 입력 필드 찾기
                    inputs = form.find_all(["input", "textarea"])
                    target_inputs = []
                    base_data = {}

                    for tag in inputs:
                        name = tag.attrs.get("name")
                        if not name: continue
                        
                        # 히든 필드나 버튼은 공격 대상에서 제외하되 데이터는 유지
                        input_type = tag.attrs.get("type", "text")
                        if input_type in ["submit", "button", "hidden", "image"]:
                            base_data[name] = tag.attrs.get("value", "")
                        else:
                            base_data[name] = "" # 공격할 빈 자리
                            target_inputs.append(name)

                    if not target_inputs: continue

                    # 공격 시작
                    for input_name in target_inputs:
                        for payload in all_payloads:
                            attack_data = base_data.copy()
                            attack_data[input_name] = payload
                            
                            try:
                                if method == "post":
                                    req = sess.post(action, data=attack_data, timeout=3)
                                else:
                                    req = sess.get(action, params=attack_data, timeout=3)
                                request_count += 1
                                
                                # 취약점 판별
                                is_vuln = False
                                
                                # 1. SQL Error
                                if "sql" in req.text.lower() and "syntax" in req.text.lower():
                                    is_vuln = True
                                # 2. Reflected XSS
                                elif payload in req.text:
                                    is_vuln = True
                                # 3. Time-based (3초 이상 지연)
                                elif req.elapsed.total_seconds() >= 3:
                                    # print(f"      [Time-based 감지] {req.elapsed.total_seconds()}초")
                                    is_vuln = True
                                
                                if is_vuln:
                                    print(f"      >>> [★취약점 발견!] {input_name} | Payload: {payload[:20]}...")
                                    vuln_count += 1
                                    # 한 입력창에서 하나 찾으면 다음 입력창으로 (중복 방지)
                                    break 

                            except requests.exceptions.Timeout:
                                # 타임아웃은 Time-based Blind SQLi 가능성 있음
                                # print("      [Timeout] 잠재적 취약점")
                                pass
                            except Exception:
                                pass

        except Exception as e:
            print(f"[Error] {e}")
            continue

except KeyboardInterrupt:
    print("\n[!] 사용자 중단")

# ==========================================
# [실험 결과 Report] - 논문에 들어갈 데이터
# ==========================================
duration = time.time() - start_time
print("\n" + "="*40)
print(f" [PLVD 실험 결과 보고서]")
print(f" 1. 총 소요 시간 : {duration:.2f}초")
print(f" 2. 총 HTTP 요청 : {request_count}회")
print(f" 3. 발견된 취약점 : {vuln_count}개")
print("="*40)