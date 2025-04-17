import requests
from urllib.parse import urlparse
import time

# Professional scanner configuration
HEADERS = {
    'User-Agent': 'SecureScanPro/1.0 (+https://example.com)',
    'Accept': 'text/html,application/xhtml+xml',
    'Accept-Language': 'en-US,en;q=0.5',
}

def validate_url(url):
    """Validate URL format and safety"""
    try:
        result = urlparse(url)
        return all([result.scheme in ['http', 'https'], result.netloc])
    except:
        return False

def scan_xss(url):
    """Advanced XSS scanning with multiple payloads"""
    if not validate_url(url):
        return False, "❌ Invalid URL format"
    
    payloads = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "\"><script>alert('XSS')</script>",
        "javascript:alert('XSS')",
        "<svg/onload=alert('XSS')>"
    ]
    
    results = []
    vulnerable = False
    
    for payload in payloads:
        try:
            # Test in URL parameter
            test_url = f"{url}?q={payload}"
            response = requests.get(test_url, headers=HEADERS, timeout=10, allow_redirects=False)
            
            if payload in response.text:
                vulnerable = True
                results.append(f"⚠ XSS vulnerability detected with payload: {payload[:30]}...")
            
            time.sleep(0.5)  # Rate limiting
            
        except Exception as e:
            results.append(f"⚠ Error testing XSS payload: {str(e)}")
            continue
    
    if not vulnerable:
        return False, "✅ No reflected XSS vulnerabilities detected"
    else:
        return True, "\n".join(results)

def scan_sql_injection(url):
    """Improved SQL injection scanning"""
    if not validate_url(url):
        return False, "❌ Invalid URL format"
    
    payloads = [
        "' OR '1'='1",
        "' OR 1=1--",
        "'; DROP TABLE users--",
        "' UNION SELECT null,username,password FROM users--",
        "' OR SLEEP(5)--"
    ]
    
    results = []
    vulnerable = False
    
    for payload in payloads:
        try:
            test_url = f"{url}?id={payload}"
            start_time = time.time()
            response = requests.get(test_url, headers=HEADERS, timeout=15, allow_redirects=False)
            response_time = time.time() - start_time
            
            # Check for error messages
            error_indicators = [
                'sql', 'syntax', 'mysql', 'ora-', 'error in your sql',
                'unclosed quotation mark', 'quoted string not properly terminated'
            ]
            
            # Check for time-based vulnerabilities
            if response_time > 5:
                vulnerable = True
                results.append(f"⚠ Potential time-based SQLi with payload: {payload[:20]}... (Response time: {response_time:.2f}s)")
            
            # Check for error messages
            if any(indicator in response.text.lower() for indicator in error_indicators):
                vulnerable = True
                results.append(f"⚠ Error-based SQLi detected with payload: {payload[:20]}...")
            
            time.sleep(1)  # Rate limiting
            
        except Exception as e:
            results.append(f"⚠ Error testing SQLi payload: {str(e)}")
            continue
    
    if not vulnerable:
        return False, "✅ No obvious SQL injection vulnerabilities detected"
    else:
        return True, "\n".join(results)
