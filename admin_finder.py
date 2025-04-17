import requests
from urllib.parse import urljoin

COMMON_ADMIN_PATHS = [
    'admin', 'admin/login', 'admin.php', 'administrator', 
    'wp-admin', 'wp-login.php', 'manager', 'login', 
    'controlpanel', 'cpanel', 'admin_area', 'backend',
    'secure', 'admincp', 'moderator', 'webadmin'
]

def find_admin_pages(base_url):
    """Professional admin page finder with better detection"""
    if not base_url.startswith(('http://', 'https://')):
        return []
    
    found_pages = []
    
    for path in COMMON_ADMIN_PATHS:
        try:
            full_url = urljoin(base_url, path)
            response = requests.get(
                full_url,
                headers={'User-Agent': 'SecureScanPro/1.0'},
                timeout=5,
                allow_redirects=False
            )
            
            # Check for login forms or common admin keywords
            page_content = response.text.lower()
            admin_indicators = [
                'login', 'password', 'username', 'admin',
                'control panel', 'dashboard', 'wp-admin'
            ]
            
            if (response.status_code == 200 and 
                any(indicator in page_content for indicator in admin_indicators)):
                found_pages.append(full_url)
            
        except requests.RequestException:
            continue
    
    return found_pages
