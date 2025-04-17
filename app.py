import streamlit as st
from PIL import Image
from scanner import scan_xss, scan_sql_injection
from admin_finder import find_admin_pages

# Page config (must be first)
st.set_page_config(
    page_title="SecureScan Pro",
    page_icon="🛡️",
    layout="centered"
)

# Load logo
try:
    logo = Image.open('/home/pc/Public/SecureScanner/assets/logo.png')
    col1, col2 = st.columns([1, 4])
    with col1:
        st.image(logo, width=70)
    with col2:
        st.markdown("""
        <h1 style='margin: 0; padding: 0;'>
            SecureScan Pro
        </h1>
        <p style='margin: 0; color: #666;'>
            Professional Web Security Assessment Tool
        </p>
        """, unsafe_allow_html=True)
except:
    st.title("SecureScan Pro")
    st.caption("Professional Web Security Assessment Tool")

# Legal disclaimer
st.warning("""
**LEGAL DISCLAIMER**  
This tool is for EDUCATIONAL PURPOSES ONLY. Use only on websites you own or have explicit permission to scan.
Unauthorized scanning is ILLEGAL and may result in criminal charges.
""")

# Sidebar
with st.sidebar:
    st.title("About")
    st.info("""
    Basic security scanning capabilities.
    For comprehensive assessments, consult a professional.
    """)

# Main scanning interface
url = st.text_input(
    "🔗 Enter target URL (e.g., https://example.com)",
    placeholder="https://"
)

agree = st.checkbox(
    "I confirm I have permission to scan this website"
)

scan_button = st.button("Scan Now", disabled=not agree)

if scan_button:
    if not url.startswith(('http://', 'https://')):
        st.error("❌ Invalid URL - must start with http:// or https://")
    else:
        with st.spinner("🔍 Scanning in progress..."):
            tab1, tab2, tab3 = st.tabs(["XSS Scan", "SQLi Scan", "Admin Pages"])
            
            with tab1:
                xss_found, xss_result = scan_xss(url)
                st.info(xss_result)
            
            with tab2:
                sqli_found, sqli_result = scan_sql_injection(url)
                st.info(sqli_result)
            
            with tab3:
                admin_pages = find_admin_pages(url)
                if admin_pages:
                    st.warning("⚠ Admin pages found:")
                    for page in admin_pages:
                        st.write(f"- {page}")
                else:
                    st.success("✅ No common admin pages detected")

        st.divider()
        if xss_found or sqli_found or admin_pages:
            st.error("## ⚠ Vulnerabilities Found!")
            if xss_found:
                st.error("- XSS vulnerabilities detected")
            if sqli_found:
                st.error("- SQL injection vulnerabilities detected")
            if admin_pages:
                st.error("- Admin interfaces exposed")
        else:
            st.success("## ✅ No obvious vulnerabilities detected")
        
        st.info("Note: Basic scan only. Consider professional testing for full assessment.")
