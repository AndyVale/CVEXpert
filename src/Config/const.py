
LABELS_DESCRIPTIONS: dict = {
    "PrivEsc": "Privilege Escalation: The attacker elevates their current access level to a higher tier (e.g., user to admin) within the application or OS.",
    "InfoLeak": "Information Disclosure: The system unintentionally reveals sensitive data (PII, credentials, internal paths, or debug info) to unauthorized actors.",
    "AuthBypass": "Authentication Bypass: The attacker gains access to the system without providing valid credentials, circumventing the login mechanism entirely.",
    "AccessControl": "Broken Access Control: The attacker successfully performs actions or accesses data outside their intended permissions (includes IDOR).",
    "DoS": "Denial of Service: The availability of the service is compromised, causing it to crash, freeze, or become unresponsive due to resource exhaustion.",
    "SQLi": "SQL Injection: The attacker interferes with database queries by injecting malicious SQL code, often allowing data theft or modification.",
    "XSS": "Cross-Site Scripting: The attacker injects malicious scripts that execute within the client-side context (browser) of other users.",
    "CSRF": "Cross-Site Request Forgery: The attacker tricks an authenticated user's browser into sending a state-changing request to a vulnerable application without the user's consent.",
    "PathTraversal": "Path Traversal: The attacker manipulates file paths (e.g., using ../) to access files and directories stored outside the intended web root folder.",
    "FileUpload": "Unsafe File Upload: The application allows the upload of files with dangerous extensions (e.g., .php, .exe) that can be executed on the server.",
    "RCE": "Remote Code Execution: The attacker triggers the execution of arbitrary commands or code on the target system from a remote network location.",
    "ConfigError": "Security Misconfiguration: The vulnerability stems from insecure default settings, open cloud buckets, exposed administrative interfaces, or missing security headers.",
    "WeakCrypto": "Cryptographic Weakness: The use of broken algorithms (MD5/SHA1), hardcoded keys, insufficient entropy, or poor certificate validation.",
    "SSRF": "Server-Side Request Forgery: The attacker induces the server to make HTTP requests to internal resources or arbitrary external systems.",
    "CommandInjection": "OS Command Injection: The application passes unsafe user input directly to a system shell (e.g., system(), exec()), executing OS commands.",
    "MemoryCorruption": "Memory Safety Violation: Low-level memory management errors including buffer stack overflows, heap overflows, use-after-free, and double-free vulnerabilities.",
    "LogicBug": "Business Logic Flaw: A design flaw in the application's workflow (e.g., race conditions, price manipulation) rather than a code syntax error.",
    "NetworkExposure": "Unintended Network Exposure: Services, databases, or management ports (e.g., RDP, SSH) are accessible from the public internet without restriction.",
}

CVE_TEST = [
    "CVE-2021-44228", # log4shell -> UnsafeDeserialization, RCE
    "CVE-2017-0144",  # EternalBlue -> MemoryCorruption, RCE
    #  "CVE-2019-14287", # Sudo Security Bypass -> LogicBug, LPE
    #  "CVE-2022-22965", # Spring4Shell -> UnsafeDeserialization, RCE
    #  "CVE-2023-4863",  # libwebp Heap Overflow -> MemoryCorruption, DoS
    # "CVE-2025-59145", # NONE
    "CVE-2025-8110"   # RCE, PrivEsc
]

REF_MAX = 5

CHAT_MODEL = "ministral-3:3b"#"deepseek-r1:1.5b"#
SUMMARIZER_MODEL = "ministral-3:3b"#"qwen3:0.6b"#"ministral-3:3b"