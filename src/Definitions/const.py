

CVE_TEST = {
    # Log4shell
    # The vulnerability exists due to improper validation of log messages containing JNDI references. It allows an attacker to trigger a network request to a malicious server (SSRF), which then serves a malicious Java class that is downloaded and executed by the application (Code Injection/Untrusted Deserialization)    "CVE-2021-44228": ["CodeInjection", "UntrustedDeserialization"],
    "CVE-2021-44228": ["CodeInjection", "UntrustedDeserialization", "SSRF", "InputValidation"],
    # EternalBlue
    # This critical vulnerability is a heap-based buffer overflow within the Windows SMBv1 protocol. It is caused by improper validation of the size and number of parameters in incoming packets, allowing unauthenticated remote attackers to bypass access controls and execute arbitrary code with kernel-level privileges.
    "CVE-2017-0144": ["BufferOverflow", "InputValidation", "AccessControl"],
    # Heartbleed
    # This vulnerability is a critical buffer over-read in OpenSSL's Heartbeat extension. Due to improper input validation of the payload length field, the server reads memory beyond the intended buffer, leading to the exposure of sensitive information such as private keys, passwords, and session tokens.
    "CVE-2014-0160": ["OutOfBoundsRead", "InfoLeak", "InputValidation"],
    # Shellshock
    # This vulnerability occurs because GNU Bash incorrectly parses environment variables containing function definitions followed by trailing commands. By appending malicious code after a function signature, an attacker can achieve OS Command Injection. The flaw stems from a fundamental failure to properly validate and bound the data within environment variables during the shell's initialization process.
    "CVE-2014-6271": ["CommandInjection", "InputValidation"],
    # Follina
    # This vulnerability in the Microsoft Support Diagnostic Tool (MSDT) allows remote code execution when the utility is invoked via the ms-msdt protocol handler. By crafting malicious parameters within the URI, an attacker can trigger OS Command Injection (specifically PowerShell) because the tool fails to properly validate and sanitize the input arguments passed from calling applications like Microsoft Word.
    "CVE-2022-30190": ["CommandInjection", "InputValidation"],
    # Zerologon
    # The vulnerability is a critical cryptographic flaw (fixed zero IV) in the Netlogon protocol that allows an unauthenticated attacker to bypass authentication. While the input (zeros) is syntactically valid, the flaw results in a complete failure of the authentication mechanism, granting domain admin privileges.
    "CVE-2020-1472": ["AccessControl"],
    # Shitrix
    # This vulnerability chains a Directory Traversal flaw with a Code Injection issue. Unauthenticated attackers can use special path characters ('/../') to bypass access restrictions and reach internal Perl scripts. These scripts then improperly handle user input, allowing the injection of malicious Perl code which is executed by the server's Template Toolkit engine.
    "CVE-2019-19781": ["PathTraversal", "CodeInjection", "InputValidation"],
    # FortiOS SSL VPN Path Traversal
    # This vulnerability is a path traversal flaw in the FortiOS SSL VPN web portal due to improper input validation of URL parameters. An unauthenticated attacker can use specially crafted HTTP requests to bypass directory restrictions and read arbitrary system files. This leads to a critical information leak, notably exposing cleartext credentials from session files, which results in a complete failure of access control.
    "CVE-2018-13379": ["PathTraversal", "InfoLeak", "InputValidation", "AccessControl"],
    # Apache Struts Jakarta Multipart RCE
    # This vulnerability is caused by the improper handling of specially crafted Content-Type HTTP headers in the Jakarta Multipart parser. When an error occurs during file upload, the framework evaluates user-supplied data as OGNL expressions. This leads to arbitrary Code Injection as the malicious expressions are executed by the OGNL interpreter, stemming from a fundamental failure in Input Validation.
    "CVE-2017-5638": ["CodeInjection", "InputValidation"],
    # CurveBall
    # This vulnerability exists in the Windows CryptoAPI (crypt32.dll) due to improper validation of Elliptic Curve Cryptography (ECC) certificate parameters. An attacker can supply a crafted certificate with modified curve properties to spoof a trusted root CA, effectively bypassing authentication and integrity checks (Access Control) for code signing and HTTPS connections.
    "CVE-2020-0601": ["AccessControl", "InputValidation"],

    # color-name npm Supply Chain Attack
    # This CVE identifies a supply chain attack where the 'color-name' npm package was compromised via an account takeover (phishing). The attacker published a malicious version (2.0.1) containing an obfuscated payload that targets cryptocurrency transactions in browser environments. Since the provided labels describe specific technical software vulnerabilities (CWEs) and do not cover malicious code insertion or supply chain compromises, "NONE" is the most appropriate choice.
    "CVE-2025-59145": ["CodeInjection", "XSS"], 
    # FortiWeb Path Traversal
    # This critical vulnerability is a relative path traversal flaw in the Fortinet FortiWeb GUI and API. By sending crafted HTTP requests with traversal sequences, an unauthenticated attacker can bypass authentication (Access Control) to reach internal system binaries and execute administrative commands (Command Injection). The issue stems from improper validation of path-related input.
    "CVE-2025-64446": ["PathTraversal", "AccessControl", "CommandInjection", "InputValidation"],
    # ProxyShell (Privilege Escalation component)
    # This vulnerability is part of the ProxyShell chain and resides in the Microsoft Exchange PowerShell backend. It occurs because the service deserializes untrusted data from the X-Rps-CAT parameter to create access tokens. By providing a crafted token, an attacker can achieve Elevation of Privilege (Access Control) and impersonate administrative users, stemming from a fundamental failure to properly validate and secure the token restoration process.
    "CVE-2021-34523": ["UntrustedDeserialization", "AccessControl", "InputValidation"],
    # ProxyLogon (UM RCE component)
    # This vulnerability is an insecure deserialization flaw in the Microsoft Exchange Unified Messaging service. It occurs when untrusted user-supplied data is processed by the Base64Deserialize method, allowing an attacker to achieve Remote Code Execution (Code Injection). By exploiting this flaw, an attacker can escalate privileges to SYSTEM level, representing a significant failure in both Input Validation and Access Control.
    "CVE-2021-26857": ["UntrustedDeserialization", "CodeInjection", "AccessControl", "InputValidation"],
    # MobileIron RCE
    # This critical vulnerability is a Java deserialization flaw in the Hessian-based web services of MobileIron Core. An unauthenticated remote attacker can supply malicious serialized objects to achieve Remote Code Execution (Code Injection). The attack often involves bypassing initial security filters (Access Control) due to improper Input Validation of crafted requests, allowing the attacker to reach and exploit the vulnerable deserialization endpoint.
    "CVE-2020-15505": ["UntrustedDeserialization", "CodeInjection", "AccessControl", "InputValidation"],
    
    # Ivanti Connect Secure RCE
    # This vulnerability is a critical stack-based buffer overflow in the web component of Ivanti gateways. It occurs due to improper input validation when handling 'clientCapabilities' data, where the software fails to enforce buffer limits during a memory copy operation. This allows an unauthenticated remote attacker to overwrite stack memory, bypass access controls, and achieve remote code execution (RCE).
    "CVE-2025-0282": ["BufferOverflow", "InputValidation", "AccessControl"],
    # Trimble Cityworks
    # Trimble Cityworks versions prior to 15.8.9 and Cityworks with office companion versions prior to 23.10 are vulnerable to a deserialization vulnerability.
    "CVE-2025-0994": ["UntrustedDeserialization"],
    # IngressNightmare
    # This critical vulnerability allows unauthenticated attackers with pod network access to inject malicious NGINX directives via crafted AdmissionReview requests to the ingress-nginx Admission Webhook. This leads to Remote Code Execution (Code Injection) and the logical exposure of cluster-wide Secrets (InfoLeak). The flaw stems from improper validation of admission requests, enabling a complete bypass of standard Kubernetes RBAC and authorization boundaries (Access Control).
    "CVE-2025-1974": ["CodeInjection", "InfoLeak", "AccessControl", "InputValidation"],
    # Double Kill
    # This vulnerability is a critical Use-After-Free flaw in the Microsoft VBScript engine. It occurs when the engine improperly handles objects in memory during the execution of the Class_Terminate event, allowing an attacker to re-reference and manipulate a freed object. This memory corruption allows for remote code execution (RCE) and stems from the engine's failure to properly validate the state and lifecycle of script-defined objects.
    "CVE-2018-8174": ["UseAfterFree", "InputValidation"],
    # Java Verifier Field Access
    # This vulnerability is a type confusion flaw in the Java HotSpot VM bytecode verifier. Due to improper input validation during the optimization of field access instructions, a malicious Java applet can bypass the JRE sandbox (Access Control). This sandbox escape allows the attacker to execute arbitrary Java code and system commands (Code Injection) with the privileges of the local user.
    "CVE-2012-1723": ["CodeInjection", "AccessControl", "InputValidation"],
}
