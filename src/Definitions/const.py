CVE_TEST = {
    # Log4Shell
    # Unauthenticated RCE via JNDI lookup injection in Apache Log4j2
    # The vulnerability allows untrusted input to be evaluated and executed as Java code via JNDI lookups.
    "CVE-2021-44228":["InputValidation", "InjectionFlaws", "CodeInjection", "UntrustedDeserialization"],

    # EternalBlue
    # Remote code execution via buffer overflow in Windows SMBv1 protocol
    # The flaw involves improper bounds checking in the kernel pool leading to a buffer overflow.
    "CVE-2017-0144": ["Memory", "MemoryCorruption", "BufferOverflow"],

    # Heartbleed
    # Information exposure due to a buffer over-read in OpenSSL TLS heartbeat extension
    # Missing bounds checks allow reading out-of-bounds memory, leaking sensitive data.
    "CVE-2014-0160": ["Memory", "MemoryDisclosure", "OutOfBoundsRead"],

    # Shellshock
    # RCE via command injection in GNU Bash environment variables
    # Unvalidated input passed via environment variables is executed as system shell commands.
    "CVE-2014-6271":["InputValidation", "InjectionFlaws", "CommandInjection"],

    # Follina
    # RCE via command injection in Windows MSDT protocol handler
    # Unvalidated input in a crafted document is used to construct and execute system shell commands.
    "CVE-2022-30190":["InputValidation", "InjectionFlaws", "CommandInjection"],

    # Zerologon
    # Privilege escalation via flawed cryptographic authentication in Netlogon
    # The protocol utilizes a flawed AES-CFB8 encryption implementation, representing weak cryptography.
    "CVE-2020-1472": ['Misconfiguration', 'WeakCryptography', 'AccessControl', 'BrokenAuthentication'],

    # Citrix ADC Path Traversal
    # Unauthenticated RCE via directory traversal in Citrix ADC and NetScaler Gateway
    # Manipulation of file paths allows accessing and writing files outside the intended scope.
    "CVE-2019-19781": ["InputValidation", "InjectionFlaws", "PathTraversal"],

    # FortiOS SSL VPN Path Traversal
    # Unauthenticated arbitrary file read via path traversal in Fortinet FortiOS
    # Attackers manipulate file paths to access internal files outside the intended web root.
    "CVE-2018-13379": ["InputValidation", "InjectionFlaws", "PathTraversal"],

    # Apache Struts 2 OGNL Injection
    # RCE via unvalidated OGNL expressions evaluated in the Content-Type header
    # Untrusted input is executed as code by the application's OGNL interpreter.
    "CVE-2017-5638":["InputValidation", "InjectionFlaws", "CodeInjection"],

    # CurveBall
    # Certificate spoofing due to flawed Elliptic Curve Cryptography validation in Windows CryptoAPI
    # The system relies on flawed cryptographic signature verification, fitting weak cryptography.
    "CVE-2020-0601": ["Misconfiguration", "WeakCryptography"],

    # CamoLeak / npm color-name Malware
    # Embedded malicious code published via a compromised npm package account
    # A supply chain attack adding malicious code does not match any specific technical vulnerability categories in the tree.
    "CVE-2025-59145": ["NONE"],

    # FortiWeb Path Traversal and Authentication Bypass
    # Unauthenticated admin access via relative path traversal and forged authentication headers
    # Attackers bypass authentication mechanisms and manipulate file paths to reach an internal CGI script.
    "CVE-2025-64446":["InputValidation", "InjectionFlaws", "PathTraversal", "AccessControl", "BrokenAuthentication"],

    # ProxyShell Exchange Privilege Escalation
    # Elevation of privilege in Microsoft Exchange Server PowerShell backend
    # Flaws in authorization allow attackers to bypass checks and impersonate privileged users.
    "CVE-2021-34523": ["AccessControl", "ImproperAuthorization"],

    # ProxyLogon Exchange Deserialization
    # RCE via insecure deserialization in Microsoft Exchange Server Unified Messaging service
    # Untrusted serialized data is unsafely restored, allowing arbitrary object instantiation and code execution.
    "CVE-2021-26857": ["InputValidation", "InjectionFlaws", "UntrustedDeserialization"],

    # MobileIron Core & Connector Deserialization RCE
    # RCE via unsafe deserialization of Hessian format in Tomcat web service
    # Unsafe restoration of objects from untrusted Hessian data streams leads to code execution.
    "CVE-2020-15505": ["InputValidation", "InjectionFlaws", "UntrustedDeserialization"],

    # Ivanti Connect Secure Buffer Overflow
    # Unauthenticated RCE via a stack-based buffer overflow in IFT protocol handling
    # Writing data past allocated stack buffer boundaries allows memory corruption and code execution.
    "CVE-2025-0282": ["Memory", "MemoryCorruption", "BufferOverflow"],

    # Trimble Cityworks Deserialization
    # Authenticated RCE via insecure deserialization in Trimble Cityworks
    # The application unsafely deserializes untrusted data, allowing arbitrary code execution.
    "CVE-2025-0994": ["InputValidation", "InjectionFlaws", "UntrustedDeserialization"],

    # IngressNightmare (Kubernetes Ingress-NGINX)
    # Unauthenticated RCE via injection of malicious NGINX configuration directives
    # Unvalidated input is used to inject configuration directives that are executed as code by NGINX.
    "CVE-2025-1974":["InputValidation", "InjectionFlaws", "CodeInjection"],

    # VBScript Engine Use After Free
    # RCE due to improper handling of objects in memory within the VBScript engine
    # Accessing explicitly freed memory allows an attacker to alter the execution flow.
    "CVE-2018-8174":["Memory", "MemoryCorruption", "UseAfterFree"],

    # Java Applet Type Confusion
    # RCE via type confusion in the HotSpot JVM
    # Type confusion is a low-level flaw allowing memory corruption to bypass the Java sandbox.
    "CVE-2012-1723":["Memory", "MemoryCorruption"]
}