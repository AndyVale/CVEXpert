LABELS_DESCRIPTIONS = {
    "XSS": "Cross-site Scripting: Malicious scripts are injected into web pages and executed in the victim's browser.",
    "SQLi": "SQL Injection: Malicious SQL queries are injected to manipulate the database.",
    "CSRF": "Cross-Site Request Forgery: Unverified requests are executed on behalf of an authenticated user without their consent.",
    "SSRF": "Server-Side Request Forgery: The server is coerced into making requests to unintended internal or external resources.",
    "PathTraversal": "Path Traversal: Manipulation of file paths (e.g., '../') to access files or directories outside the intended scope.",
    "CommandInjection": "Command Injection: Unvalidated input is used to construct system shell commands. Covers OS Command Injection.",
    "CodeInjection": "Code Injection: Unvalidated input is executed as code by the application's interpreter (e.g., PHP, Python, Java).",
    "UntrustedDeserialization": "Deserialization of Untrusted Data: Unsafe restoration of objects from data streams, leading to RCE or logic manipulation.",
    "BufferOverflow": "Buffer Overflow: Writing data past buffer boundaries on the stack or heap. explicitly covers Out-of-bounds Write.",
    "OutOfBoundsRead": "Out-of-bounds Read: Reading data past allocated memory boundaries. Use this for memory-based information leaks.",
    "UseAfterFree": "Use After Free: Accessing memory after it has been explicitly freed. A specific memory corruption distinct from overflows.",
    "AccessControl": "Broken Access Control: Failure to manage user privileges. Covers Missing Authentication, Authorization Bypass, and Privilege Escalation.",
    "InfoLeak": "Exposure of Sensitive Information: Logical exposure of private data (credentials, PII) via logs or responses. (Distinct from memory-based Out-Of-Bounds Read).",
    "ResourceExhaustion": "Resource Exhaustion: Uncontrolled allocation of resources (memory, CPU, disk) causing Denial of Service (DoS). Covers Null Pointer Dereferences if they cause crashes.",
    "InputValidation": "Improper Input Validation: General failure to validate data correctness. Catch-all for Dangerous File Uploads, Integer Overflows, and Format Strings."
}

ALL_LABELS = list(LABELS_DESCRIPTIONS.keys()) + ["NONE"]

OUTPUT_SCHEMA = {
        "title": "CVEClassification",
        "type": "object",
        "properties": {
            "labels": {
                "type": "array",
                "items": {
                    "type": "string",
                    "enum": ALL_LABELS
                },
                "minItems": 1,
                "uniqueItems": True
            }
        },
        "required": ["labels"],
        "additionalProperties": False
    }

CVE_TEST = {
    # CodeInjection because the vulnerability involves JNDI injection where unvalidated input allows the fetching and execution of remote code/objects. UntrustedDeserialization because the returned object is deserialized.
    "CVE-2021-44228": ["CodeInjection", "UntrustedDeserialization"],
    # BufferOverflow because it is a buffer overflow vulnerability in the SMBv1 server (Srv!SrvOs2FeaListSizeToNt) leading to RCE.
    "CVE-2017-0144": ["BufferOverflow"],
    # OutOfBoundsRead because it is a buffer over-read in the OpenSSL Heartbeat extension allowing attackers to read memory contents.
    "CVE-2014-0160": ["OutOfBoundsRead"],
    # CommandInjection because environment variables are used to inject commands into the Bash shell (Shellshock).
    "CVE-2014-6271": ["CommandInjection"],
    # CommandInjection because the MSDT URL protocol vulnerability allows injecting arguments to execute PowerShell commands.
    "CVE-2022-30190": ["CommandInjection"],
    # AccessControl because it is a Privilege Escalation vulnerability (Zerologon) due to a cryptographic flaw allowing authentication bypass.
    "CVE-2020-1472": ["AccessControl"],
    # PathTraversal because the vulnerability allows directory traversal to access files and execute code on Citrix ADC.
    "CVE-2019-19781": ["PathTraversal"],
    # PathTraversal because it is a path traversal vulnerability in the FortiOS SSL VPN web portal allowing the reading of unencrypted system files.
    "CVE-2018-13379": ["PathTraversal"],
    # CodeInjection because it involves OGNL injection in the Content-Type header which is executed by the Apache Struts framework.
    "CVE-2017-5638": ["CodeInjection"],
    # InputValidation because the Windows CryptoAPI failed to properly validate Elliptic Curve Cryptography (ECC) parameters (CurveBall).
    "CVE-2020-0601": ["InputValidation"],

    # XSS because the compromised npm package (color-name) injects malicious scripts that execute in the browser to redirect cryptocurrency transactions.
    "CVE-2025-59145": ["XSS"],
    # PathTraversal because it is a relative path traversal vulnerability in Fortinet FortiWeb allowing unauthenticated execution of administrative commands.
    "CVE-2025-64446": ["PathTraversal"],
    # AccessControl because it is a Privilege Escalation vulnerability in Microsoft Exchange Server (ProxyShell) allowing bypass of access controls.
    "CVE-2021-34523": ["AccessControl"],
    # UntrustedDeserialization because it is an insecure deserialization vulnerability in the Unified Messaging service of Microsoft Exchange Server.
    "CVE-2021-26857": ["UntrustedDeserialization"],
    # UntrustedDeserialization because it allows remote code execution via unspecified vectors involving deserialization in MobileIron Core & Connector.
    "CVE-2020-15505": ["UntrustedDeserialization"],

    # BufferOverflow because it is a stack-based buffer overflow in Ivanti Connect Secure allowing remote code execution.
    "CVE-2025-0282": ["BufferOverflow"],
    # UntrustedDeserialization because it is a deserialization vulnerability in Trimble Cityworks allowing remote code execution.
    "CVE-2025-0994": ["UntrustedDeserialization"],
    # CodeInjection because the vulnerability allows injection of NGINX configuration directives (code) via the Ingress-NGINX controller.
    "CVE-2025-1974": ["CodeInjection"],
    # UseAfterFree because it is a remote code execution vulnerability caused by a Use After Free error in the VBScript engine.
    "CVE-2018-8174": ["UseAfterFree"],
    # InputValidation because it is a type confusion vulnerability in the Java Hotspot VM due to insufficient type checking (verifier bug).
    "CVE-2012-1723": ["InputValidation"],
}


REF_MAX = 5

CHAT_MODEL = "ministral-3:3b"#
SUMMARIZER_MODEL = "ministral-3:3b"#