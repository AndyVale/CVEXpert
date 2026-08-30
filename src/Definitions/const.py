CVE_TEST = {
    # Log4Shell: attacker-controlled lookup text triggers outbound JNDI
    # requests and loading/execution of remote Java code. Apache's CNA record
    # additionally maps the flaw to CWE-20, CWE-400, and CWE-502.
    "CVE-2021-44228": [
        "SSRF",
        "CodeInjection",
        "UntrustedDeserialization",
        "ResourceExhaustion",
        "InputValidation",
    ],
    # EternalBlue: malformed SMBv1 transaction data causes an out-of-bounds
    # kernel-pool write because the request sizes are not validated correctly.
    # Being remotely exploitable without credentials is not itself an
    # authentication or authorization bypass.
    "CVE-2017-0144": ["BufferOverflow", "InputValidation"],
    # Heartbleed: an unchecked heartbeat payload length causes a buffer
    # over-read. The resulting memory disclosure belongs to OutOfBoundsRead,
    # which labels.py explicitly distinguishes from logical InfoLeak.
    "CVE-2014-0160": ["OutOfBoundsRead", "InputValidation"],
    # Shellshock: Bash accepts trailing commands after an exported function
    # definition, so attacker-controlled environment data becomes shell input.
    "CVE-2014-6271": ["CommandInjection", "InputValidation"],
    # Follina: crafted ms-msdt parameters are passed into PowerShell-capable
    # diagnostic execution without adequate validation.
    "CVE-2022-30190": ["CommandInjection", "InputValidation"],
    # Zerologon: misuse of a fixed zero IV lets an attacker impersonate a
    # machine account and obtain domain-administrator privileges.
    "CVE-2020-1472": ["AccessControl"],
    # Shitrix: path traversal reaches an internal Perl handler, after which an
    # attacker-controlled Template Toolkit expression is evaluated as code.
    "CVE-2019-19781": ["PathTraversal", "CodeInjection", "InputValidation"],
    # FortiOS SSL VPN: a crafted resource path escapes its intended directory
    # and returns arbitrary system files, including credential-bearing session
    # files. No separate authentication or privilege-management flaw is shown.
    "CVE-2018-13379": ["PathTraversal", "InfoLeak", "InputValidation"],
    # Apache Struts: crafted multipart headers enter an exception message that
    # is evaluated as an attacker-controlled OGNL expression.
    "CVE-2017-5638": ["CodeInjection", "InputValidation"],
    # CurveBall: CryptoAPI insufficiently validates ECC certificate parameters,
    # allowing a forged certificate to be accepted as trusted.
    "CVE-2020-0601": ["AccessControl", "InputValidation"],

    # color-name npm compromise: a stolen publishing account was used to ship
    # an intentionally malicious package. The taxonomy has no supply-chain or
    # embedded-malware label; neither CodeInjection nor XSS describes the flaw.
    "CVE-2025-59145": ["NONE"],
    # FortiWeb: relative path traversal reaches a management CGI outside the
    # authenticated route and permits administrative actions. "Administrative
    # commands" here are management operations, not OS shell command injection.
    "CVE-2025-64446": ["PathTraversal", "AccessControl", "InputValidation"],
    # ProxyShell privilege-escalation component: Exchange fails to validate a
    # caller-supplied X-Rps-CAT access token, enabling authentication bypass and
    # execution with elevated privileges. The token flaw is not deserialization.
    "CVE-2021-34523": ["AccessControl", "InputValidation"],
    # ProxyLogon UM component: Exchange deserializes untrusted user-controlled
    # data, producing SYSTEM-level RCE. RCE is an impact here, not evidence of a
    # separate code-injection or access-control weakness in this CVE.
    "CVE-2021-26857": ["UntrustedDeserialization"],
    # MobileIron: a Hessian endpoint deserializes attacker data and a Groovy
    # gadget then evaluates injected code. The related authentication-bypass
    # weakness is separately assigned CVE-2020-15506.
    "CVE-2020-15505": [
        "CodeInjection",
        "UntrustedDeserialization",
    ],

    # Ivanti Connect Secure: an overlong clientCapabilities value is copied to
    # a fixed-size stack buffer without a length check. Unauthenticated reach is
    # an attack precondition, not an access-control bypass.
    "CVE-2025-0282": ["BufferOverflow", "InputValidation"],
    # Trimble Cityworks: authenticated attacker-controlled serialized data can
    # be restored by the server and lead to RCE.
    "CVE-2025-0994": ["UntrustedDeserialization"],
    # IngressNightmare escalation: the validating admission controller is
    # insufficiently isolated from the pod network, letting callers without the
    # normally required Kubernetes privilege reach it. Configuration injection
    # and Secret disclosure require companion CVEs and are not labels for 1974.
    "CVE-2025-1974": ["AccessControl"],
    # Double Kill: the VBScript engine's Class_Terminate handling permits an
    # object to be referenced after its memory has been freed.
    "CVE-2018-8174": ["UseAfterFree"],
    # Java verifier field access: insufficient bytecode type/access checks allow
    # an untrusted applet to escape the sandbox. The applet already executes by
    # design, so the escape is not a separate code-injection flaw.
    "CVE-2012-1723": ["AccessControl", "InputValidation"],
}
