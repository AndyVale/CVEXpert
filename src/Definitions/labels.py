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