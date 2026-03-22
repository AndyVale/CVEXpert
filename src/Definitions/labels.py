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


VULNERABILITY_TREE = {
    "InputValidation": {
        "description": "Input Validation: Failures to properly verify, filter, or sanitize data received from external sources before processing.",
        "children": {
            "InjectionFlaws": {
                "description": "Injection Flaws: Broad category where untrusted data is sent to an interpreter as part of a command or query.",
                "children": {
                    "SQLi": {
                        "description": "SQL Injection: Malicious SQL queries are injected to manipulate the database.",
                        "children": {}
                    },
                    "CommandInjection": {
                        "description": "Command Injection: Unvalidated input is used to construct system shell commands. Covers OS Command Injection.",
                        "children": {}
                    },
                    "CodeInjection": {
                        "description": "Code Injection: Unvalidated input is executed as code by the application's interpreter (e.g., PHP, Python, Java).",
                        "children": {}
                    },
                    "XSS": {
                        "description": "Cross-site Scripting: Malicious scripts are injected into web pages and executed in the victim's browser.",
                        "children": {}
                    },
                    "PathTraversal": {
                        "description": "Path Traversal: Manipulation of file paths (e.g., '../') to access files or directories outside the intended scope.",
                        "children": {}
                    },
                    "UntrustedDeserialization": {
                        "description": "Deserialization of Untrusted Data: Unsafe restoration of objects from data streams, leading to RCE or logic manipulation.",
                        "children": {}
                    }
                }
            },
            "RequestHandling": {
                "description": "Request Handling: Flaws in how an application constructs and sends requests to other network components.",
                "children": {
                    "SSRF": {
                        "description": "Server-Side Request Forgery: The server is coerced into making requests to unintended internal or external resources.",
                        "children": {}
                    }
                }
            }
        }
    },
    "AccessControl": {
        "description": "AccessControl: Weaknesses in the mechanisms used to verify identity and enforce permissions across the network.",
        "children": {
            "BrokenAuthentication": {
                "description": "Broken Authentication: Vulnerabilities in login or session management allowing attackers to compromise passwords or identity tokens.",
                "children": {}
            },
            "ImproperAuthorization": {
                "description": "Improper Authorization: Failure to restrict access to sensitive resources or functions based on defined user privilege levels.",
                "children": {
                    "CSRF": {
                        "description": "Cross-Site Request Forgery: Unverified requests are executed on behalf of an authenticated user without their consent.",
                        "children": {}
                    }
                }
            }
        }
    },
    "Memory": {
        "description": "Memory: Low-level errors related to the insecure management of system memory, typically in compiled languages.",
        "children": {
            "MemoryCorruption": {
                "description": "Memory Corruption: Flaws that allow attackers to modify memory contents to alter the execution flow of a program.",
                "children": {
                    "BufferOverflow": {
                        "description": "Buffer Overflow: Writing data past buffer boundaries on the stack or heap.",
                        "children": {},
                    },
                    "UseAfterFree": {
                        "description": "Use After Free: Accessing memory after it has been explicitly freed. A specific memory corruption distinct from overflows.",
                        "children": {}
                    }
                }
            },
            "MemoryDisclosure": {
                "description": "Memory Disclosure: Vulnerabilities that allow an attacker to read data from memory locations they should not access.",
                "children": {
                    "OutOfBoundsRead": {
                        "description": "Out-of-bounds Read: Reading data past allocated memory boundaries. Use this for memory-based information leaks.",
                        "children": {}
                    }
                }
            }
        }
    },
    "ResourceManagement": {
        "description": "Resource Management: Improper handling of limited system resources such as CPU, memory, disk space, or network bandwidth.",
        "children": {
            "ResourceExhaustion": {
                "description": "Resource Exhaustion: Uncontrolled consumption of system resources like CPU or bandwidth, leading to a denial of service.",
                "children": {}
            },
            "MemoryLeaks": {
                "description": "Memory Leak: Failure to release memory after it is no longer needed, eventually leading to system instability or crashes.",
                "children": {}
            }
        }
    },
    "Misconfiguration": {
        "description": "Misconfiguration: Security weaknesses arising from incorrect settings or incomplete deployment of security controls.",
        "children": {
            "InsecureConfiguration": {
                "description": "Insecure Configuration: Vulnerabilities where the software is shipped or deployed with inherently dangerous initial settings, publicly known factory credentials, hardcoded secrets, or overly permissive access rights out-of-the-box.",
                "children": {}
            },
            "WeakCryptography": {
                "description": "Weak Cryptography: Use of obsolete or flawed encryption algorithms that fail to ensure the confidentiality and integrity of data.",
                "children": {}
            },
            "InformationExposure": {
                "description": "Information Exposure: Accidental disclosure of technical details or sensitive system data through error messages or metadata.",
                "children": {}
            }
        }
    }
}


def _extract_all_tree_labels(tree: dict) -> list:
    """Recursively extracts all keys (labels) from the vulnerability tree."""
    labels =[]
    for key, value in tree.items():
        labels.append(key)
        if "children" in value and value["children"]:
            labels.extend(_extract_all_tree_labels(value["children"]))
    return labels

ALL_TREE_LABELS = _extract_all_tree_labels(VULNERABILITY_TREE) + ["NONE"]


def _flatten_tree(tree: dict) -> dict:
    """Helper to create a flat map: label -> {description, children_keys}"""
    flat = {}
    for key, val in tree.items():
        children = val.get("children", {})
        flat[key] = {
            "description": val["description"],
            "children": list(children.keys())
        }
        if children:
            flat.update(_flatten_tree(children))
    return flat

FLATTEN_TREE = _flatten_tree(VULNERABILITY_TREE)