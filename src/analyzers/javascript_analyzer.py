"""
JavaScript Analyzer - Willie's JS Security Scanner
"JavaScript? More like JAVA-SCRIPT-KIDDIE when ye write it like THIS!"
"""

import re
from .base_analyzer import BaseAnalyzer, Severity


class JavaScriptAnalyzer(BaseAnalyzer):
    """Analyzer for JavaScript/TypeScript files."""
    
    name = "JavaScript"
    extensions = ['.js', '.jsx', '.ts', '.tsx']
    
    def _run_language_checks(self):
        """Run JavaScript-specific security and style checks."""
        self._check_eval()
        self._check_innerhtml()
        self._check_document_write()
        self._check_prototype_pollution()
        self._check_sql_injection()
        self._check_console_log()
        self._check_var_usage()
        self._check_equality()
        self._check_insecure_fetch()
        self._check_cors()
        self._check_xss_vectors()
    
    def _check_eval(self):
        """Check for eval and similar dangerous functions."""
        patterns = [
            (r'\beval\s*\(', "DANGEROUS_EVAL"),
            (r'\bFunction\s*\(', "DANGEROUS_FUNCTION_CONSTRUCTOR"),
            (r'setTimeout\s*\(\s*["\']', "SETTIMEOUT_STRING"),
            (r'setInterval\s*\(\s*["\']', "SETINTERVAL_STRING"),
        ]
        
        for line_num, line in enumerate(self.lines, 1):
            if line.strip().startswith('//'):
                continue
            for pattern, rule_id in patterns:
                if re.search(pattern, line):
                    self._add_issue(
                        line_num, 0, Severity.CRITICAL, rule_id,
                        "Dangerous eval-like pattern! This is a code injection vector!",
                        fix="Don't use eval(). Ever. Find another way.",
                    )
    
    def _check_innerhtml(self):
        """Check for innerHTML usage (XSS risk)."""
        for line_num, line in enumerate(self.lines, 1):
            if re.search(r'\.innerHTML\s*=', line):
                self._add_issue(
                    line_num, 0, Severity.HIGH, "INNERHTML_XSS",
                    "innerHTML is an XSS vector! Use textContent or sanitize!",
                    fix="Use element.textContent or DOMPurify.sanitize()",
                )
            if re.search(r'\.outerHTML\s*=', line):
                self._add_issue(
                    line_num, 0, Severity.HIGH, "OUTERHTML_XSS",
                    "outerHTML is an XSS vector!",
                )
    
    def _check_document_write(self):
        """Check for document.write usage."""
        for line_num, line in enumerate(self.lines, 1):
            if re.search(r'document\.write\s*\(', line):
                self._add_issue(
                    line_num, 0, Severity.HIGH, "DOCUMENT_WRITE",
                    "document.write is dangerous and blocks rendering!",
                    fix="Use DOM manipulation methods instead",
                )
    
    def _check_prototype_pollution(self):
        """Check for potential prototype pollution."""
        for line_num, line in enumerate(self.lines, 1):
            if re.search(r'\[.*\]\s*=.*\[.*\]', line) and 'prototype' in line.lower():
                self._add_issue(
                    line_num, 0, Severity.CRITICAL, "PROTOTYPE_POLLUTION",
                    "Potential prototype pollution detected!",
                )
            # Check for __proto__ access
            if re.search(r'__proto__', line):
                self._add_issue(
                    line_num, 0, Severity.HIGH, "PROTO_ACCESS",
                    "__proto__ access detected! This is dangerous!",
                )
    
    def _check_sql_injection(self):
        """Check for SQL injection in JS (backend)."""
        for line_num, line in enumerate(self.lines, 1):
            if re.search(r'(query|execute)\s*\(\s*`', line):
                self._add_issue(
                    line_num, 0, Severity.CRITICAL, "SQL_INJECTION_TEMPLATE",
                    "Template literal in SQL query = INJECTION RISK!",
                    fix="Use parameterized queries with prepared statements",
                )
            if re.search(r'(query|execute)\s*\([^)]*\+', line):
                self._add_issue(
                    line_num, 0, Severity.CRITICAL, "SQL_INJECTION_CONCAT",
                    "String concatenation in SQL = INJECTION RISK!",
                )
    
    def _check_console_log(self):
        """Check for console.log statements (should be removed in prod)."""
        for line_num, line in enumerate(self.lines, 1):
            if re.search(r'console\.(log|debug|info|warn|error)\s*\(', line):
                if line.strip().startswith('//'):
                    continue
                self._add_issue(
                    line_num, 0, Severity.LOW, "CONSOLE_LOG",
                    "Console statement detected. Remove for production!",
                    auto_fixable=False
                )
    
    def _check_var_usage(self):
        """Check for var usage (use let/const)."""
        for line_num, line in enumerate(self.lines, 1):
            if re.search(r'^\s*var\s+', line):
                self._add_issue(
                    line_num, 0, Severity.LOW, "VAR_USAGE",
                    "Using 'var' in modern JS? Use 'let' or 'const'!",
                    fix="Replace 'var' with 'let' or 'const'",
                    auto_fixable=False
                )
    
    def _check_equality(self):
        """Check for loose equality operators."""
        for line_num, line in enumerate(self.lines, 1):
            if line.strip().startswith('//'):
                continue
            # Match == or != but not === or !==
            if re.search(r'[^!=]==[^=]', line) or re.search(r'[^!]!=[^=]', line):
                self._add_issue(
                    line_num, 0, Severity.MEDIUM, "LOOSE_EQUALITY",
                    "Loose equality (==) can cause type coercion bugs!",
                    fix="Use === or !== for strict equality",
                )
    
    def _check_insecure_fetch(self):
        """Check for insecure fetch/request patterns."""
        for line_num, line in enumerate(self.lines, 1):
            # HTTP requests to hardcoded strings
            if re.search(r'fetch\s*\(\s*["\']http://', line):
                self._add_issue(
                    line_num, 0, Severity.HIGH, "INSECURE_HTTP",
                    "Using HTTP instead of HTTPS! Insecure!",
                    fix="Use HTTPS for all requests",
                )
            # Disabled SSL verification
            if re.search(r'rejectUnauthorized\s*:\s*false', line):
                self._add_issue(
                    line_num, 0, Severity.CRITICAL, "SSL_DISABLED",
                    "SSL verification disabled! MITM attack vector!",
                )
    
    def _check_cors(self):
        """Check for CORS misconfigurations."""
        for line_num, line in enumerate(self.lines, 1):
            if re.search(r'Access-Control-Allow-Origin.*\*', line):
                self._add_issue(
                    line_num, 0, Severity.HIGH, "CORS_WILDCARD",
                    "CORS wildcard (*) allows any origin! Restrict it!",
                )
            if re.search(r'cors\(\s*\)', line):
                self._add_issue(
                    line_num, 0, Severity.MEDIUM, "CORS_DEFAULT",
                    "Default CORS config is too permissive!",
                )
    
    def _check_xss_vectors(self):
        """Check for common XSS vectors."""
        patterns = [
            (r'location\.href\s*=.*\+', "XSS_LOCATION"),
            (r'window\.open\s*\(.*\+', "XSS_WINDOW_OPEN"),
            (r'\.src\s*=.*\+', "XSS_SRC_ASSIGN"),
        ]
        
        for line_num, line in enumerate(self.lines, 1):
            for pattern, rule_id in patterns:
                if re.search(pattern, line):
                    self._add_issue(
                        line_num, 0, Severity.HIGH, rule_id,
                        "Potential XSS vector detected!",
                        fix="Validate and sanitize all user input",
                    )
