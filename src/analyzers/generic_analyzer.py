"""
Generic Analyzer - Willie's Fallback for Unknown Languages
"I don't recognize this language, but I can still smell the GREASE!"
"""

import re
from .base_analyzer import BaseAnalyzer, Severity


class GenericAnalyzer(BaseAnalyzer):
    """Generic analyzer for any file type."""
    
    name = "Generic"
    extensions = []  # Matches any file
    
    def _run_language_checks(self):
        """Run generic checks applicable to any file."""
        self._check_sensitive_files()
        self._check_debug_flags()
        self._check_url_patterns()
        self._check_ip_addresses()
        self._check_base64_secrets()
        self._check_file_permissions()
    
    def _check_sensitive_files(self):
        """Check if this is a sensitive file that shouldn't be committed."""
        sensitive_patterns = [
            (r'\.env$', "ENV file should not be committed!"),
            (r'\.pem$', "PEM key file should not be committed!"),
            (r'\.key$', "Key file should not be committed!"),
            (r'id_rsa', "SSH private key should not be committed!"),
            (r'\.htpasswd$', "Password file should not be committed!"),
            (r'credentials\.json', "Credentials file should not be committed!"),
        ]
        
        for pattern, message in sensitive_patterns:
            if re.search(pattern, self.file_path, re.IGNORECASE):
                self._add_issue(
                    1, 0, Severity.CRITICAL, "SENSITIVE_FILE",
                    message,
                    fix="Add to .gitignore and remove from repository",
                )
    
    def _check_debug_flags(self):
        """Check for debug flags that should be disabled."""
        patterns = [
            (r'DEBUG\s*=\s*[Tt]rue', "DEBUG_ENABLED"),
            (r'DEBUG\s*=\s*1', "DEBUG_ENABLED"),
            (r'TESTING\s*=\s*[Tt]rue', "TESTING_ENABLED"),
            (r'development\s*=\s*[Tt]rue', "DEV_MODE"),
        ]
        
        for line_num, line in enumerate(self.lines, 1):
            for pattern, rule_id in patterns:
                if re.search(pattern, line):
                    self._add_issue(
                        line_num, 0, Severity.MEDIUM, rule_id,
                        "Debug/dev flag enabled! Disable for production!",
                    )
    
    def _check_url_patterns(self):
        """Check for suspicious URLs."""
        for line_num, line in enumerate(self.lines, 1):
            # Localhost URLs that might break in production
            if re.search(r'http://localhost[:/]', line):
                self._add_issue(
                    line_num, 0, Severity.MEDIUM, "LOCALHOST_URL",
                    "Hardcoded localhost URL - won't work in production!",
                    fix="Use environment variables for URLs",
                )
            # HTTP URLs (should be HTTPS)
            if re.search(r'http://(?!localhost|127\.0\.0\.1)', line):
                self._add_issue(
                    line_num, 0, Severity.MEDIUM, "INSECURE_HTTP",
                    "Using HTTP instead of HTTPS!",
                    fix="Use HTTPS for all external URLs",
                )
    
    def _check_ip_addresses(self):
        """Check for hardcoded IP addresses."""
        for line_num, line in enumerate(self.lines, 1):
            # IPv4 (but not localhost)
            if re.search(r'\b(?!127\.0\.0\.|0\.0\.0\.)\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', line):
                # Skip if it looks like a version number
                if not re.search(r'\d+\.\d+\.\d+\.\d+["\']?\s*$', line):
                    self._add_issue(
                        line_num, 0, Severity.LOW, "HARDCODED_IP",
                        "Hardcoded IP address detected. Use DNS or config!",
                    )
    
    def _check_base64_secrets(self):
        """Check for potential base64 encoded secrets."""
        for line_num, line in enumerate(self.lines, 1):
            # Long base64 strings that might be secrets
            match = re.search(r'["\'][A-Za-z0-9+/]{40,}={0,2}["\']', line)
            if match:
                # Check if it looks like a key/secret
                context = line.lower()
                if any(word in context for word in ['key', 'secret', 'token', 'password', 'auth', 'cred']):
                    self._add_issue(
                        line_num, 0, Severity.HIGH, "BASE64_SECRET",
                        "Possible base64-encoded secret detected!",
                        fix="Move secrets to environment variables",
                    )
    
    def _check_file_permissions(self):
        """Check for unsafe file permission patterns."""
        for line_num, line in enumerate(self.lines, 1):
            # chmod 777 or similar
            if re.search(r'chmod\s+777|chmod\s+666|chmod\s+755.*\.sh', line):
                self._add_issue(
                    line_num, 0, Severity.HIGH, "UNSAFE_CHMOD",
                    "Overly permissive file permissions!",
                    fix="Use least privilege principle: chmod 600 for private files",
                )
            # os.chmod with 0o777
            if re.search(r'chmod.*0o?777|chmod.*0o?666', line):
                self._add_issue(
                    line_num, 0, Severity.HIGH, "UNSAFE_CHMOD_CODE",
                    "Setting overly permissive file permissions in code!",
                )
