"""
Python Analyzer - Willie's Python Security Scanner
"Python? More like PAIN-thon when ye write it like THIS!"
"""

import re
from typing import List
from .base_analyzer import BaseAnalyzer, Severity


class PythonAnalyzer(BaseAnalyzer):
    """Analyzer for Python files."""
    
    name = "Python"
    extensions = ['.py']
    
    def _run_language_checks(self):
        """Run Python-specific security and style checks."""
        self._check_eval_exec()
        self._check_pickle()
        self._check_shell_injection()
        self._check_sql_injection()
        self._check_insecure_imports()
        self._check_assert_in_prod()
        self._check_bare_except()
        self._check_mutable_default()
        self._check_input_unsanitized()
        self._check_debug_statements()
        self._check_hardcoded_paths()
    
    def _check_eval_exec(self):
        """Check for dangerous eval/exec usage."""
        for line_num, line in enumerate(self.lines, 1):
            if re.search(r'\b(eval|exec)\s*\(', line):
                # Skip if it's a comment
                if line.strip().startswith('#'):
                    continue
                self._add_issue(
                    line_num, 0, Severity.CRITICAL, "DANGEROUS_EVAL",
                    "eval() or exec() detected! This is a code injection vector!",
                    fix="Use ast.literal_eval() for data parsing, or refactor entirely",
                )
    
    def _check_pickle(self):
        """Check for insecure pickle usage."""
        for line_num, line in enumerate(self.lines, 1):
            if re.search(r'pickle\.(load|loads)\s*\(', line):
                self._add_issue(
                    line_num, 0, Severity.CRITICAL, "INSECURE_PICKLE",
                    "pickle.load() on untrusted data = Remote Code Execution!",
                    fix="Use json for data serialization, or validate source",
                )
    
    def _check_shell_injection(self):
        """Check for shell injection vulnerabilities."""
        patterns = [
            (r'os\.system\s*\(', "OS_SYSTEM_DANGEROUS"),
            (r'os\.popen\s*\(', "OS_POPEN_DANGEROUS"),
            (r'subprocess\.\w+\s*\([^)]*shell\s*=\s*True', "SHELL_TRUE_DANGEROUS"),
            (r'commands\.\w+\s*\(', "COMMANDS_DEPRECATED"),
        ]
        
        for line_num, line in enumerate(self.lines, 1):
            if line.strip().startswith('#'):
                continue
            for pattern, rule_id in patterns:
                if re.search(pattern, line):
                    self._add_issue(
                        line_num, 0, Severity.HIGH, rule_id,
                        "Shell command with potential injection vulnerability!",
                        fix="Use subprocess.run() with shell=False and a list of args",
                    )
    
    def _check_sql_injection(self):
        """Check for SQL injection vulnerabilities."""
        for line_num, line in enumerate(self.lines, 1):
            # Check for string formatting in SQL
            if re.search(r'(execute|query)\s*\(\s*["\'].*(%s|%d|\{|\+).*["\']', line):
                self._add_issue(
                    line_num, 0, Severity.CRITICAL, "SQL_INJECTION",
                    "SQL injection vulnerability! Use parameterized queries!",
                    fix="cursor.execute('SELECT * FROM t WHERE id = ?', (user_id,))",
                )
            # Check for f-strings in SQL
            if re.search(r'(execute|query)\s*\(\s*f["\']', line):
                self._add_issue(
                    line_num, 0, Severity.CRITICAL, "SQL_INJECTION_FSTRING",
                    "f-string in SQL query = INJECTION! Use parameterized queries!",
                )
    
    def _check_insecure_imports(self):
        """Check for imports of insecure or deprecated modules."""
        insecure = {
            'telnetlib': "Telnet is unencrypted. Use SSH!",
            'ftplib': "FTP is unencrypted. Use SFTP!",
            'md5': "MD5 is broken. Use hashlib.sha256()!",
            'sha': "SHA-1 is weak. Use hashlib.sha256()!",
            'crypt': "crypt is platform-dependent and weak!",
            'random': None,  # Special handling below
        }
        
        for line_num, line in enumerate(self.lines, 1):
            for module, message in insecure.items():
                if re.search(rf'^\s*(import|from)\s+{module}\b', line):
                    if module == 'random':
                        # Only warn if used for security
                        if any('password' in l.lower() or 'secret' in l.lower() or 'token' in l.lower() 
                               for l in self.lines):
                            self._add_issue(
                                line_num, 0, Severity.HIGH, "INSECURE_RANDOM",
                                "Using 'random' for security! Use 'secrets' module instead!",
                            )
                    else:
                        self._add_issue(
                            line_num, 0, Severity.MEDIUM, "INSECURE_IMPORT",
                            message or f"Insecure module '{module}' imported!",
                        )
    
    def _check_assert_in_prod(self):
        """Check for assert statements that could be stripped in production."""
        for line_num, line in enumerate(self.lines, 1):
            if re.search(r'^\s*assert\s+', line):
                self._add_issue(
                    line_num, 0, Severity.MEDIUM, "ASSERT_IN_PROD",
                    "assert can be disabled with -O flag! Don't use for validation!",
                    fix="Use proper if/raise statements for input validation",
                )
    
    def _check_bare_except(self):
        """Check for bare except clauses."""
        for line_num, line in enumerate(self.lines, 1):
            if re.search(r'^\s*except\s*:', line):
                self._add_issue(
                    line_num, 0, Severity.MEDIUM, "BARE_EXCEPT",
                    "Bare 'except:' catches everything including KeyboardInterrupt!",
                    fix="except Exception as e:",
                    auto_fixable=False
                )
    
    def _check_mutable_default(self):
        """Check for mutable default arguments."""
        for line_num, line in enumerate(self.lines, 1):
            if re.search(r'def\s+\w+\s*\([^)]*=\s*(\[\]|\{\}|\{[^}]+\}|\[[^\]]+\])', line):
                self._add_issue(
                    line_num, 0, Severity.MEDIUM, "MUTABLE_DEFAULT",
                    "Mutable default argument! This WILL bite you!",
                    fix="Use None as default and create in function body",
                )
    
    def _check_input_unsanitized(self):
        """Check for unsanitized input() usage."""
        for line_num, line in enumerate(self.lines, 1):
            # Check for input() being used directly in dangerous contexts
            if re.search(r'(eval|exec|open|os\.\w+)\s*\(\s*input\s*\(', line):
                self._add_issue(
                    line_num, 0, Severity.CRITICAL, "UNSANITIZED_INPUT",
                    "User input passed directly to dangerous function!",
                )
    
    def _check_debug_statements(self):
        """Check for debug statements left in code."""
        debug_patterns = [
            (r'^\s*print\s*\([^)]*debug', "DEBUG_PRINT"),
            (r'^\s*import\s+pdb', "PDB_IMPORT"),
            (r'pdb\.set_trace\s*\(', "PDB_TRACE"),
            (r'breakpoint\s*\(\)', "BREAKPOINT"),
            (r'^\s*import\s+ipdb', "IPDB_IMPORT"),
        ]
        
        for line_num, line in enumerate(self.lines, 1):
            for pattern, rule_id in debug_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    self._add_issue(
                        line_num, 0, Severity.MEDIUM, rule_id,
                        "Debug statement in code! Remove before production!",
                        auto_fixable=False
                    )
    
    def _check_hardcoded_paths(self):
        """Check for hardcoded absolute paths."""
        for line_num, line in enumerate(self.lines, 1):
            # Windows paths
            if re.search(r'["\'][A-Z]:\\\\', line):
                self._add_issue(
                    line_num, 0, Severity.MEDIUM, "HARDCODED_PATH_WIN",
                    "Hardcoded Windows path! Use pathlib or os.path!",
                )
            # Unix absolute paths (but not root references for config)
            if re.search(r'["\']\/(?!etc\/|var\/|tmp\/)[a-z]+\/', line):
                self._add_issue(
                    line_num, 0, Severity.LOW, "HARDCODED_PATH_UNIX",
                    "Hardcoded Unix path detected. Consider using relative paths.",
                )
