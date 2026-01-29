"""
Base Analyzer - The Foundation of Willie's Wrath
"Every file is guilty until proven otherwise."
"""

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Tuple
from pathlib import Path


class Severity(Enum):
    """How angry Willie is about this issue."""
    CRITICAL = "CRITICAL"  # "YE ABSOLUTE NUMPTY!"
    HIGH = "HIGH"          # "Are ye DAFT?!"
    MEDIUM = "MEDIUM"      # "This is garbage, laddie."
    LOW = "LOW"            # "Och, I've seen worse..."
    INFO = "INFO"          # "Just so ye know..."


@dataclass
class Issue:
    """A single issue found in the code."""
    file_path: str
    line_number: int
    column: int
    severity: Severity
    rule_id: str
    message: str
    code_snippet: str = ""
    fix_suggestion: Optional[str] = None
    auto_fixable: bool = False
    
    def to_dict(self) -> dict:
        return {
            'file': self.file_path,
            'line': self.line_number,
            'column': self.column,
            'severity': self.severity.value,
            'rule': self.rule_id,
            'message': self.message,
            'snippet': self.code_snippet,
            'fix': self.fix_suggestion,
            'auto_fixable': self.auto_fixable,
        }


# Willie's colorful commentary
WILLIE_INSULTS = {
    Severity.CRITICAL: [
        "YE ABSOLUTE NUMPTY! This is a security disaster!",
        "ACH! MY EYES! This code is an abomination!",
        "Are ye TRYING to get hacked?! Fix this NOW!",
        "I've seen bairns write better code than this!",
        "This is so bad it's making me bagpipes weep!",
    ],
    Severity.HIGH: [
        "Are ye DAFT?! This is dangerous code!",
        "Grease me up, because I'm gonna have to fix this mess!",
        "Did Ralph write this? It looks like paste and crayons!",
        "This code smells like haggis left in the sun!",
    ],
    Severity.MEDIUM: [
        "This is garbage, laddie. Pure garbage.",
        "I wouldn't trust this code to lock a shed!",
        "Och, what were ye thinking here?",
        "This needs a good scrubbing, it does!",
    ],
    Severity.LOW: [
        "Och, I've seen worse... but not by much.",
        "This is sloppy work. Willie doesn't do sloppy.",
        "Clean this up before I lose my temper!",
    ],
    Severity.INFO: [
        "Just so ye know, laddie...",
        "Here's a wee suggestion for ye...",
        "Not terrible, but could be better.",
    ],
}


def get_willie_comment(severity: Severity) -> str:
    """Get a random Willie insult for the severity level."""
    import random
    return random.choice(WILLIE_INSULTS[severity])


@dataclass
class AnalysisResult:
    """Results from analyzing a single file."""
    file_path: str
    issues: List[Issue] = field(default_factory=list)
    fixed_content: Optional[str] = None
    original_content: str = ""
    
    @property
    def issue_count(self) -> int:
        return len(self.issues)
    
    @property
    def critical_count(self) -> int:
        return sum(1 for i in self.issues if i.severity == Severity.CRITICAL)
    
    @property
    def high_count(self) -> int:
        return sum(1 for i in self.issues if i.severity == Severity.HIGH)
    
    @property
    def is_clean(self) -> bool:
        return len(self.issues) == 0
    
    @property
    def fixable_count(self) -> int:
        return sum(1 for i in self.issues if i.auto_fixable)


class BaseAnalyzer(ABC):
    """Base class for all language analyzers."""
    
    name: str = "Base"
    extensions: List[str] = []
    
    def __init__(self):
        self.issues: List[Issue] = []
        self.content: str = ""
        self.lines: List[str] = []
        self.file_path: str = ""
    
    def analyze_file(self, file_path: str) -> AnalysisResult:
        """Analyze a file and return issues found."""
        self.file_path = file_path
        self.issues = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                self.content = f.read()
                self.lines = self.content.splitlines()
        except Exception as e:
            self.issues.append(Issue(
                file_path=file_path,
                line_number=0,
                column=0,
                severity=Severity.CRITICAL,
                rule_id="FILE_READ_ERROR",
                message=f"Could not read file: {e}",
            ))
            return AnalysisResult(file_path=file_path, issues=self.issues)
        
        # Run all checks
        self._run_common_checks()
        self._run_language_checks()
        
        return AnalysisResult(
            file_path=file_path,
            issues=self.issues,
            original_content=self.content,
        )
    
    def _run_common_checks(self):
        """Run checks common to all languages."""
        self._check_hardcoded_secrets()
        self._check_todo_fixme()
        self._check_long_lines()
        self._check_trailing_whitespace()
    
    @abstractmethod
    def _run_language_checks(self):
        """Run language-specific checks. Override in subclasses."""
        pass
    
    def _add_issue(self, line_num: int, col: int, severity: Severity, 
                   rule_id: str, message: str, fix: Optional[str] = None,
                   auto_fixable: bool = False):
        """Helper to add an issue."""
        snippet = self.lines[line_num - 1] if 0 < line_num <= len(self.lines) else ""
        self.issues.append(Issue(
            file_path=self.file_path,
            line_number=line_num,
            column=col,
            severity=severity,
            rule_id=rule_id,
            message=message,
            code_snippet=snippet.strip(),
            fix_suggestion=fix,
            auto_fixable=auto_fixable,
        ))
    
    def _check_hardcoded_secrets(self):
        """Check for hardcoded secrets, API keys, passwords."""
        secret_patterns = [
            (r'(?i)(api[_-]?key|apikey)\s*[=:]\s*["\'][^"\']{10,}["\']', "API_KEY_EXPOSED"),
            (r'(?i)(password|passwd|pwd)\s*[=:]\s*["\'][^"\']+["\']', "PASSWORD_HARDCODED"),
            (r'(?i)(secret|token)\s*[=:]\s*["\'][^"\']{8,}["\']', "SECRET_EXPOSED"),
            (r'(?i)(aws_access_key|aws_secret)\s*[=:]\s*["\'][^"\']+["\']', "AWS_CREDS_EXPOSED"),
            (r'(?i)private[_-]?key\s*[=:]\s*["\'][^"\']+["\']', "PRIVATE_KEY_EXPOSED"),
            (r'sk-[a-zA-Z0-9]{20,}', "OPENAI_KEY_EXPOSED"),
            (r'ghp_[a-zA-Z0-9]{36}', "GITHUB_TOKEN_EXPOSED"),
        ]
        
        for line_num, line in enumerate(self.lines, 1):
            for pattern, rule_id in secret_patterns:
                if re.search(pattern, line):
                    self._add_issue(
                        line_num, 0, Severity.CRITICAL, rule_id,
                        f"HARDCODED SECRET DETECTED! Move to environment variables!",
                        fix="Use os.environ.get() or a .env file",
                        auto_fixable=False
                    )
    
    def _check_todo_fixme(self):
        """Check for TODO/FIXME comments that might indicate incomplete code."""
        for line_num, line in enumerate(self.lines, 1):
            if re.search(r'(?i)\b(TODO|FIXME|XXX|HACK|BUG)\b', line):
                self._add_issue(
                    line_num, 0, Severity.INFO, "TODO_FOUND",
                    "Unfinished business detected. Complete it or remove it!",
                )
    
    def _check_long_lines(self, max_length: int = 120):
        """Check for excessively long lines."""
        for line_num, line in enumerate(self.lines, 1):
            if len(line) > max_length:
                self._add_issue(
                    line_num, max_length, Severity.LOW, "LINE_TOO_LONG",
                    f"Line is {len(line)} chars. Keep it under {max_length}!",
                    auto_fixable=False
                )
    
    def _check_trailing_whitespace(self):
        """Check for trailing whitespace."""
        for line_num, line in enumerate(self.lines, 1):
            if line.endswith(' ') or line.endswith('\t'):
                self._add_issue(
                    line_num, len(line.rstrip()), Severity.LOW, "TRAILING_WHITESPACE",
                    "Trailing whitespace detected. Clean up after yourself!",
                    fix=line.rstrip(),
                    auto_fixable=True
                )
    
    def apply_fixes(self, content: str) -> Tuple[str, int]:
        """Apply auto-fixes to content. Returns (fixed_content, fix_count)."""
        lines = content.splitlines(keepends=True)
        fix_count = 0
        
        for issue in self.issues:
            if issue.auto_fixable and issue.fix_suggestion:
                idx = issue.line_number - 1
                if 0 <= idx < len(lines):
                    # Preserve line ending
                    ending = '\n' if lines[idx].endswith('\n') else ''
                    lines[idx] = issue.fix_suggestion + ending
                    fix_count += 1
        
        return ''.join(lines), fix_count
