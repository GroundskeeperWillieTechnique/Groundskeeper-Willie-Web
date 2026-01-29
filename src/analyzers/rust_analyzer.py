"""
Rust Analyzer - Willie's Rust Safety Scanner
"Rust claims to be safe, but YE still found a way to mess it up!"
"""

import re
from .base_analyzer import BaseAnalyzer, Severity


class RustAnalyzer(BaseAnalyzer):
    """Analyzer for Rust files."""
    
    name = "Rust"
    extensions = ['.rs']
    
    def _run_language_checks(self):
        """Run Rust-specific safety checks."""
        self._check_unsafe()
        self._check_unwrap()
        self._check_panic()
        self._check_transmute()
        self._check_forgetting()
        self._check_raw_pointers()
        self._check_unchecked()
        self._check_deprecated()
        self._check_format_string()
    
    def _check_unsafe(self):
        """Check for unsafe blocks."""
        for line_num, line in enumerate(self.lines, 1):
            if re.search(r'\bunsafe\s*\{', line) or re.search(r'\bunsafe\s+fn\b', line):
                self._add_issue(
                    line_num, 0, Severity.HIGH, "UNSAFE_BLOCK",
                    "unsafe block/fn detected! Document WHY this is safe!",
                    fix="Add // SAFETY: comment explaining invariants",
                )
            if re.search(r'\bunsafe\s+impl\b', line):
                self._add_issue(
                    line_num, 0, Severity.HIGH, "UNSAFE_IMPL",
                    "unsafe impl detected! Verify trait safety requirements!",
                )
    
    def _check_unwrap(self):
        """Check for unwrap() calls that could panic."""
        for line_num, line in enumerate(self.lines, 1):
            if line.strip().startswith('//'):
                continue
            if re.search(r'\.unwrap\(\)', line):
                # Check if it's in a test
                in_test = any('#[test]' in self.lines[max(0,i):line_num] 
                             for i in range(max(0, line_num-5), line_num))
                if not in_test:
                    self._add_issue(
                        line_num, 0, Severity.MEDIUM, "UNWRAP_PANIC",
                        "unwrap() can panic! Handle the error properly!",
                        fix="Use match, if let, or ? operator instead",
                    )
            if re.search(r'\.expect\s*\(', line):
                # expect is slightly better but still panics
                in_test = any('#[test]' in self.lines[max(0,i):line_num] 
                             for i in range(max(0, line_num-5), line_num))
                if not in_test:
                    self._add_issue(
                        line_num, 0, Severity.LOW, "EXPECT_PANIC",
                        "expect() can still panic. Consider proper error handling.",
                    )
    
    def _check_panic(self):
        """Check for explicit panic calls."""
        for line_num, line in enumerate(self.lines, 1):
            if re.search(r'\bpanic!\s*\(', line):
                # Skip if in test
                in_test = any('#[test]' in self.lines[max(0,i):line_num] 
                             for i in range(max(0, line_num-5), line_num))
                if not in_test:
                    self._add_issue(
                        line_num, 0, Severity.MEDIUM, "EXPLICIT_PANIC",
                        "Explicit panic! Consider returning Result instead.",
                    )
            if re.search(r'\bunreachable!\s*\(', line):
                self._add_issue(
                    line_num, 0, Severity.LOW, "UNREACHABLE",
                    "unreachable! - make sure it truly is unreachable!",
                )
            if re.search(r'\bunimplemented!\s*\(', line):
                self._add_issue(
                    line_num, 0, Severity.MEDIUM, "UNIMPLEMENTED",
                    "unimplemented! found - this will panic at runtime!",
                )
            if re.search(r'\btodo!\s*\(', line):
                self._add_issue(
                    line_num, 0, Severity.MEDIUM, "TODO_MACRO",
                    "todo! macro will panic! Implement before production!",
                )
    
    def _check_transmute(self):
        """Check for transmute usage."""
        for line_num, line in enumerate(self.lines, 1):
            if re.search(r'std::mem::transmute|mem::transmute', line):
                self._add_issue(
                    line_num, 0, Severity.CRITICAL, "TRANSMUTE",
                    "transmute is EXTREMELY dangerous! Use safer alternatives!",
                    fix="Consider TryFrom/TryInto, as casting, or type-specific conversions",
                )
    
    def _check_forgetting(self):
        """Check for mem::forget usage."""
        for line_num, line in enumerate(self.lines, 1):
            if re.search(r'std::mem::forget|mem::forget', line):
                self._add_issue(
                    line_num, 0, Severity.HIGH, "MEM_FORGET",
                    "mem::forget can cause memory/resource leaks!",
                    fix="Use ManuallyDrop if you need to prevent drop",
                )
    
    def _check_raw_pointers(self):
        """Check for raw pointer operations."""
        for line_num, line in enumerate(self.lines, 1):
            if re.search(r'\*const\s+\w+|\*mut\s+\w+', line):
                self._add_issue(
                    line_num, 0, Severity.HIGH, "RAW_POINTER",
                    "Raw pointer type detected. Document safety invariants!",
                )
            if re.search(r'\.as_ptr\(\)|\.as_mut_ptr\(\)', line):
                self._add_issue(
                    line_num, 0, Severity.MEDIUM, "AS_PTR",
                    "Creating raw pointer - ensure proper lifetime management!",
                )
            if re.search(r'\*[a-z_]+\s*[=\+\-]', line):
                self._add_issue(
                    line_num, 0, Severity.HIGH, "PTR_DEREF",
                    "Raw pointer dereference - must be in unsafe block!",
                )
    
    def _check_unchecked(self):
        """Check for unchecked operations."""
        patterns = [
            (r'get_unchecked\s*\(', "GET_UNCHECKED"),
            (r'get_unchecked_mut\s*\(', "GET_UNCHECKED_MUT"),
            (r'slice_unchecked\s*\(', "SLICE_UNCHECKED"),
            (r'from_raw_parts\s*\(', "FROM_RAW_PARTS"),
            (r'from_utf8_unchecked\s*\(', "UTF8_UNCHECKED"),
        ]
        
        for line_num, line in enumerate(self.lines, 1):
            for pattern, rule_id in patterns:
                if re.search(pattern, line):
                    self._add_issue(
                        line_num, 0, Severity.HIGH, rule_id,
                        f"Unchecked operation! Caller must guarantee safety!",
                        fix="Add // SAFETY: comment with proof of validity",
                    )
    
    def _check_deprecated(self):
        """Check for deprecated patterns."""
        for line_num, line in enumerate(self.lines, 1):
            if re.search(r'try!\s*\(', line):
                self._add_issue(
                    line_num, 0, Severity.LOW, "TRY_MACRO_DEPRECATED",
                    "try! macro is deprecated. Use ? operator instead.",
                    fix="Replace try!(expr) with expr?",
                    auto_fixable=False
                )
    
    def _check_format_string(self):
        """Check for potential format string issues."""
        for line_num, line in enumerate(self.lines, 1):
            # Format! with user input
            if re.search(r'format!\s*\(\s*[a-z_]+\s*\)', line):
                self._add_issue(
                    line_num, 0, Severity.MEDIUM, "FORMAT_STRING_VAR",
                    "format! with variable format string - potential injection!",
                    fix="Use format! with static format string and {} placeholders",
                )
