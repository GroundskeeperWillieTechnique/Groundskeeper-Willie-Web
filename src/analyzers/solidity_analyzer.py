"""
Solidity Analyzer - Willie's Smart Contract Auditor
"Ye want to handle OTHER PEOPLE'S MONEY with THIS code?!"
"""

import re
from .base_analyzer import BaseAnalyzer, Severity


class SolidityAnalyzer(BaseAnalyzer):
    """Analyzer for Solidity smart contract files."""
    
    name = "Solidity"
    extensions = ['.sol']
    
    def _run_language_checks(self):
        """Run Solidity-specific security checks."""
        self._check_reentrancy()
        self._check_tx_origin()
        self._check_delegatecall()
        self._check_selfdestruct()
        self._check_overflow()
        self._check_visibility()
        self._check_timestamp()
        self._check_gas_limit()
        self._check_unchecked_call()
        self._check_frontrunning()
        self._check_floating_pragma()
    
    def _check_reentrancy(self):
        """Check for reentrancy vulnerabilities."""
        # Look for external calls followed by state changes
        for line_num, line in enumerate(self.lines, 1):
            if re.search(r'\.call\{.*value.*\}|\.transfer\(|\.send\(', line):
                # Check if there are state changes after
                remaining_code = '\n'.join(self.lines[line_num:line_num+5])
                if re.search(r'=\s*[^=]', remaining_code):
                    self._add_issue(
                        line_num, 0, Severity.CRITICAL, "REENTRANCY",
                        "REENTRANCY RISK! External call before state change!",
                        fix="Follow Checks-Effects-Interactions pattern. Update state BEFORE external calls.",
                    )
        
        # Check for lack of reentrancy guard on payable functions
        for line_num, line in enumerate(self.lines, 1):
            if re.search(r'function\s+\w+\s*\([^)]*\)\s*(external|public)\s+payable', line):
                # Check for nonReentrant modifier
                if 'nonReentrant' not in line:
                    func_block = '\n'.join(self.lines[line_num-1:line_num+10])
                    if '.call' in func_block or 'transfer' in func_block:
                        self._add_issue(
                            line_num, 0, Severity.HIGH, "MISSING_REENTRANCY_GUARD",
                            "Payable function without nonReentrant modifier!",
                            fix="Add 'nonReentrant' modifier from OpenZeppelin ReentrancyGuard",
                        )
    
    def _check_tx_origin(self):
        """Check for tx.origin usage (phishing vulnerability)."""
        for line_num, line in enumerate(self.lines, 1):
            if re.search(r'tx\.origin', line):
                self._add_issue(
                    line_num, 0, Severity.CRITICAL, "TX_ORIGIN",
                    "tx.origin is PHISHING VULNERABLE! Use msg.sender!",
                    fix="Replace tx.origin with msg.sender",
                )
    
    def _check_delegatecall(self):
        """Check for dangerous delegatecall usage."""
        for line_num, line in enumerate(self.lines, 1):
            if re.search(r'\.delegatecall\(', line):
                self._add_issue(
                    line_num, 0, Severity.CRITICAL, "DELEGATECALL",
                    "delegatecall executes external code in YOUR context!",
                    fix="Ensure delegatecall target is trusted and immutable",
                )
    
    def _check_selfdestruct(self):
        """Check for selfdestruct usage."""
        for line_num, line in enumerate(self.lines, 1):
            if re.search(r'selfdestruct\s*\(', line):
                self._add_issue(
                    line_num, 0, Severity.HIGH, "SELFDESTRUCT",
                    "selfdestruct allows contract to be destroyed!",
                    fix="Ensure proper access control on selfdestruct",
                )
    
    def _check_overflow(self):
        """Check for potential integer overflow/underflow."""
        # Check Solidity version
        uses_old_solidity = any(
            re.search(r'pragma\s+solidity\s+[\^~]?0\.[0-7]\.', line) 
            for line in self.lines
        )
        
        if uses_old_solidity:
            # Check if SafeMath is used
            uses_safemath = any('SafeMath' in line for line in self.lines)
            
            for line_num, line in enumerate(self.lines, 1):
                if re.search(r'[+\-*/]=?', line) and 'uint' in ''.join(self.lines[max(0,line_num-10):line_num]):
                    if not uses_safemath:
                        self._add_issue(
                            line_num, 0, Severity.HIGH, "INTEGER_OVERFLOW",
                            "Math operation on uint without SafeMath (Solidity <0.8)!",
                            fix="Use SafeMath or upgrade to Solidity 0.8+",
                        )
    
    def _check_visibility(self):
        """Check for missing visibility modifiers."""
        for line_num, line in enumerate(self.lines, 1):
            if re.search(r'^\s*function\s+\w+\s*\([^)]*\)\s*{', line):
                # No visibility modifier before {
                self._add_issue(
                    line_num, 0, Severity.HIGH, "MISSING_VISIBILITY",
                    "Function without visibility modifier! Defaults to public!",
                    fix="Explicitly declare public, external, internal, or private",
                )
            
            # Check for public state variables that should be private
            if re.search(r'^\s*(uint|int|address|bool|string|bytes)\s+(public|)\s+\w+\s*;', line):
                if 'private' not in line and 'internal' not in line:
                    self._add_issue(
                        line_num, 0, Severity.LOW, "PUBLIC_STATE",
                        "State variable is public. Intended?",
                    )
    
    def _check_timestamp(self):
        """Check for block.timestamp manipulation risk."""
        for line_num, line in enumerate(self.lines, 1):
            if re.search(r'block\.timestamp|now\b', line):
                if re.search(r'(==|<|>|<=|>=)', line):
                    self._add_issue(
                        line_num, 0, Severity.MEDIUM, "TIMESTAMP_MANIPULATION",
                        "block.timestamp can be manipulated by miners (+/- 15s)!",
                        fix="Don't use for precise timing or randomness",
                    )
    
    def _check_gas_limit(self):
        """Check for patterns that could hit gas limits."""
        for line_num, line in enumerate(self.lines, 1):
            # Unbounded loops
            if re.search(r'for\s*\([^)]+\.length[^)]+\)', line):
                self._add_issue(
                    line_num, 0, Severity.HIGH, "UNBOUNDED_LOOP",
                    "Loop over dynamic array could exceed gas limit!",
                    fix="Use pagination or limit iterations",
                )
            
            # Transfer in loop
            if re.search(r'for.*{', line):
                loop_block = '\n'.join(self.lines[line_num:line_num+10])
                if re.search(r'\.transfer\(|\.send\(|\.call\{', loop_block):
                    self._add_issue(
                        line_num, 0, Severity.HIGH, "TRANSFER_IN_LOOP",
                        "External calls in loop = DoS vector!",
                        fix="Use pull-over-push pattern",
                    )
    
    def _check_unchecked_call(self):
        """Check for unchecked low-level calls."""
        for line_num, line in enumerate(self.lines, 1):
            if re.search(r'\.call\{?[^}]*\}?\s*\([^)]*\)\s*;', line):
                if 'require' not in line and '(success' not in line and '= ' not in line:
                    self._add_issue(
                        line_num, 0, Severity.HIGH, "UNCHECKED_CALL",
                        "Low-level call without checking return value!",
                        fix="(bool success, ) = addr.call{...}(); require(success);",
                    )
            
            if re.search(r'\.send\s*\([^)]*\)\s*;', line):
                if 'require' not in line and 'assert' not in line and '= ' not in line:
                    self._add_issue(
                        line_num, 0, Severity.HIGH, "UNCHECKED_SEND",
                        "send() return value not checked!",
                        fix="Use transfer() or check send() return value",
                    )
    
    def _check_frontrunning(self):
        """Check for frontrunning vulnerabilities."""
        for line_num, line in enumerate(self.lines, 1):
            # Check for approve patterns vulnerable to frontrunning
            if re.search(r'\.approve\s*\(', line):
                self._add_issue(
                    line_num, 0, Severity.MEDIUM, "APPROVE_FRONTRUN",
                    "approve() is frontrunnable! Use increaseAllowance().",
                    fix="Use OpenZeppelin's increaseAllowance/decreaseAllowance",
                )
    
    def _check_floating_pragma(self):
        """Check for floating pragma."""
        for line_num, line in enumerate(self.lines, 1):
            if re.search(r'pragma\s+solidity\s+[\^~]', line):
                self._add_issue(
                    line_num, 0, Severity.LOW, "FLOATING_PRAGMA",
                    "Floating pragma. Lock to specific version for production!",
                    fix="Use exact version: pragma solidity 0.8.19;",
                )
