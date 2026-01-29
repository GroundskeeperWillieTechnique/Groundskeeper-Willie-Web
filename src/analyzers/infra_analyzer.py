"""
Infra Analyzer - Willie's System & Config Auditor
"A leaky configuration is just a welcome mat for burglars!"
"""

import re
import os
from .base_analyzer import BaseAnalyzer, Severity


class InfraAnalyzer(BaseAnalyzer):
    """Analyzer for configuration files like .env, YAML, and JSON."""
    
    name = "Infra"
    extensions = ['.env', '.yml', '.yaml', '.json', '.conf', '.config']
    
    def _run_language_checks(self):
        """Run infrastructure-specific security and health checks."""
        self._check_db_connectivity()
        self._check_insecure_ports()
        self._check_debug_mode()
        self._check_permissions_config()
        self._check_missing_essential_vars()
        
    def _check_db_connectivity(self):
        """Check for database connection strings and security."""
        db_patterns = [
            (r'mongodb\+srv://[^:]+:[^@]+@', "MONGODB_SRV_FOUND"),
            (r'postgres://[^:]+:[^@]+@', "POSTGRES_URL_FOUND"),
            (r'mysql://[^:]+:[^@]+@', "MYSQL_URL_FOUND"),
            (r'redis://[^:]+:[^@]+@', "REDIS_URL_FOUND"),
        ]
        
        for line_num, line in enumerate(self.lines, 1):
            for pattern, rule_id in db_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    # Check if it's in a production-looking config but uses localhost
                    if 'localhost' in line.lower() or '127.0.0.1' in line:
                        self._add_issue(
                            line_num, 0, Severity.MEDIUM, "LOCAL_DB_IN_CONFIG",
                            "Using localhost for a DB connection string? Is this project a hobby or a business?!",
                            fix="Use a remote DB host or environment variable"
                        )
                    
                    # Check for hardcoded credentials (already in base, but emphasizing here)
                    if ':' in line.split('//')[-1] and '@' in line:
                        self._add_issue(
                            line_num, 0, Severity.CRITICAL, "HARDCODED_DB_CREDS",
                            "Hardcoded DB credentials! Ye've basically handed the keys to the castle to the Vikings!",
                            fix="Use environment variables for username and password"
                        )

    def _check_insecure_ports(self):
        """Check for insecure port configurations."""
        insecure_ports = {
            '21': 'FTP',
            '23': 'Telnet',
            '80': 'HTTP',
            '3306': 'MySQL (Public)',
            '6379': 'Redis (Public)',
        }
        
        for line_num, line in enumerate(self.lines, 1):
            for port, service in insecure_ports.items():
                if f':{port}' in line and not ('localhost' in line or '127.0.0.1' in line):
                    self._add_issue(
                        line_num, 0, Severity.HIGH, f"INSECURE_PORT_{port}",
                        f"Potentially exposing {service} on port {port}! Are ye TRYING to get boarded?!",
                        fix=f"Close port {port} or use SSH tunneling"
                    )

    def _check_debug_mode(self):
        """Check if debug or development modes are enabled in production configs."""
        debug_patterns = [
            (r'DEBUG\s*=\s*(True|true|1)', "DEBUG_MODE_ON"),
            (r'NODE_ENV\s*=\s*[\'"]?development[\'"]?', "DEV_ENV_IN_PROD"),
        ]
        
        for line_num, line in enumerate(self.lines, 1):
            for pattern, rule_id in debug_patterns:
                if re.search(pattern, line):
                    self._add_issue(
                        line_num, 0, Severity.HIGH, rule_id,
                        "Debug/Dev mode enabled! In production, this is a disaster waiting to happen!",
                        fix="Set to False or 'production' for deployment"
                    )

    def _check_permissions_config(self):
        """Check for overly permissive file/access settings."""
        if any('0.0.0.0' in line for line in self.lines):
            for line_num, line in enumerate(self.lines, 1):
                if '0.0.0.0' in line:
                    self._add_issue(
                        line_num, 0, Severity.MEDIUM, "BIND_ALL_INTERFACES",
                        "Binding to 0.0.0.0? Ye're shouting yer secrets to the whole wide world!",
                        fix="Bind to 127.0.0.1 or a specific internal IP"
                    )

    def _check_missing_essential_vars(self):
        """Check if essential environment variables are missing (in .env files)."""
        if self.file_path.endswith('.env'):
            essential = ['SECRET_KEY', 'DATABASE_URL', 'PORT', 'NODE_ENV']
            content_keys = [line.split('=')[0].strip() for line in self.lines if '=' in line]
            
            for key in essential:
                if key not in content_keys:
                    self._add_issue(
                        1, 0, Severity.INFO, f"MISSING_{key}",
                        f"Essential variable '{key}' seems to be missing from yer .env file.",
                    )
