# Groundskeeper Willie - Analyzer Module
# "If it compiles, it's still probably trash."

from .base_analyzer import BaseAnalyzer, Issue, Severity
from .python_analyzer import PythonAnalyzer
from .javascript_analyzer import JavaScriptAnalyzer
from .solidity_analyzer import SolidityAnalyzer
from .rust_analyzer import RustAnalyzer
from .generic_analyzer import GenericAnalyzer
from .web_analyzer import WebAnalyzer
from .infra_analyzer import InfraAnalyzer

__all__ = [
    'BaseAnalyzer',
    'Issue', 
    'Severity',
    'PythonAnalyzer',
    'JavaScriptAnalyzer',
    'SolidityAnalyzer',
    'RustAnalyzer',
    'GenericAnalyzer',
    'WebAnalyzer',
    'InfraAnalyzer',
]

# Language to analyzer mapping
ANALYZER_MAP = {
    '.py': PythonAnalyzer,
    '.js': JavaScriptAnalyzer,
    '.jsx': JavaScriptAnalyzer,
    '.ts': JavaScriptAnalyzer,
    '.tsx': JavaScriptAnalyzer,
    '.sol': SolidityAnalyzer,
    '.rs': RustAnalyzer,
    '.html': WebAnalyzer,
    '.htm': WebAnalyzer,
    '.css': WebAnalyzer,
    '.env': InfraAnalyzer,
    '.yml': InfraAnalyzer,
    '.yaml': InfraAnalyzer,
    '.json': InfraAnalyzer,
}

def get_analyzer(file_path: str) -> BaseAnalyzer:
    """Get the appropriate analyzer for a file based on extension."""
    import os
    ext = os.path.splitext(file_path)[1].lower()
    analyzer_class = ANALYZER_MAP.get(ext, GenericAnalyzer)
    return analyzer_class()
