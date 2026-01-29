"""
Web Analyzer - Willie's Frontend Optimization Tool
"If yer website loads slower than a snail on a salt lick, ye've failed!"
"""

import re
import os
from .base_analyzer import BaseAnalyzer, Severity


class WebAnalyzer(BaseAnalyzer):
    """Analyzer for HTML and CSS files."""
    
    name = "Web"
    extensions = ['.html', '.css', '.htm']
    
    def _run_language_checks(self):
        """Run web-specific optimization and health checks."""
        ext = os.path.splitext(self.file_path)[1].lower()
        
        if ext in ['.html', '.htm']:
            self._check_html_health()
        elif ext == '.css':
            self._check_css_health()
            
    def _check_html_health(self):
        """Perform HTML-specific checks."""
        self._check_image_formats()
        self._check_alt_text()
        self._check_inline_styles()
        self._check_deprecated_tags()
        
    def _check_css_health(self):
        """Perform CSS-specific checks."""
        self._check_duplicate_selectors()
        self._check_important_usage()
        self._check_web_fonts()

    def _check_image_formats(self):
        """Check for unoptimized image formats in HTML."""
        unoptimized_pattern = r'src=["\']([^"\']+\.(jpg|jpeg|png|gif))["\']'
        for line_num, line in enumerate(self.lines, 1):
            matches = re.finditer(unoptimized_pattern, line, re.IGNORECASE)
            for match in matches:
                img_path = match.group(1)
                self._add_issue(
                    line_num, match.start(), Severity.MEDIUM, "UNOPTIMIZED_IMAGE_FORMAT",
                    f"Found unoptimized image format: {img_path}. Use WebP or AVIF instead!",
                    fix=f"Convert {img_path} to .webp or .avif"
                )

    def _check_alt_text(self):
        """Check for missing alt text in img tags."""
        img_pattern = r'<img\b(?![^>]*\balt=)[^>]*>'
        for line_num, line in enumerate(self.lines, 1):
            if re.search(img_pattern, line, re.IGNORECASE):
                self._add_issue(
                    line_num, 0, Severity.LOW, "MISSING_ALT_TEXT",
                    "Image tag is missing an 'alt' attribute! Lazy dev work, laddie!",
                    fix='Add alt="Description of image"'
                )

    def _check_inline_styles(self):
        """Check for inline styles in HTML."""
        for line_num, line in enumerate(self.lines, 1):
            if ' style="' in line.lower() or " style='" in line.lower():
                self._add_issue(
                    line_num, 0, Severity.LOW, "INLINE_STYLE",
                    "Inline styles detected! Use a CSS file like a professional!",
                    auto_fixable=False
                )

    def _check_deprecated_tags(self):
        """Check for deprecated HTML tags."""
        deprecated = ['font', 'center', 'strike', 'big', 'basefont']
        for line_num, line in enumerate(self.lines, 1):
            for tag in deprecated:
                if f'<{tag}' in line.lower():
                    self._add_issue(
                        line_num, 0, Severity.MEDIUM, "DEPRECATED_HTML_TAG",
                        f"Found deprecated tag: <{tag}>. It's not 1999 anymore!"
                    )

    def _check_duplicate_selectors(self):
        """Check for duplicate selectors in CSS."""
        selector_pattern = r'^([^{]+)\{'
        seen_selectors = {}
        for line_num, line in enumerate(self.lines, 1):
            match = re.match(selector_pattern, line.strip())
            if match:
                selector = match.group(1).strip()
                if selector in seen_selectors:
                    prev_line = seen_selectors[selector]
                    self._add_issue(
                        line_num, 0, Severity.MEDIUM, "DUPLICATE_CSS_SELECTOR",
                        f"Duplicate selector '{selector}' found! (Already defined on line {prev_line})",
                        fix="Merge rules or remove duplicate"
                    )
                else:
                    seen_selectors[selector] = line_num

    def _check_important_usage(self):
        """Check for !important usage in CSS."""
        for line_num, line in enumerate(self.lines, 1):
            if '!important' in line.lower():
                self._add_issue(
                    line_num, 0, Severity.LOW, "CSS_IMPORTANT_USAGE",
                    "Using !important? Fix yer specificity instead of taking the easy way out!",
                )

    def _check_web_fonts(self):
        """Check for web font imports that might slow down loading."""
        if any('@import' in line and 'fonts.googleapis.com' in line for line in self.lines):
            self._add_issue(
                1, 0, Severity.INFO, "GOOGLE_FONTS_IMPORT",
                "Google Fonts @import detected. Consider self-hosting or preloading for better performance.",
            )
