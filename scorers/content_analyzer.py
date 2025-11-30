"""Content and HTML analysis scoring module."""

import re
from typing import Any

from bs4 import BeautifulSoup

from .base import BaseScorer, ScoreResult
from http_client import fetch_url


# Phishing-related form patterns
PHISHING_FORM_ACTIONS = [
    r'data:',
    r'javascript:',
    r'^#$',
    r'^$',
]

# Suspicious meta patterns
SUSPICIOUS_META_PATTERNS = [
    'redirect',
    'refresh',
]


class ContentAnalyzerScorer(BaseScorer):
    """
    Score based on website content analysis.
    
    Analyzes:
    - Form actions and input types
    - External resource loading patterns
    - Hidden elements
    - JavaScript redirects
    - Page title and meta tags
    - Content quality signals
    """
    
    @property
    def name(self) -> str:
        return "Content Analysis"
    
    async def _fetch_content(self, url: str) -> tuple[str, int, dict[str, str]]:
        """Fetch webpage content using shared HTTP client."""
        if not url.startswith(('http://', 'https://')):
            url = f"https://{url}"
        
        # Use shared client with connection pooling (max 2MB for content)
        return await fetch_url(url, timeout=10.0, max_content_length=2 * 1024 * 1024)
    
    def _analyze_forms(self, soup: BeautifulSoup, base_url: str) -> tuple[float, list[str], dict[str, Any]]:
        """Analyze forms for phishing patterns."""
        score_delta = 0.0
        warnings: list[str] = []
        details: dict[str, Any] = {}
        
        forms = soup.find_all('form')
        details["form_count"] = len(forms)
        
        password_inputs = soup.find_all('input', {'type': 'password'})
        details["password_fields"] = len(password_inputs)
        
        # Forms with password fields are more suspicious to analyze
        has_login_form = len(password_inputs) > 0
        details["has_login_form"] = has_login_form
        
        suspicious_forms = []
        
        for i, form in enumerate(forms):
            action = str(form.get('action', '') or '')
            method = str(form.get('method', 'get') or 'get').lower()
            
            form_info: dict[str, Any] = {
                "action": action,
                "method": method,
            }
            
            # Check for suspicious form actions
            for pattern in PHISHING_FORM_ACTIONS:
                if re.match(pattern, action):
                    warnings.append(f"Form {i+1} has suspicious action: {action or '(empty)'}")
                    score_delta -= 15
                    form_info["suspicious_action"] = True
                    break
            
            # Check if form posts to external domain
            if action and not action.startswith(('#', '/', '?')):
                if not action.startswith(base_url):
                    warnings.append(f"Form {i+1} posts to external domain")
                    score_delta -= 20
                    form_info["external_action"] = True
            
            # Check for forms without HTTPS
            if action.startswith('http://'):
                warnings.append(f"Form {i+1} posts to insecure HTTP endpoint")
                score_delta -= 20
                form_info["insecure_action"] = True
            
            # Check for hidden inputs (often used in phishing)
            hidden_inputs = form.find_all('input', {'type': 'hidden'})
            if len(hidden_inputs) > 5:
                warnings.append(f"Form {i+1} has many hidden inputs ({len(hidden_inputs)})")
                score_delta -= 5
            
            suspicious_forms.append(form_info)
        
        details["forms"] = suspicious_forms
        
        return score_delta, warnings, details
    
    def _analyze_scripts(self, soup: BeautifulSoup, html: str) -> tuple[float, list[str], dict[str, Any]]:
        """Analyze JavaScript for suspicious patterns."""
        score_delta = 0.0
        warnings: list[str] = []
        details: dict[str, Any] = {}
        
        scripts = soup.find_all('script')
        details["script_count"] = len(scripts)
        
        inline_scripts = [s for s in scripts if not s.get('src')]
        details["inline_script_count"] = len(inline_scripts)
        
        # Check for suspicious JavaScript patterns
        suspicious_js_patterns = [
            (r'document\.write\s*\(', "document.write usage (potential injection)"),
            (r'eval\s*\(', "eval() usage (code obfuscation)"),
            (r'unescape\s*\(', "unescape() usage (potential obfuscation)"),
            (r'fromCharCode', "fromCharCode usage (potential obfuscation)"),
            (r'window\.location\s*=', "JavaScript redirect"),
            (r'location\.href\s*=', "JavaScript redirect"),
            (r'location\.replace\s*\(', "JavaScript redirect"),
            (r'atob\s*\(', "Base64 decoding (potential obfuscation)"),
            (r'\\x[0-9a-fA-F]{2}', "Hex-encoded strings"),
        ]
        
        found_patterns = []
        for pattern, description in suspicious_js_patterns:
            if re.search(pattern, html, re.IGNORECASE):
                found_patterns.append(description)
                score_delta -= 5
        
        if found_patterns:
            details["suspicious_js_patterns"] = found_patterns
            if len(found_patterns) >= 3:
                warnings.append(f"Multiple suspicious JavaScript patterns: {', '.join(found_patterns[:3])}")
            else:
                warnings.append(f"Suspicious JavaScript: {', '.join(found_patterns)}")
        
        # Check for very long inline scripts (often obfuscated)
        for script in inline_scripts:
            if script.string and len(script.string) > 5000:
                if re.search(r'^[A-Za-z0-9+/=]{1000,}', script.string):
                    warnings.append("Contains large encoded/obfuscated script block")
                    score_delta -= 15
                    break
        
        return score_delta, warnings, details
    
    def _analyze_meta_and_redirects(self, soup: BeautifulSoup) -> tuple[float, list[str], dict[str, Any]]:
        """Analyze meta tags and redirects."""
        score_delta = 0.0
        warnings: list[str] = []
        details: dict[str, Any] = {}
        
        # Check title
        title = soup.find('title')
        title_text = title.get_text().strip() if title else ""
        details["title"] = title_text
        
        if not title_text:
            warnings.append("Page has no title")
            score_delta -= 10
        elif len(title_text) < 3:
            warnings.append("Page has very short title")
            score_delta -= 5
        
        # Check meta refresh (auto-redirect)
        meta_refresh = soup.find('meta', {'http-equiv': re.compile(r'refresh', re.I)})
        if meta_refresh:
            content = meta_refresh.get('content', '')
            warnings.append(f"Page has meta refresh redirect")
            score_delta -= 15
            details["meta_refresh"] = content
        
        # Check for multiple redirects in noscript
        noscript = soup.find('noscript')
        if noscript:
            noscript_meta = noscript.find('meta', {'http-equiv': re.compile(r'refresh', re.I)})
            if noscript_meta:
                warnings.append("Hidden redirect in noscript tag")
                score_delta -= 20
        
        # Check description meta
        meta_desc = soup.find('meta', {'name': 'description'})
        if meta_desc:
            content = str(meta_desc.get('content', '') or '')
            details["meta_description"] = content[:200]
        
        return score_delta, warnings, details
    
    def _analyze_hidden_elements(self, soup: BeautifulSoup) -> tuple[float, list[str], dict[str, Any]]:
        """Check for hidden elements that might be deceptive."""
        score_delta = 0.0
        warnings: list[str] = []
        details: dict[str, Any] = {}
        
        # Check for hidden divs with content
        hidden_elements = soup.find_all(style=re.compile(r'display:\s*none|visibility:\s*hidden', re.I))
        details["hidden_element_count"] = len(hidden_elements)
        
        # Check for iframes (often used for clickjacking)
        iframes = soup.find_all('iframe')
        details["iframe_count"] = len(iframes)
        
        for iframe in iframes:
            src = str(iframe.get('src', '') or '')
            style = str(iframe.get('style', '') or '')
            
            # Hidden iframes are very suspicious
            if 'display:none' in style or 'visibility:hidden' in style:
                warnings.append("Hidden iframe detected")
                score_delta -= 25
            elif iframe.get('width') == '0' or iframe.get('height') == '0':
                warnings.append("Zero-size iframe detected")
                score_delta -= 25
            elif 'opacity:0' in style:
                warnings.append("Transparent iframe detected")
                score_delta -= 25
        
        return score_delta, warnings, details
    
    def _analyze_links(self, soup: BeautifulSoup, base_url: str) -> tuple[float, list[str], dict[str, Any]]:
        """Analyze links on the page."""
        score_delta = 0.0
        warnings: list[str] = []
        details: dict[str, Any] = {}
        
        links = soup.find_all('a', href=True)
        details["link_count"] = len(links)
        
        external_links = 0
        suspicious_links = 0
        
        for link in links:
            href = str(link.get('href', '') or '')
            
            # Count external links
            if href.startswith('http') and not href.startswith(base_url):
                external_links += 1
            
            # Check for javascript: links
            if href.startswith('javascript:'):
                suspicious_links += 1
            
            # Check for data: links
            if href.startswith('data:'):
                suspicious_links += 1
                warnings.append("Page contains data: URI links")
                score_delta -= 10
        
        details["external_links"] = external_links
        details["suspicious_links"] = suspicious_links
        
        # High ratio of external links can be suspicious
        if links and external_links / len(links) > 0.8:
            warnings.append("Most links point to external sites")
            score_delta -= 10
        
        return score_delta, warnings, details
    
    async def analyze(self, url: str) -> ScoreResult:
        """Analyze webpage content."""
        score = 100.0
        warnings: list[str] = []
        details: dict[str, Any] = {"url": url}
        
        if not url.startswith(('http://', 'https://')):
            url = f"https://{url}"
        
        try:
            html, status_code, headers = await self._fetch_content(url)
            details["status_code"] = status_code
            details["content_length"] = len(html)
            
            # Check status code
            if status_code >= 400:
                return self._create_result(
                    score=30.0,
                    details=details,
                    errors=[f"HTTP error: {status_code}"],
                )
            
            soup = BeautifulSoup(html, 'html.parser')
            
            # Run all analyses
            form_delta, form_warnings, form_details = self._analyze_forms(soup, url)
            score += form_delta
            warnings.extend(form_warnings)
            details.update(form_details)
            
            script_delta, script_warnings, script_details = self._analyze_scripts(soup, html)
            score += script_delta
            warnings.extend(script_warnings)
            details.update(script_details)
            
            meta_delta, meta_warnings, meta_details = self._analyze_meta_and_redirects(soup)
            score += meta_delta
            warnings.extend(meta_warnings)
            details.update(meta_details)
            
            hidden_delta, hidden_warnings, hidden_details = self._analyze_hidden_elements(soup)
            score += hidden_delta
            warnings.extend(hidden_warnings)
            details.update(hidden_details)
            
            link_delta, link_warnings, link_details = self._analyze_links(soup, url)
            score += link_delta
            warnings.extend(link_warnings)
            details.update(link_details)
            
            # Check content type
            content_type = headers.get('content-type', '')
            details["content_type"] = content_type
            
            if 'text/html' not in content_type.lower():
                warnings.append(f"Unexpected content type: {content_type}")
                score -= 10
            
            # Very short pages are suspicious
            if len(html) < 500:
                warnings.append("Page has very little content")
                score -= 15
            
            return self._create_result(
                score=max(0, min(100, score)),
                details=details,
                warnings=warnings,
            )
            
        except TimeoutError:
            return self._create_result(
                score=40.0,
                details=details,
                errors=["Request timeout - site may be slow or unresponsive"],
            )
        except ConnectionError as e:
            return self._create_result(
                score=30.0,
                details=details,
                errors=[f"Connection failed: {str(e)}"],
            )
        except ValueError as e:
            # Content too large
            return self._create_result(
                score=50.0,
                details=details,
                warnings=[str(e)],
            )
        except Exception as e:
            return self._create_result(
                score=35.0,
                details=details,
                errors=[f"Content analysis failed: {str(e)}"],
            )
