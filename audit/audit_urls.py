#!/usr/bin/env python3
"""
NAV KING Audit URL Scanner v1.2
Security hardened with proper streaming, expanded tool detection, safe redirects.

Features:
- Stream-based content reading with true 1MB limit
- Expanded explicit_tool_page detection rules
- Safe cross-domain redirect handling
- Comprehensive review_reason_code tracking
- explicit_tool_page result field for observability
"""

import json
import time
import re
from datetime import datetime
from typing import Dict, List, Any, Tuple, Optional
from urllib.parse import urlparse

try:
    import requests
    from bs4 import BeautifulSoup
except ImportError:
    print("Error: Required packages not installed.")
    print("Please run: pip install requests beautifulsoup4")
    raise SystemExit(1)


class URLAuditor:
    TIMEOUT = 10
    MAX_RETRIES = 2
    REQUEST_DELAY = 0.7
    USER_AGENT = "NAV-KING-Audit/1.2"
    MAX_CONTENT_SIZE = 1048576

    SCORE_RULES = {
        "https": 5,
        "http_200": 20,
        "no_redirect": 5,
        "reasonable_redirect": 3,
        "keywords_match": 20,
        "title_match": 10,
        "description_match": 5,
        "explicit_tool_page": 10,
        "fast_response": 10,
        "medium_response": 5,
        "not_found": -100,
        "server_error": -100,
        "dns_failed": -100,
        "parked_domain": -100,
        "task_mismatch": -80,
        "malicious_redirect": -100,
    }

    SCORE_PASS = 80
    SCORE_REVIEW = 50

    CONFIDENCE_HIGH = "HIGH"
    CONFIDENCE_MEDIUM = "MEDIUM"
    CONFIDENCE_LOW = "LOW"

    TOOL_PATH_PATTERNS = [
        r"/compress[-_]pdf",
        r"/compress[-_]image",
        r"/pdf[-_]to[-_]word",
        r"/word[-_]to[-_]pdf",
        r"/merge[-_]pdf",
        r"/split[-_]pdf",
        r"/image[-_]resize",
        r"/remove[-_]background",
        r"/video[-_]to[-_]gif",
        r"/audio[-_]converter",
        r"/audio[-_]to[-_]mp3",
        r"/transcribe",
        r"/ocr",
        r"/converter",
        r"/generator",
        r"/compress",
        r"/translate",
        r"/cut[-_]",
        r"/merge",
        r"/extract",
        r"/convert",
    ]

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": self.USER_AGENT})

    def run_audit(self, candidates_file: str, output_file: str) -> bool:
        print(f"[AUDIT] Loading candidates from {candidates_file}...")

        try:
            with open(candidates_file, "r", encoding="utf-8") as f:
                data = json.load(f)
        except FileNotFoundError:
            print(f"ERROR: {candidates_file} not found")
            return False
        except json.JSONDecodeError:
            print(f"ERROR: {candidates_file} is not valid JSON")
            return False

        candidates = data.get("candidates", [])
        print(f"[AUDIT] Found {len(candidates)} candidates to audit")

        results = []
        summary = {"total": 0, "pass": 0, "review": 0, "fail": 0}

        for idx, candidate in enumerate(candidates):
            cid = candidate.get("candidate_id", "UNKNOWN")
            url = candidate.get("url", "")
            print(f"\n[{idx + 1}/{len(candidates)}] {cid}: {url}")

            result = self.audit_url(candidate)
            results.append(result)

            verdict = result.get("verdict", "FAIL")
            summary[verdict.lower()] += 1
            summary["total"] += 1

            if idx < len(candidates) - 1:
                time.sleep(self.REQUEST_DELAY)

        print("\n[AUDIT] Generating output files...")
        self.generate_audit_results(results, summary, output_file)
        self.generate_approved(results)
        self.generate_rejected(results)

        print("\n[AUDIT] Summary:")
        print(f"  Total: {summary['total']}")
        print(f"  PASS: {summary['pass']}")
        print(f"  REVIEW: {summary['review']}")
        print(f"  FAIL: {summary['fail']}")

        return True

    def audit_url(self, candidate: Dict[str, Any]) -> Dict[str, Any]:
        candidate_id = candidate.get("candidate_id", "UNKNOWN")
        task_id = candidate.get("task_id", "")
        url = candidate.get("url", "").strip()
        expected_keywords = candidate.get("expected_keywords", [])

        result = {
            "candidate_id": candidate_id,
            "task_id": task_id,
            "url": url,
            "http_status": None,
            "final_url": url,
            "response_time_ms": 0,
            "https": url.startswith("https://"),
            "redirected": False,
            "redirect_reason": "",
            "title": "",
            "meta_description": "",
            "content_preview": "",
            "task_match": "FAIL",
            "ads_detected": "unknown",
            "login_wall": "unknown",
            "forced_app": "unknown",
            "network_error_type": None,
            "automation_blocked": False,
            "explicit_tool_page": False,
            "score": 0,
            "confidence": self.CONFIDENCE_LOW,
            "review_reason_code": None,
            "verdict": "FAIL",
            "reason": "Audit started",
        }

        score = 0

        if not url or not url.startswith("https://"):
            result["reason"] = "URL must be HTTPS"
            result["confidence"] = self.CONFIDENCE_HIGH
            result["review_reason_code"] = "INVALID_URL"
            return result

        if not self._is_valid_url(url):
            result["reason"] = "Invalid URL format"
            result["confidence"] = self.CONFIDENCE_HIGH
            result["review_reason_code"] = "INVALID_URL"
            return result

        score += self.SCORE_RULES["https"]

        response, response_time, error_type = self._fetch_url_streaming(url)

        if response is None:
            result["network_error_type"] = error_type
            result["reason"] = f"Network error: {error_type}"

            if error_type == "DNS_FAILED":
                result["verdict"] = "FAIL"
                result["confidence"] = self.CONFIDENCE_HIGH
                result["review_reason_code"] = "DNS_FAILED"
                score += self.SCORE_RULES["dns_failed"]
            elif error_type == "INVALID_URL":
                result["verdict"] = "FAIL"
                result["confidence"] = self.CONFIDENCE_HIGH
                result["review_reason_code"] = "INVALID_URL"
                score = -100
            else:
                result["verdict"] = "REVIEW"
                result["confidence"] = self.CONFIDENCE_MEDIUM
                result["review_reason_code"] = error_type
                score = -20

            result["score"] = max(0, score)
            return result

        result["response_time_ms"] = int(response_time * 1000)
        result["final_url"] = response.url
        result["http_status"] = response.status_code

        if response.status_code == 404:
            result["reason"] = "HTTP 404 Not Found"
            result["verdict"] = "FAIL"
            result["confidence"] = self.CONFIDENCE_HIGH
            result["review_reason_code"] = "HTTP_404"
            score += self.SCORE_RULES["not_found"]
            result["score"] = max(0, score)
            return result

        if response.status_code == 410:
            result["reason"] = "HTTP 410 Gone"
            result["verdict"] = "FAIL"
            result["confidence"] = self.CONFIDENCE_HIGH
            result["review_reason_code"] = "HTTP_410"
            score += self.SCORE_RULES["not_found"]
            result["score"] = max(0, score)
            return result

        if response.status_code >= 500:
            result["reason"] = f"Server error: HTTP {response.status_code}"
            result["verdict"] = "FAIL"
            result["confidence"] = self.CONFIDENCE_HIGH
            result["review_reason_code"] = "SERVER_ERROR"
            score += self.SCORE_RULES["server_error"]
            result["score"] = max(0, score)
            return result

        if response.status_code == 401:
            result["reason"] = "HTTP 401 Unauthorized - authentication required"
            result["verdict"] = "REVIEW"
            result["automation_blocked"] = True
            result["review_reason_code"] = "AUTH_REQUIRED"
            result["confidence"] = self.CONFIDENCE_MEDIUM
            return result

        if response.status_code == 403:
            result["reason"] = "HTTP 403 Forbidden - access blocked"
            result["verdict"] = "REVIEW"
            result["automation_blocked"] = True
            result["review_reason_code"] = "AUTOMATION_BLOCKED"
            result["confidence"] = self.CONFIDENCE_MEDIUM
            return result

        if response.status_code == 429:
            result["reason"] = "HTTP 429 Rate Limited"
            result["verdict"] = "REVIEW"
            result["automation_blocked"] = True
            result["review_reason_code"] = "RATE_LIMITED"
            result["confidence"] = self.CONFIDENCE_MEDIUM
            return result

        if response.history:
            result["redirected"] = True
            redirect_analysis = self._analyze_redirect_v12(
                url,
                response.url,
                response.text,
            )

            if redirect_analysis["verdict"] == "FAIL":
                result["reason"] = redirect_analysis["reason"]
                result["verdict"] = "FAIL"
                result["confidence"] = self.CONFIDENCE_HIGH
                result["review_reason_code"] = "MALICIOUS_REDIRECT"
                score += self.SCORE_RULES["malicious_redirect"]
                result["score"] = max(0, score)
                return result

            if redirect_analysis["verdict"] == "REVIEW":
                result["reason"] = redirect_analysis["reason"]
                result["task_match"] = "REVIEW"
                result["redirect_reason"] = redirect_analysis["code"]
                result["review_reason_code"] = redirect_analysis["code"]
                score += self.SCORE_RULES["reasonable_redirect"]
            else:
                result["redirect_reason"] = redirect_analysis["code"]
                score += self.SCORE_RULES["no_redirect"]
        else:
            score += self.SCORE_RULES["no_redirect"]

        if response.status_code == 200:
            score += self.SCORE_RULES["http_200"]

        if result["response_time_ms"] < 2000:
            score += self.SCORE_RULES["fast_response"]
        elif result["response_time_ms"] < 5000:
            score += self.SCORE_RULES["medium_response"]

        content_text = ""

        try:
            if response.text:
                soup = BeautifulSoup(response.text, "html.parser")

                title_tag = soup.find("title")
                if title_tag:
                    result["title"] = title_tag.get_text().strip()

                meta_desc = soup.find("meta", attrs={"name": "description"})
                if meta_desc:
                    result["meta_description"] = meta_desc.get("content", "").strip()

                body_text = soup.get_text(" ", strip=True)[:500]
                result["content_preview"] = body_text
                content_text = body_text.lower()

                is_404_page = self._detect_404_page_v11(
                    soup,
                    body_text,
                    result["http_status"],
                )
                is_parked_page = self._detect_parked_domain(soup, body_text)

                ads_evidence = self._detect_ads_v11(soup, body_text)
                login_evidence = self._detect_login_wall_v11(soup, body_text)
                app_evidence = self._detect_forced_app_v11(soup, body_text)

                result["ads_detected"] = "true" if ads_evidence else "unknown"
                result["login_wall"] = "true" if login_evidence else "unknown"
                result["forced_app"] = "true" if app_evidence else "unknown"

                if is_404_page:
                    result["reason"] = "Detected as 404 page"
                    result["verdict"] = "FAIL"
                    result["confidence"] = self.CONFIDENCE_MEDIUM
                    result["review_reason_code"] = "PAGE_404"
                    score += self.SCORE_RULES["not_found"]
                    result["score"] = max(0, score)
                    return result

                if is_parked_page:
                    result["reason"] = "Detected as parked domain"
                    result["verdict"] = "FAIL"
                    result["confidence"] = self.CONFIDENCE_MEDIUM
                    result["review_reason_code"] = "PARKED_DOMAIN"
                    score += self.SCORE_RULES["parked_domain"]
                    result["score"] = max(0, score)
                    return result

                if login_evidence == "STRONG":
                    result["login_wall"] = "true"
                    result["verdict"] = "REVIEW"
                    result["reason"] = "Strong login wall detected"
                    result["review_reason_code"] = "AUTH_REQUIRED"
                    result["confidence"] = self.CONFIDENCE_MEDIUM
                    return result

        except Exception as exc:
            result["reason"] = f"Content parsing error: {exc}"
            result["review_reason_code"] = "PARSE_ERROR"

        title = result["title"].lower()
        description = result["meta_description"].lower()
        content = content_text
        final_path = urlparse(result["final_url"]).path.lower()

        if not expected_keywords:
            task_match = self._check_task_match_no_keywords(
                task_id,
                title,
                content,
                final_path,
            )
            result["confidence"] = self.CONFIDENCE_LOW
        else:
            task_match = self._check_task_match_v11(
                task_id,
                expected_keywords,
                title,
                description,
                content,
                final_path,
            )

        result["task_match"] = task_match

        if task_match == "PASS":
            score += self.SCORE_RULES["keywords_match"]

            if any(kw.lower() in title for kw in expected_keywords):
                score += self.SCORE_RULES["title_match"]

            if description and any(
                kw.lower() in description for kw in expected_keywords
            ):
                score += self.SCORE_RULES["description_match"]

            is_explicit_tool = self._is_explicit_tool_page_v12(
                title,
                final_path,
                content,
                task_id,
                expected_keywords,
            )
            result["explicit_tool_page"] = is_explicit_tool

            if is_explicit_tool:
                score += self.SCORE_RULES["explicit_tool_page"]

            result["confidence"] = self.CONFIDENCE_HIGH

        elif task_match == "FAIL":
            score += self.SCORE_RULES["task_mismatch"]
            result["confidence"] = self.CONFIDENCE_MEDIUM

        else:
            result["confidence"] = self.CONFIDENCE_LOW
            if not result["review_reason_code"]:
                result["review_reason_code"] = "INSUFFICIENT_EVIDENCE"

        result["score"] = max(0, min(100, score))

        if result["task_match"] == "FAIL" or score < self.SCORE_REVIEW:
            result["verdict"] = "FAIL"

            if result["reason"] == "Audit started":
                result["reason"] = (
                    f"Low score and task mismatch: {result['score']}"
                )

            if not result["review_reason_code"]:
                result["review_reason_code"] = "TASK_MISMATCH"

        elif score >= self.SCORE_PASS:
            result["verdict"] = "PASS"
            result["reason"] = (
                f"Page healthy and task relevant (score: {result['score']})"
            )
            result["review_reason_code"] = None

        else:
            result["verdict"] = "REVIEW"
            result["reason"] = (
                f"Needs manual review "
                f"(score: {result['score']}, task_match: {task_match})"
            )

            if not result["review_reason_code"]:
                result["review_reason_code"] = "INSUFFICIENT_EVIDENCE"

        return result

    def _fetch_url_streaming(
        self,
        url: str,
    ) -> Tuple[Optional[Any], float, Optional[str]]:
        error_type = "UNKNOWN_ERROR"

        for attempt in range(self.MAX_RETRIES):
            try:
                start_time = time.time()

                response = self.session.get(
                    url,
                    timeout=self.TIMEOUT,
                    allow_redirects=True,
                    verify=True,
                    stream=True,
                )

                content_size = 0
                chunks = []

                for chunk in response.iter_content(
                    chunk_size=8192,
                    decode_unicode=False,
                ):
                    if not chunk:
                        continue

                    remaining = self.MAX_CONTENT_SIZE - content_size

                    if remaining <= 0:
                        break

                    if len(chunk) > remaining:
                        chunks.append(chunk[:remaining])
                        content_size += remaining
                        break

                    chunks.append(chunk)
                    content_size += len(chunk)

                response._content = b"".join(chunks)

                try:
                    response.encoding = response.apparent_encoding or "utf-8"
                except Exception:
                    response.encoding = "utf-8"

                elapsed = time.time() - start_time
                return response, elapsed, None

            except requests.exceptions.Timeout:
                print(
                    f"  [WARN] Timeout "
                    f"(attempt {attempt + 1}/{self.MAX_RETRIES})"
                )
                error_type = "TIMEOUT"

            except requests.exceptions.SSLError:
                print(
                    f"  [WARN] SSL error "
                    f"(attempt {attempt + 1}/{self.MAX_RETRIES})"
                )
                error_type = "SSL_ERROR"

            except requests.exceptions.ConnectionError as exc:
                error_msg = str(exc).lower()

                dns_signals = [
                    "name or service not known",
                    "nodename nor servname provided",
                    "temporary failure in name resolution",
                    "nxdomain",
                    "failed to resolve",
                ]

                if any(signal in error_msg for signal in dns_signals):
                    return None, 0, "DNS_FAILED"

                print(
                    f"  [WARN] Connection error "
                    f"(attempt {attempt + 1}/{self.MAX_RETRIES})"
                )
                error_type = "CONNECTION_FAILED"

            except requests.exceptions.InvalidURL:
                return None, 0, "INVALID_URL"

            except requests.exceptions.RequestException as exc:
                error_msg = str(exc).lower()

                if "nxdomain" in error_msg or "failed to resolve" in error_msg:
                    return None, 0, "DNS_FAILED"

                print(f"  [WARN] Request failed: {exc}")
                error_type = "REQUEST_FAILED"

            except Exception as exc:
                print(f"  [WARN] Unexpected error: {exc}")
                error_type = "UNKNOWN_ERROR"

            if attempt < self.MAX_RETRIES - 1:
                time.sleep(1)

        return None, 0, error_type

    def _is_valid_url(self, url: str) -> bool:
        try:
            parsed = urlparse(url)

            return (
                parsed.scheme in ("http", "https")
                and bool(parsed.netloc)
            )

        except Exception:
            return False

    def _analyze_redirect_v12(
        self,
        original_url: str,
        final_url: str,
        final_content: str,
    ) -> Dict[str, str]:
        try:
            orig = urlparse(original_url)
            final = urlparse(final_url)

            if orig.netloc.lower() == final.netloc.lower():
                if final.path.lower() in ("", "/", "/index.html"):
                    return {
                        "verdict": "REVIEW",
                        "reason": "Redirects to homepage (same domain)",
                        "code": "HOMEPAGE_REDIRECT",
                    }

                return {
                    "verdict": "NORMAL",
                    "reason": "Normal same-domain redirect",
                    "code": "NORMAL_REDIRECT",
                }

            orig_domain = orig.netloc.lower().replace("www.", "")
            final_domain = final.netloc.lower().replace("www.", "")

            if orig_domain == final_domain:
                return {
                    "verdict": "NORMAL",
                    "reason": "Subdomain normalization",
                    "code": "NORMAL_REDIRECT",
                }

            if self._is_language_subdomain(orig.netloc, final.netloc):
                return {
                    "verdict": "NORMAL",
                    "reason": "Language/locale redirect",
                    "code": "NORMAL_REDIRECT",
                }

            suspicious = self._check_redirect_target_v12(
                final_content,
                final.netloc,
            )

            if suspicious:
                return {
                    "verdict": "FAIL",
                    "reason": (
                        f"Suspicious cross-domain redirect: {suspicious}"
                    ),
                    "code": "MALICIOUS_REDIRECT",
                }

            return {
                "verdict": "REVIEW",
                "reason": (
                    f"Cross-domain redirect to {final.netloc} "
                    f"(needs verification)"
                ),
                "code": "CROSS_DOMAIN_REDIRECT",
            }

        except Exception as exc:
            return {
                "verdict": "REVIEW",
                "reason": f"Redirect analysis error: {exc}",
                "code": "REDIRECT_ANALYSIS_ERROR",
            }

    def _is_language_subdomain(self, orig: str, final: str) -> bool:
        langs = {
            "en",
            "zh",
            "fr",
            "de",
            "es",
            "ja",
            "ko",
            "ru",
            "pt",
            "it",
        }

        orig_parts = orig.lower().split(".")
        final_parts = final.lower().split(".")

        if len(orig_parts) < 2 or len(final_parts) < 2:
            return False

        orig_base = ".".join(
            orig_parts[1:] if orig_parts[0] in langs else orig_parts
        )

        final_base = ".".join(
            final_parts[1:] if final_parts[0] in langs else final_parts
        )

        return orig_base == final_base

    def _check_redirect_target_v12(
        self,
        content: str,
        final_domain: str,
    ) -> Optional[str]:
        content_lower = content.lower()

        suspicious_patterns = [
            ("domain for sale", "Domain for sale"),
            ("parked domain", "Parked domain"),
            ("make an offer", "Domain sale"),
            ("casino", "Casino content"),
            ("viagra", "Pharma spam"),
            ("phishing", "Phishing attempt"),
            ("malware", "Malware"),
        ]

        for pattern, reason in suspicious_patterns:
            if pattern in content_lower:
                return reason

        if "redirecting" in content_lower and "click here" in content_lower:
            return "Suspicious redirect loop"

        return None

    def _detect_404_page_v11(
        self,
        soup,
        text: str,
        http_status: int,
    ) -> bool:
        if http_status in (404, 410):
            return True

        text_lower = text.lower()
        indicators = [
            "not found",
            "page not found",
            "404",
        ]

        matches = sum(
            1 for indicator in indicators
            if indicator in text_lower
        )

        if matches < 2:
            return False

        title = soup.find("title")

        if title:
            title_text = title.get_text().lower()

            if "404" in title_text or "not found" in title_text:
                return True

        h1 = soup.find("h1")

        if h1:
            h1_text = h1.get_text().lower()

            if "404" in h1_text or "not found" in h1_text:
                return True

        return False

    def _detect_parked_domain(self, soup, text: str) -> bool:
        indicators = [
            "domain for sale",
            "this domain is for sale",
            "make an offer",
            "parked domain",
            "page under construction",
        ]

        text_lower = text.lower()

        return any(
            indicator in text_lower
            for indicator in indicators
        )

    def _detect_ads_v11(self, soup, text: str) -> bool:
        text_lower = text.lower()

        strong_indicators = [
            "advertisement",
            "ad network",
            "google ads",
            "doubleclick",
            "adsbygoogle",
        ]

        if any(
            indicator in text_lower
            for indicator in strong_indicators
        ):
            return True

        for script in soup.find_all("script", src=True):
            src = script.get("src", "").lower()

            if any(
                signal in src
                for signal in (
                    "doubleclick",
                    "adsbygoogle",
                    "googlesyndication",
                )
            ):
                return True

        return False

    def _detect_login_wall_v11(
        self,
        soup,
        text: str,
    ) -> Optional[str]:
        text_lower = text.lower()

        strong_indicators = [
            "please log in",
            "must sign in",
            "login required",
            "sign in to continue",
            "please sign in",
            "you must be logged in",
        ]

        if any(
            indicator in text_lower
            for indicator in strong_indicators
        ):
            return "STRONG"

        return None

    def _detect_forced_app_v11(
        self,
        soup,
        text: str,
    ) -> bool:
        text_lower = text.lower()

        forced_indicators = [
            "open in app",
            "app only",
            "requires app",
            "app required",
            "download and install",
            "install now to continue",
            "only available in our mobile app",
        ]

        return any(
            indicator in text_lower
            for indicator in forced_indicators
        )

    def _check_task_match_v11(
        self,
        task_id: str,
        keywords: List[str],
        title: str,
        description: str,
        content: str,
        path: str,
    ) -> str:
        """
        Task matching with expected-keyword evidence protection.

        Important:
        If expected_keywords are supplied, task-id terms alone are NOT
        sufficient to produce REVIEW.

        This prevents unrelated pages that merely mention generic terms
        such as "PDF" or "compression" from being treated as plausible
        task matches.

        PASS:
        - >= 70% expected keywords match
        - AND at least one task-id term matches
        - AND page is not only a root/homepage

        REVIEW:
        - >= 40% expected keywords match
        - AND at least one task-id term matches

        FAIL:
        - insufficient expected-keyword evidence
        """

        if not keywords:
            return self._check_task_match_no_keywords(
                task_id,
                title,
                content,
                path,
            )

        keywords_lower = [
            str(keyword).lower().strip()
            for keyword in keywords
            if str(keyword).strip()
        ]

        if not keywords_lower:
            return self._check_task_match_no_keywords(
                task_id,
                title,
                content,
                path,
            )

        combined_text = (
            f"{title} {description} {content} {path}"
        ).lower()

        keyword_matches = sum(
            1
            for keyword in keywords_lower
            if keyword in combined_text
        )

        keyword_ratio = (
            keyword_matches / len(keywords_lower)
        )

        task_terms = [
            term
            for term in task_id.lower().split("-")
            if term
        ]

        task_term_matches = sum(
            1
            for term in task_terms
            if term in combined_text
        )

        # Strong evidence.
        if (
            keyword_ratio >= 0.7
            and task_term_matches > 0
        ):
            if path in ("", "/", "/index.html"):
                return "REVIEW"

            return "PASS"

        # Partial evidence.
        #
        # Critical v1.2 fix:
        # expected keywords MUST contribute evidence.
        # Task terms alone cannot elevate an unrelated page to REVIEW.
        if (
            keyword_ratio >= 0.4
            and task_term_matches > 0
        ):
            return "REVIEW"

        return "FAIL"

    def _check_task_match_no_keywords(
        self,
        task_id: str,
        title: str,
        content: str,
        path: str,
    ) -> str:
        task_terms = [
            term
            for term in task_id.lower().split("-")
            if term
        ]

        if not task_terms:
            return "FAIL"

        combined_text = (
            f"{title} {content} {path}"
        ).lower()

        task_term_matches = sum(
            1
            for term in task_terms
            if term in combined_text
        )

        ratio = (
            task_term_matches / len(task_terms)
        )

        if ratio >= 0.8:
            if path in ("", "/", "/index.html"):
                return "REVIEW"

            return "PASS"

        if task_term_matches > 0:
            return "REVIEW"

        return "FAIL"

    def _is_explicit_tool_page_v12(
        self,
        title: str,
        path: str,
        content: str,
        task_id: str,
        keywords: List[str],
    ) -> bool:
        path_lower = path.lower()
        title_lower = title.lower()

        for pattern in self.TOOL_PATH_PATTERNS:
            if re.search(pattern, path_lower):
                return True

        normalized_path = re.sub(
            r"[-_/]",
            "",
            path_lower,
        )

        normalized_task = re.sub(
            r"[-_ ]",
            "",
            task_id.lower(),
        )

        if (
            normalized_task
            and normalized_task in normalized_path
        ):
            return True

        for keyword in keywords:
            normalized_keyword = re.sub(
                r"[-_ ]",
                "",
                str(keyword).lower(),
            )

            if (
                normalized_keyword
                and normalized_keyword in normalized_path
            ):
                return True

        explicit_indicators = [
            "online pdf compressor",
            "pdf compressor",
            "compression tool",
            "converter",
            "generator",
            "online tool",
            "free online",
        ]

        if any(
            indicator in title_lower
            for indicator in explicit_indicators
        ):
            return True

        return False

    def generate_audit_results(
        self,
        results: List[Dict],
        summary: Dict,
        output_file: str,
    ):
        output = {
            "version": "1.2",
            "generated_at": datetime.now().isoformat(),
            "summary": summary,
            "note": (
                "Results reflect public network accessibility only. "
                "NOT equivalent to Mainland China carrier testing, "
                "ad-free verification, free access, mobile experience, "
                "or login-free confirmation. "
                "PASS verdict = machine initial review only."
            ),
            "results": results,
        }

        with open(
            output_file,
            "w",
            encoding="utf-8",
        ) as f:
            json.dump(
                output,
                f,
                ensure_ascii=False,
                indent=2,
            )

        print(f"[OUTPUT] Wrote {output_file}")

    def generate_approved(
        self,
        results: List[Dict],
    ):
        approved = [
            result
            for result in results
            if result.get("verdict") == "PASS"
        ]

        with open(
            "audit/approved.json",
            "w",
            encoding="utf-8",
        ) as f:
            json.dump(
                {"approved": approved},
                f,
                ensure_ascii=False,
                indent=2,
            )

        print(
            f"[OUTPUT] Wrote audit/approved.json "
            f"({len(approved)} items)"
        )

    def generate_rejected(
        self,
        results: List[Dict],
    ):
        rejected = []

        for result in results:
            if result.get("verdict") != "FAIL":
                continue

            rejected.append({
                "candidate_id":
                    result.get("candidate_id"),
                "task_id":
                    result.get("task_id"),
                "url":
                    result.get("url"),
                "http_status":
                    result.get("http_status"),
                "reason":
                    result.get("reason"),
                "review_reason_code":
                    result.get("review_reason_code"),
            })

        with open(
            "audit/rejected.json",
            "w",
            encoding="utf-8",
        ) as f:
            json.dump(
                {"rejected": rejected},
                f,
                ensure_ascii=False,
                indent=2,
            )

        print(
            f"[OUTPUT] Wrote audit/rejected.json "
            f"({len(rejected)} items)"
        )


def main():
    print("=" * 70)
    print("NAV KING URL Audit System v1.2")
    print("=" * 70)

    auditor = URLAuditor()

    success = auditor.run_audit(
        "audit/candidates.json",
        "audit/audit-results.json",
    )

    if success:
        print(
            "\n[SUCCESS] Audit completed successfully"
        )
        return 0

    print(
        "\n[ERROR] Audit failed"
    )

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
