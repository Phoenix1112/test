#!/usr/bin/env python3
"""
install:

pip install playwright
playwright install chromium


XSS Scanner - String-based XSS Detection using Playwright
Uses unique string markers instead of traditional XSS payloads
"""

import argparse
import sys
import json
import time
import re
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
from playwright.sync_api import sync_playwright


# Configuration
REFLECTION_MARKER = "hacktivist"
XSS_TEST_STRING = "hacktivist1337"
OUTPUT_FILE = "xss_found.txt"


def parse_args():
    parser = argparse.ArgumentParser(
        description="XSS Scanner - String-based XSS Detection",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("-u", "--url", help="Single URL to test (must have query parameters)")
    parser.add_argument("-l", "--list", help="File containing list of URLs")
    parser.add_argument("-o", "--output", default=OUTPUT_FILE, help="Output file (default: xss_found.txt)")
    parser.add_argument("-r", "--redirect", action="store_true", default=False, help="Follow redirects")
    return parser.parse_args()


def extract_params(url):
    parsed = urlparse(url)
    return parse_qsl(parsed.query)


def replace_param_value(url, param_name, new_value):
    parsed = urlparse(url)
    params = parse_qsl(parsed.query)
    new_params = [(k, new_value if k == param_name else v) for k, v in params]
    new_query = urlencode(new_params)
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))


def build_reflection_url(url):
    parsed = urlparse(url)
    params = parse_qsl(parsed.query)
    if not params:
        return None, []
    new_params = []
    param_names = []
    for i, (k, v) in enumerate(params, 1):
        new_params.append((k, REFLECTION_MARKER + str(i)))
        param_names.append(k)
    new_query = urlencode(new_params)
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment)), param_names


def get_payloads():
    return [
        ("double_quote", '"' + XSS_TEST_STRING),
        ("single_quote", "'" + XSS_TEST_STRING),
        ("html_tag", "<" + XSS_TEST_STRING + ">"),
        ("script_break", "</script><" + XSS_TEST_STRING + ">"),
    ]


def check_unquoted_attribute_xss(page, param_name, url_tested):
    try:
        html = page.content()
        idx = 0
        while True:
            idx = html.find(XSS_TEST_STRING, idx)
            if idx == -1:
                break
            before = html[max(0, idx - 100):idx]
            eq_pos = before.rfind("=")
            if eq_pos != -1:
                after_eq = before[eq_pos + 1:].strip()
                if after_eq and after_eq[0] not in ('"', "'"):
                    script_start = html.rfind("<script", 0, idx)
                    if script_start != -1:
                        script_tag = html[script_start:script_start + 200]
                        if "application/ld+json" in script_tag.lower():
                            idx += 1
                            continue
                    return True
            idx += 1
        return False
    except Exception as e:
        print("    [!] Error in unquoted attribute check: " + str(e))
        return False


def check_double_quote_xss(page, param_name, url_tested):
    try:
        html = page.content()
        patterns = [
            r'="[^"]*"hacktivist1337',
            r'="[^"]*" hacktivist1337',
            r'="[^"]*hacktivist1337"',
        ]
        for pattern in patterns:
            if re.search(pattern, html):
                return True

        elements = page.evaluate("""
            () => {
                const results = [];
                const all = document.querySelectorAll("*");
                for (let el of all) {
                    for (let attr of el.attributes) {
                        if (attr.value.includes("hacktivist1337")) {
                            const outer = el.outerHTML;
                            const dqPattern = new RegExp(attr.name + '="([^"]*)hacktivist1337');
                            if (dqPattern.test(outer)) {
                                results.push({tag: el.tagName, attr: attr.name, value: attr.value});
                            }
                        }
                    }
                }
                return results;
            }
        """)
        if elements and len(elements) > 0:
            return True
        return False
    except Exception as e:
        print("    [!] Error in double quote check: " + str(e))
        return False


def check_single_quote_xss(page, param_name, url_tested):
    try:
        html = page.content()
        patterns = [
            r"='[^']*'hacktivist1337",
            r"='[^']*' hacktivist1337",
            r"='[^']*hacktivist1337'",
        ]
        for pattern in patterns:
            if re.search(pattern, html):
                return True

        elements = page.evaluate("""
            () => {
                const results = [];
                const all = document.querySelectorAll("*");
                for (let el of all) {
                    for (let attr of el.attributes) {
                        if (attr.value.includes("hacktivist1337")) {
                            const outer = el.outerHTML;
                            const sqPattern = new RegExp(attr.name + "='([^']*)hacktivist1337");
                            if (sqPattern.test(outer)) {
                                results.push({tag: el.tagName, attr: attr.name, value: attr.value});
                            }
                        }
                    }
                }
                return results;
            }
        """)
        if elements and len(elements) > 0:
            return True
        return False
    except Exception as e:
        print("    [!] Error in single quote check: " + str(e))
        return False


def check_html_tag_xss(page, param_name, url_tested):
    try:
        exists = page.evaluate("""
            () => {
                const el = document.querySelector("hacktivist1337");
                return el !== null;
            }
        """)
        if exists:
            return True
        html = page.content()
        if "<hacktivist1337>" in html and "&lt;hacktivist1337&gt;" not in html:
            return True
        if "</hacktivist1337>" in html and "&lt;/hacktivist1337&gt;" not in html:
            return True
        return False
    except Exception as e:
        print("    [!] Error in HTML tag check: " + str(e))
        return False


def check_script_break_xss(page, param_name, url_tested):
    try:
        html = page.content()
        marker = "</script><hacktivist1337>"
        if marker in html:
            return True
        idx = 0
        while True:
            idx = html.find("</script>", idx)
            if idx == -1:
                break
            after = html[idx + 9:idx + 100]
            if "hacktivist1337" in after:
                return True
            idx += 1
        return False
    except Exception as e:
        print("    [!] Error in script break check: " + str(e))
        return False


class XSSScanner:
    def __init__(self, output_file, follow_redirects=False):
        self.output_file = output_file
        self.follow_redirects = follow_redirects
        with open(self.output_file, "w", encoding="utf-8") as f:
            f.write("# XSS Scan Results\n")

    def log(self, msg):
        print(msg)
        with open(self.output_file, "a", encoding="utf-8") as f:
            f.write(msg + "\n")

    def scan_reflection(self, page, url):
        reflection_url, param_names = build_reflection_url(url)
        if not reflection_url:
            return None
        try:
            response = page.goto(reflection_url, wait_until="networkidle", timeout=15000)
            if not self.follow_redirects and response:
                final_url = page.url
                if final_url.split("?")[0] != reflection_url.split("?")[0]:
                    print("    [!] Redirect detected, skipping (use -r to follow)")
                    return None
            html = page.content()
            reflected_params = []
            unquoted_attrs = []
            for i, param_name in enumerate(param_names, 1):
                marker = REFLECTION_MARKER + str(i)
                if marker in html:
                    reflected_params.append(param_name)
                    idx = html.find(marker)
                    while idx != -1:
                        before = html[max(0, idx - 100):idx]
                        eq_pos = before.rfind("=")
                        if eq_pos != -1:
                            after_eq = before[eq_pos + 1:].strip()
                            if after_eq and after_eq[0] not in ('"', "'"):
                                script_start = html.rfind("<script", 0, idx)
                                if script_start != -1:
                                    script_tag = html[script_start:script_start + 200]
                                    if "application/ld+json" not in script_tag.lower():
                                        unquoted_attrs.append(param_name)
                                        break
                                else:
                                    unquoted_attrs.append(param_name)
                                    break
                        idx = html.find(marker, idx + 1)
            if not reflected_params:
                return None
            return {
                "url": url,
                "parametre": ",".join(reflected_params),
                "attribute": ",".join(unquoted_attrs) if unquoted_attrs else ""
            }
        except Exception as e:
            print("    [!] Error scanning " + url + ": " + str(e))
            return None

    def test_unquoted_attribute(self, page, base_url, param_name):
        test_url = replace_param_value(base_url, param_name, XSS_TEST_STRING)
        try:
            page.goto(test_url, wait_until="networkidle", timeout=15000)
            if check_unquoted_attribute_xss(page, param_name, test_url):
                msg = "[xss-found][" + param_name + "] " + test_url
                self.log(msg)
                return True
            return False
        except Exception as e:
            print("    [!] Error testing unquoted " + param_name + ": " + str(e))
            return False

    def test_payload(self, page, base_url, param_name, payload_type, payload_value):
        test_url = replace_param_value(base_url, param_name, payload_value)
        try:
            page.goto(test_url, wait_until="networkidle", timeout=15000)
            if payload_type == "double_quote":
                if check_double_quote_xss(page, param_name, test_url):
                    msg = "[xss-found][" + param_name + "] " + test_url
                    self.log(msg)
                    return True
            elif payload_type == "single_quote":
                if check_single_quote_xss(page, param_name, test_url):
                    msg = "[xss-found][" + param_name + "] " + test_url
                    self.log(msg)
                    return True
            elif payload_type == "html_tag":
                if check_html_tag_xss(page, param_name, test_url):
                    msg = "[xss-found][" + param_name + "] " + test_url
                    self.log(msg)
                    return True
            elif payload_type == "script_break":
                if check_script_break_xss(page, param_name, test_url):
                    msg = "[xss-found][" + param_name + "] " + test_url
                    self.log(msg)
                    return True
            return False
        except Exception as e:
            print("    [!] Error testing " + payload_type + " on " + param_name + ": " + str(e))
            return False

    def scan_xss(self, page, reflection_data):
        base_url = reflection_data["url"]
        params = reflection_data["parametre"].split(",")
        unquoted_attrs_str = reflection_data.get("attribute", "")
        unquoted_attrs = unquoted_attrs_str.split(",") if unquoted_attrs_str else []
        for attr_param in unquoted_attrs:
            if attr_param and attr_param in params:
                print("[*] Testing unquoted attribute: " + attr_param)
                if self.test_unquoted_attribute(page, base_url, attr_param):
                    return
                time.sleep(0.3)
        payloads = get_payloads()
        for param_name in params:
            if not param_name:
                continue
            print("[*] Testing parameter: " + param_name)
            for payload_type, payload_value in payloads:
                print("    [-] Testing " + payload_type + ": " + payload_value)
                if self.test_payload(page, base_url, param_name, payload_type, payload_value):
                    return
                time.sleep(0.3)

    def run(self, urls):
        with sync_playwright() as p:
            browser = p.chromium.launch(
                headless=True,
                args=["--no-sandbox", "--disable-setuid-sandbox"]
            )
            context = browser.new_context(
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                viewport={"width": 1920, "height": 1080}
            )
            page = context.new_page()
            print("[+] Phase 1: Detecting DOM reflections...")
            reflection_results = []
            for url in urls:
                print("\n[*] Checking: " + url)
                result = self.scan_reflection(page, url)
                if result:
                    print("    [+] Reflected: " + json.dumps(result, ensure_ascii=False))
                    reflection_results.append(result)
                else:
                    print("    [-] No reflection or skipped")
            print("\n[+] Phase 2: Testing " + str(len(reflection_results)) + " URLs for XSS...")
            for result in reflection_results:
                print("\n[*] Testing: " + result["url"])
                print("    Parameters: " + result["parametre"])
                if result.get("attribute"):
                    print("    Unquoted attrs: " + result["attribute"])
                self.scan_xss(page, result)
            browser.close()
        print("\n[+] Scan complete. Results saved to: " + self.output_file)


def main():
    args = parse_args()
    if not args.url and not args.list:
        print("[!] Error: Provide -u for single URL or -l for URL list")
        sys.exit(1)
    urls = []
    if args.url:
        params = extract_params(args.url)
        if not params:
            print("[!] Error: URL must contain query parameters")
            sys.exit(1)
        urls.append(args.url)
    if args.list:
        try:
            with open(args.list, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        params = extract_params(line)
                        if params:
                            urls.append(line)
                        else:
                            print("[!] Skipping (no params): " + line)
        except FileNotFoundError:
            print("[!] Error: File not found: " + args.list)
            sys.exit(1)
    if not urls:
        print("[!] No valid URLs to test")
        sys.exit(1)
    print("[+] Loaded " + str(len(urls)) + " URLs with parameters")
    scanner = XSSScanner(args.output, args.redirect)
    scanner.run(urls)


if __name__ == "__main__":
    main()
