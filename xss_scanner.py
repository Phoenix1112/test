#!/usr/bin/env python3
"""
XSS Scanner - String-based XSS Detection using Playwright (Async)
Uses unique string markers instead of traditional XSS payloads
Supports parallel tab loading, real-time XSS testing, and resume capability
"""

import argparse
import sys
import json
import re
import asyncio
import os
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
from playwright.async_api import async_playwright


# ── Colors ──────────────────────────────────────────────────────
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    RESET = '\033[0m'


def color_print(text, color=Colors.WHITE, bold=False):
    if silent_mode:
        return
    prefix = Colors.BOLD if bold else ''
    print(prefix + color + text + Colors.RESET)


def xss_print(text):
    """Always print XSS findings even in silent mode"""
    print("\n" + Colors.BOLD + Colors.YELLOW + text + Colors.RESET)


def progress_line(current, total, reflected, xss_found):
    """Print progress on same line"""
    if silent_mode:
        return
    line = Colors.CYAN + Colors.BOLD + str(current) + "/" + str(total) + " deneniyor" + Colors.RESET
    line += " | " + Colors.YELLOW + "reflection: " + str(reflected) + Colors.RESET
    line += " | " + Colors.RED + "discovered-XSS: " + str(xss_found) + Colors.RESET
    print("\r" + line, end="", flush=True)


def clear_progress_line():
    """Clear the progress line"""
    if silent_mode:
        return
    print("\r" + " " * 100 + "\r", end="", flush=True)


# ── Globals ─────────────────────────────────────────────────────
silent_mode = False
REFLECTION_MARKER = "hacktivist"
XSS_TEST_STRING = "hacktivist1337"
OUTPUT_FILE = "xss_found.txt"
MAX_TABS = 5
RESUME_FILE = "/tmp/xss_scanner.txt"


# ── Argument Parser ─────────────────────────────────────────────
def parse_args():
    parser = argparse.ArgumentParser(
        description="XSS Scanner - String-based XSS Detection",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("-u", "--url", help="Single URL to test (must have query parameters)")
    parser.add_argument("-l", "--list", help="File containing list of URLs")
    parser.add_argument("-o", "--output", default=OUTPUT_FILE, help="Output file (default: xss_found.txt)")
    parser.add_argument("-r", "--redirect", action="store_true", default=False, help="Follow redirects")
    parser.add_argument("-t", "--tabs", type=int, default=1, help="Number of parallel tabs (1-5, default: 1)")
    parser.add_argument("--silent", action="store_true", default=False, help="Silent mode - only show XSS findings")
    parser.add_argument("--resume", action="store_true", default=False, help="Resume from last position (requires -l)")
    return parser.parse_args()


# ── URL Helpers ─────────────────────────────────────────────────
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


# ── Payloads ────────────────────────────────────────────────────
def get_payloads():
    return [
        ("double_quote", '"' + XSS_TEST_STRING),
        ("single_quote", "'" + XSS_TEST_STRING),
        ("html_tag", "<" + XSS_TEST_STRING + ">"),
        ("script_break", "</script><" + XSS_TEST_STRING + ">"),
    ]


# ── XSS Detection Functions ─────────────────────────────────────
def classify_context(html, idx):
    """
    Classify the HTML/JS context that the reflected marker at position `idx`
    in `html` lands in. Returns one of:
      "double_quoted" - inside an HTML attribute value delimited by "
      "single_quoted" - inside an HTML attribute value delimited by '
      "unquoted_attr" - directly after '=' in an HTML attribute, no quote
      "js_unquoted"   - directly after '=' in a bare JS assignment in <script>
      "text"          - plain HTML text content (not inside a tag)
      "tag_other"     - inside a tag's attribute list, but not part of any
                        value (e.g. between attributes) - not injectable

    This replaces the old approach of blindly rfind()-ing the nearest '='
    within a fixed character window. That approach broke as soon as ANY
    other '=' happened to sit closer to the marker than the real delimiter -
    e.g. a query string echoed inside an href/RetURL attribute
    (href="...?x=1&y=hacktivist1337") has its own internal '=' characters,
    and text like "You searched for 'X'" isn't inside a tag/attribute at
    all. Both cases were being misclassified as "unquoted" before, because
    the code never checked whether it was actually still inside an already
    -open quoted value, or even inside a tag at all.

    The fix: find whether idx sits inside an open tag (last '<' after the
    last '>'), and if so, walk forward from the tag start tracking quote
    state character-by-character, so an '=' that is merely literal text
    *inside* an already-open attribute value is never mistaken for a fresh,
    unquoted assignment.
    """
    last_lt = html.rfind("<", 0, idx)
    last_gt = html.rfind(">", 0, idx)

    if last_gt > last_lt:
        # idx is in plain text content, not inside any tag's attribute list -
        # unless this text is the raw body of a <script> element, where a
        # bare JS assignment can still be an unquoted-exploitable sink.
        if is_inside_script_block(html, idx):
            script_start = html.rfind("<script", 0, idx)
            script_tag = html[script_start:script_start + 200]
            if "application/ld+json" in script_tag.lower():
                return "text"
            before = html[max(0, idx - 200):idx]
            eq_pos = before.rfind("=")
            if eq_pos == -1:
                return "text"
            after_eq = before[eq_pos + 1:].strip()
            if after_eq[:1] == '"':
                return "double_quoted"
            if after_eq[:1] == "'":
                return "single_quoted"
            return "js_unquoted"
        return "text"

    # idx is inside an open HTML tag (its attribute-list region). Track
    # quote state from the tag's own start so we never leak state from a
    # previous, already-closed tag.
    tag_start = last_lt
    state = None  # None | '"' | "'"
    i = tag_start + 1
    while i < idx:
        c = html[i]
        if state is None:
            if c in ('"', "'"):
                state = c
        else:
            if c == state:
                state = None
        i += 1

    if state == '"':
        return "double_quoted"
    if state == "'":
        return "single_quoted"

    eq_pos = html.rfind("=", tag_start + 1, idx)
    if eq_pos == -1:
        return "tag_other"
    return "unquoted_attr"


def is_unquoted_reflection(html, idx):
    """True only for a genuine unquoted HTML attribute or bare JS value."""
    return classify_context(html, idx) in ("unquoted_attr", "js_unquoted")


async def has_new_attribute_named(page, needle):
    """
    Return True if any element in the live DOM has an attribute whose NAME
    (not value!) contains `needle`. This is the reliable signal that an
    injected quote/space actually broke OUT of an existing attribute value -
    the browser re-parses the broken markup and mints a brand-new attribute
    out of whatever followed the break. Merely finding the marker inside an
    attribute's VALUE proves nothing: a properly-escaped, 100%-safe
    reflection also contains that substring in the value.
    """
    try:
        return bool(await page.evaluate(
            """(needle) => {
                const all = document.querySelectorAll("*");
                for (const el of all) {
                    for (const attr of el.attributes) {
                        if (attr.name.toLowerCase().includes(needle)) {
                            return true;
                        }
                    }
                }
                return false;
            }""",
            needle,
        ))
    except Exception:
        return False


async def check_unquoted_attribute_xss(page, param_name, url_tested):
    try:
        html = await page.content()
        idx = 0
        while True:
            idx = html.find(XSS_TEST_STRING, idx)
            if idx == -1:
                break
            if is_unquoted_reflection(html, idx):
                return True
            idx += 1
        return False
    except Exception as e:
        return False


async def check_double_quote_xss(page, param_name, url_tested):
    """
    Confirms a REAL double-quote breakout, not just the presence of the
    marker inside some attribute's value (which is trivially true for any
    safe, properly-escaped reflection too - e.g. a RetURL/redirect link
    that happens to echo the current query string).

    Two independent, both-real signals:
      1) A brand new attribute NAME appeared in the DOM (the injected
         quote closed the original attribute early and the browser turned
         the rest of our payload into a fresh attribute).
      2) The raw payload's quote character (") is found immediately
         preceding the marker in the page source AND, at that exact
         position, quote-state tracking shows we really were inside an
         open double-quoted value that our quote then closed.
    """
    try:
        if await has_new_attribute_named(page, XSS_TEST_STRING.lower()):
            return True
        html = await page.content()
        idx = 0
        while True:
            idx = html.find('"' + XSS_TEST_STRING, idx)
            if idx == -1:
                break
            if classify_context(html, idx) == "double_quoted":
                return True
            idx += 1
        return False
    except Exception as e:
        return False


async def check_single_quote_xss(page, param_name, url_tested):
    """Mirror of check_double_quote_xss for the ' payload - see its
    docstring for why both a new-attribute-name signal and a quote-state
    check are used instead of a naive substring/regex match."""
    try:
        if await has_new_attribute_named(page, XSS_TEST_STRING.lower()):
            return True
        html = await page.content()
        idx = 0
        while True:
            idx = html.find("'" + XSS_TEST_STRING, idx)
            if idx == -1:
                break
            if classify_context(html, idx) == "single_quoted":
                return True
            idx += 1
        return False
    except Exception as e:
        return False


def is_inside_script_block(html, idx):
    """
    True if idx sits inside the raw-text content of a <script>...</script>
    element (i.e. before the browser reaches the matching closing tag).
    Browsers parse <script> content as raw text, not HTML - so a literal
    '<tag>' found in there is never turned into a real DOM element and
    can't be exploited as HTML tag injection there.
    """
    script_start = html.rfind("<script", 0, idx)
    if script_start == -1:
        return False
    close_idx = html.find("</script", script_start)
    if close_idx == -1 or close_idx > idx:
        return True
    return False


async def check_html_tag_xss(page, param_name, url_tested):
    try:
        exists = await page.evaluate("""
            () => {
                const el = document.querySelector("hacktivist1337");
                return el !== null;
            }
        """)
        if exists:
            return True

        html = await page.content()
        for marker in ("<hacktivist1337>", "</hacktivist1337>"):
            encoded = marker.replace("<", "&lt;").replace(">", "&gt;")
            if encoded in html:
                continue
            idx = html.find(marker)
            while idx != -1:
                if not is_inside_script_block(html, idx):
                    return True
                idx = html.find(marker, idx + 1)
        return False
    except Exception as e:
        return False


async def check_script_break_xss(page, param_name, url_tested):
    try:
        html = await page.content()
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
        return False


# ── Scanner Class ───────────────────────────────────────────────
class XSSScanner:
    def __init__(self, output_file, follow_redirects=False, max_tabs=1, resume=False):
        self.output_file = output_file
        self.follow_redirects = follow_redirects
        self.max_tabs = max_tabs
        self.resume = resume
        self.total_urls = 0
        self.reflected_count = 0
        self.xss_count = 0
        self.current_index = 0

    def is_duplicate(self, msg):
        """Check if XSS finding already exists in output file"""
        if not os.path.exists(self.output_file):
            return False
        try:
            with open(self.output_file, "r", encoding="utf-8") as f:
                existing = f.read()
            return msg in existing
        except Exception:
            return False

    def log(self, msg):
        # Always print to screen
        xss_print(msg)
        # Only write to file if not duplicate
        if not self.is_duplicate(msg):
            with open(self.output_file, "a", encoding="utf-8") as f:
                f.write(msg + "\n")

    def save_resume(self, index):
        """Save current position, counters, and output path to resume file"""
        try:
            with open(RESUME_FILE, "w", encoding="utf-8") as f:
                data = {
                    "index": index,
                    "reflected": self.reflected_count,
                    "xss": self.xss_count,
                    "output-path": os.path.abspath(self.output_file)
                }
                f.write(json.dumps(data))
        except Exception:
            pass

    def load_resume(self):
        """Load resume position, counters, and output path from file"""
        try:
            if os.path.exists(RESUME_FILE):
                with open(RESUME_FILE, "r", encoding="utf-8") as f:
                    content = f.read().strip()
                    data = json.loads(content)
                    if isinstance(data, dict):
                        self.reflected_count = data.get("reflected", 0)
                        self.xss_count = data.get("xss", 0)
                        # Load output path if saved (even if file was deleted, recreate it)
                        saved_output = data.get("output-path")
                        if saved_output:
                            self.output_file = saved_output
                        return data.get("index", 0)
                    elif content.isdigit():
                        return int(content)
        except Exception:
            pass
        return 0

    def remove_resume(self):
        """Remove resume file"""
        try:
            if os.path.exists(RESUME_FILE):
                os.remove(RESUME_FILE)
        except Exception:
            pass

    async def scan_reflection_single(self, context, url):
        page = await context.new_page()
        try:
            reflection_url, param_names = build_reflection_url(url)
            if not reflection_url:
                return None
            response = await page.goto(reflection_url, wait_until="domcontentloaded", timeout=12000)
            if not self.follow_redirects and response:
                final_url = page.url
                if final_url.split("?")[0] != reflection_url.split("?")[0]:
                    return None
            await asyncio.sleep(0.5)
            html = await page.content()
            reflected_params = []
            unquoted_attrs = []
            for i, param_name in enumerate(param_names, 1):
                marker = REFLECTION_MARKER + str(i)
                if marker in html:
                    reflected_params.append(param_name)
                    idx = html.find(marker)
                    while idx != -1:
                        if is_unquoted_reflection(html, idx):
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
            return None
        finally:
            await page.close()

    async def test_unquoted_attribute(self, context, base_url, param_name):
        test_url = replace_param_value(base_url, param_name, XSS_TEST_STRING)
        page = await context.new_page()
        try:
            await page.goto(test_url, wait_until="domcontentloaded", timeout=12000)
            await asyncio.sleep(0.3)
            if await check_unquoted_attribute_xss(page, param_name, test_url):
                return True, test_url
            return False, None
        except Exception as e:
            return False, None
        finally:
            await page.close()

    async def test_payload(self, context, base_url, param_name, payload_type, payload_value):
        test_url = replace_param_value(base_url, param_name, payload_value)
        page = await context.new_page()
        try:
            await page.goto(test_url, wait_until="domcontentloaded", timeout=12000)
            await asyncio.sleep(0.3)
            if payload_type == "double_quote":
                if await check_double_quote_xss(page, param_name, test_url):
                    return True, test_url
            elif payload_type == "single_quote":
                if await check_single_quote_xss(page, param_name, test_url):
                    return True, test_url
            elif payload_type == "html_tag":
                if await check_html_tag_xss(page, param_name, test_url):
                    return True, test_url
            elif payload_type == "script_break":
                if await check_script_break_xss(page, param_name, test_url):
                    return True, test_url
            return False, None
        except Exception as e:
            return False, None
        finally:
            await page.close()

    async def scan_xss_on_reflection(self, context, reflection_data):
        """Test XSS immediately when reflection found - tests ALL parameters regardless of findings"""
        base_url = reflection_data["url"]
        params = reflection_data["parametre"].split(",")
        unquoted_attrs_str = reflection_data.get("attribute", "")
        unquoted_attrs = unquoted_attrs_str.split(",") if unquoted_attrs_str else []
        any_found = False

        # 1) Önce tırnaksız attribute parametrelerini dene (XSS bulunsa bile devam et)
        for attr_param in unquoted_attrs:
            if attr_param and attr_param in params:
                found, test_url = await self.test_unquoted_attribute(context, base_url, attr_param)
                if found:
                    self.xss_count += 1
                    msg = "[xss-found][unquoted][" + attr_param + "] " + test_url
                    self.log(msg)
                    any_found = True
                # NOT: return True yok - diğer parametrelere devam ediyoruz

        # 2) Tüm reflected parametreler için normal payloadları dene
        #    (attribute olanlar da dahil - farklı payloadlar farklı sonuç verebilir)
        payloads = get_payloads()
        for param_name in params:
            if not param_name:
                continue
            for payload_type, payload_value in payloads:
                found, test_url = await self.test_payload(context, base_url, param_name, payload_type, payload_value)
                if found:
                    self.xss_count += 1
                    msg = "[xss-found][" + payload_type + "][" + param_name + "] " + test_url
                    self.log(msg)
                    any_found = True
                # NOT: return True yok - diğer payloadlara ve parametrelere devam ediyoruz

        return any_found

    async def process_url(self, context, url, index):
        """Process single URL: reflection + immediate XSS test"""
        reflection = await self.scan_reflection_single(context, url)
        if reflection:
            self.reflected_count += 1
            found = await self.scan_xss_on_reflection(context, reflection)
            if found and not silent_mode:
                clear_progress_line()

    def ensure_output_file(self):
        """Create output file with header if it does not exist"""
        if not os.path.exists(self.output_file):
            with open(self.output_file, "w", encoding="utf-8") as f:
                f.write("# XSS Scan Results\n")

    async def run(self, urls):
        start_index = 0
        if self.resume:
            start_index = self.load_resume()
            if not silent_mode:
                print(Colors.CYAN + Colors.BOLD + "[+] Resuming from URL " + str(start_index + 1) + " | reflection: " + str(self.reflected_count) + " | discovered-XSS: " + str(self.xss_count) + Colors.RESET)
                print(Colors.CYAN + Colors.BOLD + "[+] Output file: " + self.output_file + Colors.RESET)
        else:
            self.remove_resume()

        # Create output file only after output path is finalized (post-resume load)
        self.ensure_output_file()

        urls_to_scan = urls[start_index:]
        self.total_urls = len(urls)

        async with async_playwright() as p:
            browser = await p.chromium.launch(
                headless=True,
                args=["--no-sandbox", "--disable-setuid-sandbox", "--disable-images"]
            )
            context = await browser.new_context(
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                viewport={"width": 1920, "height": 1080}
            )

            if not silent_mode:
                print(Colors.MAGENTA + Colors.BOLD + "[+] Scanning " + str(len(urls_to_scan)) + " URLs..." + Colors.RESET)

            batch_size = self.max_tabs
            for i in range(0, len(urls_to_scan), batch_size):
                batch = urls_to_scan[i:i + batch_size]
                actual_index = start_index + i + len(batch)

                if not silent_mode:
                    progress_line(actual_index, self.total_urls, self.reflected_count, self.xss_count)

                tasks = []
                for j, url in enumerate(batch):
                    idx = start_index + i + j + 1
                    tasks.append(self.process_url(context, url, idx))

                await asyncio.gather(*tasks, return_exceptions=True)
                self.save_resume(actual_index)

            if not silent_mode:
                clear_progress_line()
                progress_line(self.total_urls, self.total_urls, self.reflected_count, self.xss_count)
                print()
                print(Colors.GREEN + Colors.BOLD + "[+] Scan complete. Results saved to: " + self.output_file + Colors.RESET)

            await browser.close()

        if not self.resume:
            self.remove_resume()


# ── Main ────────────────────────────────────────────────────────
def main():
    args = parse_args()
    global silent_mode
    silent_mode = args.silent
    max_tabs = args.tabs

    if max_tabs > MAX_TABS:
        if not silent_mode:
            print(Colors.YELLOW + Colors.BOLD + "[!] WARNING: Maximum " + str(MAX_TABS) + " tabs allowed. Setting tabs to " + str(MAX_TABS) + "." + Colors.RESET)
        max_tabs = MAX_TABS

    if args.resume and not args.list:
        if not silent_mode:
            print(Colors.RED + Colors.BOLD + "[!] Error: --resume requires -l/--list" + Colors.RESET)
        sys.exit(1)

    if not args.url and not args.list:
        if not silent_mode:
            print(Colors.RED + Colors.BOLD + "[!] Error: Provide -u for single URL or -l for URL list" + Colors.RESET)
        sys.exit(1)

    urls = []
    if args.url:
        params = extract_params(args.url)
        if not params:
            if not silent_mode:
                print(Colors.RED + Colors.BOLD + "[!] Error: URL must contain query parameters" + Colors.RESET)
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
                            if not silent_mode:
                                print(Colors.YELLOW + "[!] Skipping (no params): " + line + Colors.RESET)
        except FileNotFoundError:
            if not silent_mode:
                print(Colors.RED + Colors.BOLD + "[!] Error: File not found: " + args.list + Colors.RESET)
            sys.exit(1)

    if not urls:
        if not silent_mode:
            print(Colors.RED + Colors.BOLD + "[!] No valid URLs to test" + Colors.RESET)
        sys.exit(1)

    if not silent_mode:
        print(Colors.GREEN + Colors.BOLD + "[+] Loaded " + str(len(urls)) + " URLs with parameters" + Colors.RESET)
        print(Colors.CYAN + Colors.BOLD + "[+] Using " + str(max_tabs) + " parallel tab(s)" + Colors.RESET)
        if args.resume:
            print(Colors.CYAN + Colors.BOLD + "[+] Resume mode enabled" + Colors.RESET)

    scanner = XSSScanner(args.output, args.redirect, max_tabs, args.resume)
    asyncio.run(scanner.run(urls))


if __name__ == "__main__":
    main()
