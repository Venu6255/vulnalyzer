"""
Enhanced WebSecurityScanner with progress tracking and WebSocket integration
"""

import requests
from bs4 import BeautifulSoup
import colorama
import urllib.parse
from typing import Set, List, Dict, Optional, Callable
import time
import concurrent.futures
import threading
import logging

# Import plugins
from plugins import load_plugins

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Suppress SSL warnings
import warnings
warnings.filterwarnings("ignore", category=UserWarning, module='bs4')
warnings.filterwarnings("ignore", category=requests.packages.urllib3.exceptions.InsecureRequestWarning)

colorama.init(autoreset=True)

class WebSecurityScanner:
    """Enhanced web security scanner with progress tracking"""

    def __init__(self, target_url: str, max_depth: int = 3, delay: float = 0.1,
                 max_workers: int = 10, plugins: Optional[List] = None, 
                 plugin_names: Optional[List[str]] = None, 
                 progress_callback: Optional[Callable] = None):

        self.target_url = target_url.rstrip('/')
        self.max_depth = max_depth
        self.delay = delay
        self.visited_urls: Set[str] = set()
        self.vulnerabilities: List[Dict] = []
        self.progress_callback = progress_callback

        # Enhanced plugin loading
        if plugins is None:
            if plugin_names:
                self.plugins = load_plugins(plugin_names)
            else:
                self.plugins = load_plugins()  # Load all plugins
        else:
            self.plugins = plugins

        print(f"🔌 LOADED PLUGINS: {[plugin.name for plugin in self.plugins]}")

        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=max_workers)
        self.stop_flag = threading.Event()

        # Progress tracking
        self.total_operations = 0
        self.completed_operations = 0
        self.current_operation = "Initializing..."

        # Setup session with proper headers
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (compatible; VulnerabilityScanner/1.0)',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive'
        })

        # Disable SSL verification for testing
        self.session.verify = False

    def update_progress(self, operation: str):
        """Update progress and notify callback"""
        self.completed_operations += 1
        self.current_operation = operation

        if self.progress_callback:
            try:
                self.progress_callback(
                    self.completed_operations, 
                    max(self.total_operations, 1), 
                    operation
                )
            except Exception as e:
                logger.error(f"Progress callback error: {e}")

    def request_stop(self):
        """Request the scanner to stop"""
        self.stop_flag.set()

    def is_stopped(self) -> bool:
        """Check if the scanner should stop"""
        return self.stop_flag.is_set()

    def normalize_url(self, url: str) -> str:
        """Normalize URL by parsing and rebuilding it without fragment"""
        try:
            parsed = urllib.parse.urlparse(url)
            normalized = parsed._replace(fragment='').geturl()
            return normalized
        except Exception:
            return url

    @staticmethod
    def looks_like_html(text: str) -> bool:
        """Check if the text looks like HTML content"""
        if text is None:
            return False
        lowered = text.strip().lower()
        return (lowered.startswith('<!doctype html') or 
                lowered.startswith('<html') or 
                '<html' in lowered or
                '</html>' in lowered)

    @staticmethod
    def is_static_resource(url: str) -> bool:
        """Check if URL points to a static resource"""
        static_extensions = ('.png', '.jpg', '.jpeg', '.gif', '.svg', '.css',
                           '.js', '.ico', '.woff', '.ttf', '.pdf', '.zip',
                           '.mp4', '.mp3', '.avi', '.mov', '.wmv')
        return url.lower().endswith(static_extensions)

    def estimate_operations(self):
        """Estimate total number of operations for progress tracking"""
        # This is a rough estimate - will be refined during actual crawling
        estimated_pages = min(50, 2 ** self.max_depth)  # Cap at 50 pages
        estimated_forms_per_page = 3
        plugins_per_form = len(self.plugins)

        self.total_operations = estimated_pages * estimated_forms_per_page * plugins_per_form
        self.total_operations = max(self.total_operations, 10)  # Minimum operations

    def crawl(self, url: str, depth: int = 0):
        """Crawl the website and discover forms to test"""
        if self.is_stopped():
            return

        if depth > self.max_depth or url in self.visited_urls:
            return

        self.visited_urls.add(url)
        self.update_progress(f"Crawling: {url} (depth: {depth})")
        logger.info(f"Crawling: {url} (depth: {depth})")

        try:
            time.sleep(self.delay)
            response = self.session.get(url, timeout=10)

            content_type = response.headers.get('Content-Type', '').lower()
            if 'text/html' not in content_type:
                return

            if not self.looks_like_html(response.text):
                return

            soup = BeautifulSoup(response.text, "html.parser")

            # Find and test forms
            forms = soup.find_all("form")
            form_futures = []

            for form in forms:
                if self.is_stopped():
                    return

                form_futures.append(
                    self.executor.submit(self.test_form, url, form)
                )

            # Wait for all form tests to complete
            concurrent.futures.wait(form_futures)

            # Find links for further crawling
            links = []
            for a_tag in soup.find_all('a', href=True):
                link = urllib.parse.urljoin(url, a_tag['href'])
                link = self.normalize_url(link)

                if (link.startswith(self.target_url) and
                    not self.is_static_resource(link) and
                    link not in self.visited_urls and
                    '#' not in link):  # Skip anchor links
                    links.append(link)

            # Limit the number of links to crawl to prevent infinite crawling
            links = links[:10]  # Max 10 links per page

            # Crawl discovered links
            crawl_futures = []
            for link in links:
                if self.is_stopped():
                    return

                crawl_futures.append(
                    self.executor.submit(self.crawl, link, depth + 1)
                )

            concurrent.futures.wait(crawl_futures)

        except requests.RequestException as e:
            logger.error(f"Request error processing {url}: {e}")
        except Exception as e:
            logger.error(f"Error processing {url}: {e}")

    def test_form(self, page_url: str, form: BeautifulSoup):
        """Test a form for vulnerabilities using loaded plugins"""
        if self.is_stopped():
            return

        try:
            form_action = form.get('action', '')
            self.update_progress(f"Testing form: {form_action}")

            # Run each plugin on the form
            for plugin in self.plugins:
                if self.is_stopped():
                    return

                try:
                    self.update_progress(f"Running {plugin.name} on form")
                    vulnerabilities = plugin.scan(self.session, page_url, form)

                    for vuln in vulnerabilities:
                        # Check if vulnerability already exists to avoid duplicates
                        if not any(v.get('url') == vuln.get('url') and
                                 v.get('type') == vuln.get('type') and
                                 v.get('payload') == vuln.get('payload')
                                 for v in self.vulnerabilities):

                            self.vulnerabilities.append(vuln)
                            logger.warning(f"[{vuln['type']}] Vulnerability found at {vuln['url']} "
                                         f"with payload '{vuln['payload']}' on inputs {vuln.get('inputs', [])}")

                except Exception as e:
                    logger.error(f"Error in plugin {plugin.name} on {page_url}: {e}")

        except Exception as e:
            logger.error(f"Error testing form on {page_url}: {e}")

    def run(self) -> List[Dict]:
        """Run the security scan and return results"""
        logger.info(f"Starting scan on {self.target_url} with depth {self.max_depth}")
        print(f"{colorama.Fore.GREEN}Starting scan on {self.target_url} with depth {self.max_depth}")

        try:
            self.estimate_operations()
            self.update_progress("Starting security scan...")

            # Start crawling from the target URL
            self.crawl(self.target_url)

            self.update_progress("Scan completed successfully")

        except Exception as e:
            logger.error(f"Scan error: {e}")
            self.update_progress(f"Scan failed: {str(e)}")
        finally:
            self.executor.shutdown(wait=True)

        logger.info(f"Scan completed. Found {len(self.vulnerabilities)} vulnerabilities.")
        print(f"\n{colorama.Fore.BLUE}Scan finished. Found {len(self.vulnerabilities)} potential vulnerabilities.\n")

        # Print vulnerabilities to console
        for v in self.vulnerabilities:
            print(f"{colorama.Fore.MAGENTA}[{v['type']}] at {v['url']} "
                  f"inputs: {v.get('inputs', [])} evidence: {v.get('evidence', v.get('payload'))}")

        return self.vulnerabilities

# CLI interface for standalone testing
if __name__ == '__main__':
    try:
        target = input("Enter the URL of the site to scan (with http/https): ").strip()
        if not target:
            print("No URL provided. Exiting.")
            exit(1)

        if not target.startswith(('http://', 'https://')):
            target = 'http://' + target

        depth = input("Enter max crawl depth (default 3): ").strip()
        delay = input("Enter delay between requests in seconds (default 0.1): ").strip()

        try:
            depth_val = int(depth) if depth else 3
        except ValueError:
            depth_val = 3

        try:
            delay_val = float(delay) if delay else 0.1
        except ValueError:
            delay_val = 0.1

        # Progress callback for CLI
        def progress_callback(current, total, operation):
            percentage = (current / total) * 100 if total > 0 else 0
            print(f"Progress: {percentage:.1f}% - {operation}")

        print(f"\nStarting scan of {target}")
        print(f"Max depth: {depth_val}")
        print(f"Delay: {delay_val}s")
        print("=" * 50)

        scanner = WebSecurityScanner(
            target_url=target,
            max_depth=depth_val,
            delay=delay_val,
            max_workers=5,
            progress_callback=progress_callback
        )

        results = scanner.run()

        print("\n" + "=" * 50)
        print("SCAN SUMMARY:")
        print(f"Total vulnerabilities found: {len(results)}")
        print(f"Pages crawled: {len(scanner.visited_urls)}")

        if results:
            print("\nVulnerabilities by type:")
            vuln_types = {}
            for vuln in results:
                vuln_type = vuln.get('type', 'Unknown')
                vuln_types[vuln_type] = vuln_types.get(vuln_type, 0) + 1

            for vuln_type, count in vuln_types.items():
                print(f"  {vuln_type}: {count}")
        else:
            print("No vulnerabilities found.")

    except KeyboardInterrupt:
        print("\nScan interrupted by user.")
    except Exception as e:
        print(f"\nError: {e}")
