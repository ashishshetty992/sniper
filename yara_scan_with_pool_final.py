import yara
import sys
import os
import json
from pathlib import Path
from datetime import datetime
import time
from collections import defaultdict
import mmap
import threading
import queue
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor, as_completed
import platform
import ctypes
import itertools
import asyncio
import logging
from typing import List, Dict, Set
import signal
import psutil

# Define skip patterns for directories to ignore
SKIP_PATTERNS = {
    '.git',
    'node_modules',
    '__pycache__',
    'venv',
    '.venv',
    '.idea',
    '.vscode'
}

class Config:
    # Optimized system configuration
    TOTAL_CPU_CORES = psutil.cpu_count(logical=True)
    AVAILABLE_MEMORY = psutil.virtual_memory().available
    MAX_WORKERS = max(2, min(TOTAL_CPU_CORES // 2, 8))  # Reduced worker count
    BATCH_SIZE = 50  # Smaller batch size
    
    # Enhanced I/O settings
    CHUNK_SIZE = 25000  # Reduced chunk size
    IO_BUFFER_SIZE = 32768  # Reduced buffer size
    
    # File size limits
    MAX_FILE_SIZE = 250 * 1024 * 1024  # Reduced max file size to 250MB
    MIN_FILE_SIZE = 1
    MMAP_THRESHOLD = 5 * 1024 * 1024  # Reduced mmap threshold to 5MB
    
    # Performance settings
    PROGRESS_INTERVAL = 2.0  # Increased progress interval
    MAX_QUEUE_SIZE = 5000  # Reduced queue size

def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )

def normalize_path(path: str) -> str:
    """Normalize path for Windows"""
    return path.replace('/', '\\')

def batch_scan_files(batch_args):
    """Process a batch of files at once to reduce IPC overhead"""
    file_paths, rules_path = batch_args
    results = []
    rules = yara.compile(rules_path)
    
    for file_path in file_paths:
        try:
            if not os.path.exists(file_path) or not os.access(file_path, os.R_OK):
                continue
                
            file_size = os.path.getsize(file_path)
            if not Config.MIN_FILE_SIZE <= file_size <= Config.MAX_FILE_SIZE:
                continue
                
            scan_start = time.time()
            
            try:
                # Read file in chunks for better memory management
                if file_size >= Config.MMAP_THRESHOLD:
                    with open(file_path, 'rb') as f:
                        # Use smaller chunks for mmap
                        chunk_size = min(file_size, 10 * 1024 * 1024)  # 10MB chunks
                        with mmap.mmap(f.fileno(), chunk_size, access=mmap.ACCESS_READ) as mm:
                            matches = rules.match(data=mm)
                else:
                    with open(file_path, 'rb', buffering=Config.IO_BUFFER_SIZE) as f:
                        # Read in smaller chunks
                        content = b''
                        while True:
                            chunk = f.read(Config.CHUNK_SIZE)
                            if not chunk:
                                break
                            content += chunk
                        matches = rules.match(data=content)
                        del content  # Explicitly delete to free memory
                
                results.append({
                    "status": "success",
                    "file": file_path,
                    "file_size": file_size,
                    "scan_time": time.time() - scan_start,
                    "matches": [str(match) for match in matches],
                    "timestamp": datetime.now().isoformat()
                })
            except Exception as e:
                results.append({
                    "status": "error",
                    "file": file_path,
                    "error_type": type(e).__name__,
                    "message": str(e)
                })
        except:
            continue
    
    return results

async def collect_files(search_path: str):
    """Optimized file collection with async support"""
    files = []
    try:
        for root, _, filenames in os.walk(search_path, followlinks=False):
            # Convert path separators to forward slashes for consistent matching
            normalized_path = root.replace(os.sep, '/')
            # Skip directories that match any of the patterns
            if any(pattern in normalized_path.split('/') for pattern in SKIP_PATTERNS):
                continue
                
            for filename in filenames:
                try:
                    file_path = os.path.join(root, filename)
                    if os.path.exists(file_path) and os.access(file_path, os.R_OK):
                        files.append(file_path)
                except Exception as e:
                    logging.error(f"Error processing file {filename}: {str(e)}")
                    continue
                
                # Process in chunks to avoid memory issues
                if len(files) >= Config.CHUNK_SIZE:
                    yield files
                    files = []
                    # Allow other async operations to run
                    await asyncio.sleep(0)
    except Exception as e:
        logging.error(f"Error collecting files: {str(e)}")
    
    if files:  # Yield remaining files
        yield files

async def find_path_to_scan(search_path: str) -> str:
    """
    Smart path search function.
    1. Checks if exact path exists
    2. If not, searches for the last folder name
    3. If not found, returns C:\ drive
    """
    search_path = normalize_path(search_path)
    
    # Check if exact path exists
    if os.path.exists(search_path):
        logging.info(f"Found exact path: {search_path}")
        return search_path
        
    # Get the last folder name from the path
    last_folder = os.path.basename(search_path.rstrip('\\'))
    logging.info(f"Searching for folder: {last_folder}")
    
    # Search for the last folder name in C drive
    try:
        for root, dirs, _ in os.walk("C:\\"):
            # Skip directories that match skip patterns
            if any(skip in root for skip in Config.SKIP_PATTERNS):
                continue
                
            if last_folder in dirs:
                found_path = os.path.join(root, last_folder)
                logging.info(f"Found matching folder: {found_path}")
                return found_path
            
            await asyncio.sleep(0)  # Allow other async operations
    except Exception as e:
        logging.error(f"Error while searching for path: {str(e)}")
    
    # If nothing found, return C drive
    logging.warning(f"Path not found: {search_path}. Defaulting to C:\\")
    return "C:\\"

async def process_batch_results(batch_results: List[Dict], stats: Dict):
    """Process batch results with detailed statistics"""
    for result in batch_results:
        if result["status"] == "success":
            stats["scanned_files"] += 1
            file_size = result["file_size"]
            stats["bytes_scanned"] += file_size
            stats["scan_times"].append(result["scan_time"])
            
            # Track file extensions
            file_ext = os.path.splitext(result["file"])[1].lower() or 'no_extension'
            stats["file_types"][file_ext] += 1
            
            # Track file sizes
            if file_size > stats["largest_file"]["size"]:
                stats["largest_file"] = {"path": result["file"], "size": file_size}
            if file_size < stats["smallest_file"]["size"]:
                stats["smallest_file"] = {"path": result["file"], "size": file_size}
            
            # Track matches
            if result["matches"]:
                stats["files_with_matches"] += 1
                stats["total_matches"] += len(result["matches"])
                stats["matches"] += 1
                # Add file to matched_files list with its matches
                stats["matched_files"].append({
                    "file": result["file"],
                    "matches": result["matches"],
                    "scan_time": result["scan_time"]
                })
                # Track matches by rule
                for match in result["matches"]:
                    rule_name = str(match).split(' ')[0]  # Extract rule name from match string
                    stats["matches_by_rule"][rule_name] += 1
        else:
            stats["errors"] += 1
            stats["error_types"][result.get("error_type", "unknown")] += 1

async def monitor_progress(stats: Dict, total_files: int, start_time: float):
    """Efficient progress monitoring"""
    last_update = time.time()
    while stats["scanned_files"] + stats["errors"] < total_files:
        current_time = time.time()
        if current_time - last_update >= Config.PROGRESS_INTERVAL:
            elapsed = current_time - start_time
            completed = stats["scanned_files"] + stats["errors"]
            
            print(json.dumps({
                "status": "progress",
                "completed": completed,
                "total": total_files,
                "percent": (completed / total_files * 100),
                "files_per_second": completed / elapsed if elapsed > 0 else 0,
                "bytes_scanned": stats["bytes_scanned"],
                "matches": stats["matches"],
                "errors": stats["errors"],
                "elapsed_time": elapsed
            }))
            
            last_update = current_time
        await asyncio.sleep(0.1)

async def scan_files(rules_path: str, search_path: str):
    """Optimized main scanning function with smart path search"""
    setup_logging()
    
    # Normalize paths for Windows
    rules_path = normalize_path(rules_path)
    
    if not os.path.exists(rules_path):
        logging.error(f"Rules file not found: {rules_path}")
        return
    
    # Use smart path search
    search_path = await find_path_to_scan(search_path)
    logging.info(f"Starting scan with path: {search_path}")
    
    try:
        # Initialize statistics with more detailed metrics
        stats = {
            "scanned_files": 0,
            "errors": 0,
            "matches": 0,
            "bytes_scanned": 0,
            "file_types": defaultdict(int),
            "error_types": defaultdict(int),
            "largest_file": {"path": None, "size": 0},
            "smallest_file": {"path": None, "size": float('inf')},
            "matches_by_rule": defaultdict(int),
            "scan_times": [],
            "files_with_matches": 0,
            "total_matches": 0,
            "matched_files": [],  # List to store files with matches
            "total_time": 0  # Total execution time
        }
        
        start_time = time.time()
        total_files = 0
        
        # Create process pool for scanning
        with ProcessPoolExecutor(max_workers=Config.MAX_WORKERS) as executor:
            # Start progress monitoring
            monitor_task = asyncio.create_task(monitor_progress(stats, float('inf'), start_time))
            
            # Process files in batches
            futures = []
            async for file_batch in collect_files(search_path):
                total_files += len(file_batch)
                
                # Split into smaller batches for better load balancing
                for i in range(0, len(file_batch), Config.BATCH_SIZE):
                    batch = file_batch[i:i + Config.BATCH_SIZE]
                    futures.append(executor.submit(batch_scan_files, (batch, rules_path)))
                
                # Update total_files in monitor_task
                monitor_task.cancel()
                monitor_task = asyncio.create_task(monitor_progress(stats, total_files, start_time))
            
            # Process results as they complete
            for future in as_completed(futures):
                try:
                    batch_results = future.result()
                    await process_batch_results(batch_results, stats)
                except Exception as e:
                    logging.error(f"Error processing batch: {str(e)}")
                    stats["errors"] += 1
        
        # Cancel monitoring
        monitor_task.cancel()
        
        # Calculate final statistics
        stats["total_time"] = time.time() - start_time
        avg_scan_time = sum(stats["scan_times"]) / len(stats["scan_times"]) if stats["scan_times"] else 0
        
        # Print final detailed summary
        print(json.dumps({
            "status": "completed",
            "scan_stats": {
                "total_files": total_files,
                "scanned_files": stats["scanned_files"],
                "files_with_matches": stats["files_with_matches"],
                "total_matches": stats["total_matches"],
                "errors": stats["errors"],
                "bytes_scanned": stats["bytes_scanned"],
                "total_time": stats["total_time"],
                "files_per_second": stats["scanned_files"] / stats["total_time"] if stats["total_time"] > 0 else 0,
                "average_scan_time": avg_scan_time,
                "file_types": dict(stats["file_types"]),
                "error_types": dict(stats["error_types"]),
                "largest_file": stats["largest_file"],
                "smallest_file": stats["smallest_file"],
                "matches_by_rule": dict(stats["matches_by_rule"]),
                "matched_files": stats["matched_files"]  # List of files with matches
            }
        }, indent=2))
        
    except Exception as e:
        logging.error(f"Scanning error: {str(e)}")
        raise

def main():
    if len(sys.argv) < 3:
        print(json.dumps({
            "status": "error",
            "message": "Usage: python script.py <rule_file> <search_path>"
        }))
        sys.exit(1)
    
    try:
        asyncio.run(scan_files(sys.argv[1], sys.argv[2]))
    except Exception as e:
        print(json.dumps({
            "status": "error",
            "message": str(e)
        }))
        sys.exit(1)

if __name__ == "__main__":
    main()