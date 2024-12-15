import yara
import sys
import os
import json
from pathlib import Path
from datetime import datetime
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
import mmap
import threading
import queue
import logging
from typing import List, Dict, Set

# Configuration
NUM_SCANNER_THREADS = max(4, min(os.cpu_count() or 4, 8))  # Balance between 4-8 threads
MAX_QUEUE_SIZE = 5000
MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB

# Global queues
file_queue = queue.Queue(maxsize=MAX_QUEUE_SIZE)

def collect_files(directory_path):
    """Collect files for scanning with proper error handling."""
    files = []
    try:
        for root, _, filenames in os.walk(directory_path):
            for filename in filenames:
                try:
                    file_path = os.path.join(root, filename)
                    if os.path.exists(file_path) and os.access(file_path, os.R_OK):
                        # Skip files that are too large
                        if os.path.getsize(file_path) <= MAX_FILE_SIZE:
                            files.append(file_path)
                except (PermissionError, OSError) as e:
                    logging.warning(f"Error accessing {filename}: {str(e)}")
    except Exception as e:
        logging.error(f"Error walking directory {directory_path}: {str(e)}")
    return files

def scan_worker(rules, stats_lock):
    """Worker function for scanning files."""
    while True:
        try:
            file_path = file_queue.get()
            if file_path is None:  # Poison pill
                file_queue.task_done()
                break
                
            result = scan_file(rules, file_path)
            
            # Update progress
            print(json.dumps({
                "status": "progress",
                "file": os.path.basename(file_path),  # Only show filename in progress
                "matches": len(result["matches"]) if result["status"] == "success" else 0
            }))
            
            file_queue.task_done()
            
        except Exception as e:
            logging.error(f"Error in scan worker: {str(e)}")
            if 'file_path' in locals():
                file_queue.task_done()

def scan_file(rules, file_path):
    """Scan a single file with YARA rules."""
    start_time = time.time()
    try:
        # Get file size
        file_size = os.path.getsize(file_path)
        
        # Skip large files
        if file_size > MAX_FILE_SIZE:
            return {
                "status": "error",
                "file": file_path,
                "error_type": "FileTooLarge",
                "error": f"File size {file_size} exceeds limit {MAX_FILE_SIZE}",
                "timestamp": datetime.now().isoformat()
            }
            
        # Scan file
        matches = rules.match(file_path)
        scan_time = time.time() - start_time
        
        return {
            "status": "success",
            "file": file_path,
            "matches": matches,
            "scan_time": scan_time,
            "file_size": file_size,
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        return {
            "status": "error",
            "file": file_path,
            "error_type": type(e).__name__,
            "error": str(e),
            "timestamp": datetime.now().isoformat()
        }

def scan_directory(rules, directory_path):
    """Recursively scan a directory and its subdirectories with detailed analytics"""    
    start_time = time.time()
    stats = {
        "total_files": 0,
        "scanned_files": 0,
        "error_files": 0,
        "files_with_matches": 0,
        "total_matches": 0,
        "bytes_scanned": 0,
        "file_types": defaultdict(int),
        "error_types": defaultdict(int),
        "largest_file": {"path": None, "size": 0},
        "smallest_file": {"path": None, "size": float('inf')},
        "matches_by_rule": defaultdict(int),
        "scan_times": [],
        "start_time": start_time
    }
    
    stats_lock = threading.Lock()
    
    def update_stats(result):
        with stats_lock:
            if result["status"] == "success":
                stats["scanned_files"] += 1
                file_size = result["file_size"]
                stats["bytes_scanned"] += file_size
                stats["scan_times"].append(result["scan_time"])
                
                # Track file extensions
                file_ext = os.path.splitext(result["file"])[1].lower() or 'no_extension'
                stats["file_types"][file_ext] += 1
                
                # Track matches
                if result["matches"]:
                    stats["files_with_matches"] += 1
                    stats["total_matches"] += len(result["matches"])
                    # Track matches by rule
                    for match in result["matches"]:
                        rule_name = str(match).split(' ')[0]
                        stats["matches_by_rule"][rule_name] += 1
                
                # Track file sizes
                if file_size > stats["largest_file"]["size"]:
                    stats["largest_file"] = {"path": result["file"], "size": file_size}
                if file_size < stats["smallest_file"]["size"]:
                    stats["smallest_file"] = {"path": result["file"], "size": file_size}
            else:
                stats["error_files"] += 1
                stats["error_types"][result.get("error_type", "unknown")] += 1
    
    try:
        # Collect all files first
        print(json.dumps({
            "status": "info",
            "message": "Collecting files for scanning..."
        }))
        
        files_to_scan = collect_files(directory_path)
        stats["total_files"] = len(files_to_scan)
        
        print(json.dumps({
            "status": "info",
            "message": f"Found {stats['total_files']} files to scan"
        }))
        
        # Create scanner threads
        scanner_threads = []
        for _ in range(NUM_SCANNER_THREADS):
            t = threading.Thread(target=scan_worker, args=(rules, stats_lock))
            t.daemon = True
            t.start()
            scanner_threads.append(t)
        
        # Feed files to the queue
        for file_path in files_to_scan:
            file_queue.put(file_path)
        
        # Add poison pills
        for _ in range(NUM_SCANNER_THREADS):
            file_queue.put(None)
        
        # Wait for all files to be processed
        file_queue.join()
        
        # Calculate final statistics
        total_time = time.time() - start_time
        avg_scan_time = sum(stats["scan_times"]) / len(stats["scan_times"]) if stats["scan_times"] else 0
        
        # Print final detailed summary
        summary = {
            "status": "completed",
            "scan_stats": {
                "total_files": stats["total_files"],
                "scanned_files": stats["scanned_files"],
                "files_with_matches": stats["files_with_matches"],
                "total_matches": stats["total_matches"],
                "error_files": stats["error_files"],
                "bytes_scanned": stats["bytes_scanned"],
                "total_time": total_time,
                "files_per_second": stats["scanned_files"] / total_time if total_time > 0 else 0,
                "average_scan_time": avg_scan_time,
                "file_types": dict(stats["file_types"]),
                "error_types": dict(stats["error_types"]),
                "largest_file": stats["largest_file"],
                "smallest_file": stats["smallest_file"],
                "matches_by_rule": dict(stats["matches_by_rule"])
            }
        }
        
        print(json.dumps(summary))
        
    except Exception as e:
        print(json.dumps({
            "status": "error",
            "error": str(e)
        }))
        raise

def find_and_scan_path(rules, search_path):
    """Smart path search and scan function."""
    # Normalize path for Windows
    search_path = str(Path(search_path))
    
    # Check if exact path exists
    if os.path.exists(search_path):
        print(json.dumps({
            "status": "info",
            "message": f"Found exact path: {search_path}"
        }))
        return scan_directory(rules, search_path)
    
    # Try to find the last folder name
    last_folder = os.path.basename(search_path)
    if not last_folder:  # Handle case where path ends with separator
        last_folder = os.path.basename(os.path.dirname(search_path))
    
    # Search for the last folder name in C drive
    try:
        for root, dirs, _ in os.walk("C:\\"):
            if last_folder in dirs:
                found_path = os.path.join(root, last_folder)
                print(json.dumps({
                    "status": "info",
                    "message": f"Found matching folder: {found_path}"
                }))
                return scan_directory(rules, found_path)
        
        # If not found, scan C drive
        print(json.dumps({
            "status": "info",
            "message": "Path not found, scanning C drive"
        }))
        return scan_directory(rules, "C:\\")
        
    except Exception as e:
        print(json.dumps({
            "status": "error",
            "error": f"Error in path search: {str(e)}"
        }))
        raise

def main():
    if len(sys.argv) != 3:
        print("Usage: python script.py <rules_file> <directory>")
        sys.exit(1)
    
    rules_path = sys.argv[1]
    search_path = sys.argv[2]
    
    try:
        # Compile YARA rules
        rules = yara.compile(rules_path)
        
        # Start scanning
        find_and_scan_path(rules, search_path)
        
    except Exception as e:
        print(json.dumps({
            "status": "error",
            "error": str(e)
        }))
        sys.exit(1)

if __name__ == "__main__":
    main()