import yara
import sys
import os
import json
from pathlib import Path
from datetime import datetime
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
import mmap
import threading
import queue
from multiprocessing import cpu_count

# Optimize thread counts based on system
NUM_SCANNER_THREADS = min(32, cpu_count() * 4)   # More scanners for parallel processing

# Queue for managing file scanning
file_queue = queue.Queue(maxsize=50000)
result_queue = queue.Queue()

def collect_files(directory_path):
    """Collect all files upfront for better progress tracking."""
    print(json.dumps({
        "status": "info",
        "message": "Starting file collection..."
    }))
    
    files = []
    start_time = time.time()
    last_update = start_time
    
    for root, _, filenames in os.walk(directory_path):
        for filename in filenames:
            files.append(os.path.join(root, filename))
            
            # Progress update every second
            current_time = time.time()
            if current_time - last_update >= 1:
                print(json.dumps({
                    "status": "collecting",
                    "files_found": len(files),
                    "elapsed_time": current_time - start_time
                }))
                last_update = current_time
    
    print(json.dumps({
        "status": "info",
        "message": f"File collection complete. Found {len(files)} files"
    }))
    return files

def scan_worker(rules, stats_lock):
    """Worker function for scanning files."""
    while True:
        try:
            file_path = file_queue.get(timeout=0.5)  # Reduced timeout for faster thread termination
            if file_path is None:  # Poison pill
                break
                
            try:
                file_size = os.path.getsize(file_path)
                if file_size == 0:  # Skip empty files
                    result = {"status": "skipped", "file": file_path, "message": "Empty file"}
                else:
                    result = scan_file(rules, file_path)
            except Exception as e:
                result = {
                    "status": "error",
                    "file": file_path,
                    "error_type": type(e).__name__,
                    "message": str(e),
                    "timestamp": datetime.now().isoformat()
                }
            
            result_queue.put(result)
            
        except queue.Empty:
            continue
        finally:
            if 'file_path' in locals():
                file_queue.task_done()

def scan_file(rules, file_path):
    """Scan a single file with YARA rules."""
    try:
        file_size = os.path.getsize(file_path)
        file_scan_start = time.time()
        
        # Use memory mapping for large files
        if file_size > 10 * 1024 * 1024:  # 10MB
            try:
                with open(file_path, 'rb') as f:
                    with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                        matches = rules.match(data=mm)
            except Exception:
                # Fallback to direct file scanning if memory mapping fails
                matches = rules.match(file_path)
        else:
            matches = rules.match(file_path)
            
        file_scan_time = time.time() - file_scan_start
        
        return {
            "status": "success",
            "file": file_path,
            "file_size": file_size,
            "scan_time": file_scan_time,
            "matches": [str(match) for match in matches],
            "message": "Match found" if matches else "No match found",
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        return {
            "status": "error",
            "file": file_path,
            "error_type": type(e).__name__,
            "message": str(e),
            "timestamp": datetime.now().isoformat()
        }

def scan_directory(rules, directory_path):
    """Recursively scan a directory and its subdirectories with detailed analytics"""    
    results = []
    stats = {
        "total_files": 0,
        "scanned_files": 0,
        "error_files": 0,
        "files_with_matches": 0,
        "total_matches": 0,
        "start_time": time.time(),
        "file_types": defaultdict(int),
        "error_types": defaultdict(int),
        "size_scanned": 0,
        "largest_file": {"path": None, "size": 0},
        "smallest_file": {"path": None, "size": float('inf')},
        "matches_by_rule": defaultdict(int),
        "scan_times": []
    }
    
    stats_lock = threading.Lock()
    
    def update_stats(result):
        with stats_lock:
            if result["status"] == "success":
                stats["scanned_files"] += 1
                file_size = result["file_size"]
                stats["size_scanned"] += file_size
                stats["scan_times"].append(result["scan_time"])
                
                if result["matches"]:
                    stats["files_with_matches"] += 1
                    stats["total_matches"] += len(result["matches"])
                
                file_ext = os.path.splitext(result["file"])[1].lower() or 'no_extension'
                stats["file_types"][file_ext] += 1
                
                if file_size > stats["largest_file"]["size"]:
                    stats["largest_file"] = {"path": result["file"], "size": file_size}
                if file_size < stats["smallest_file"]["size"]:
                    stats["smallest_file"] = {"path": result["file"], "size": file_size}
            elif result["status"] != "skipped":
                stats["error_files"] += 1
                stats["error_types"][result.get("error_type", "unknown")] += 1
    
    try:
        # Collect all files first
        files_to_scan = collect_files(directory_path)
        stats["total_files"] = len(files_to_scan)
        
        if not files_to_scan:
            print(json.dumps({
                "status": "warning",
                "message": "No files found to scan"
            }))
            return []
        
        # Create scanner threads
        scanner_threads = []
        for _ in range(NUM_SCANNER_THREADS):
            t = threading.Thread(target=scan_worker, args=(rules, stats_lock))
            t.daemon = True
            t.start()
            scanner_threads.append(t)
        
        # Feed files to queue
        for file_path in files_to_scan:
            file_queue.put(file_path)
            
        # Add poison pills
        for _ in range(NUM_SCANNER_THREADS):
            file_queue.put(None)
        
        # Process results as they come in
        completed_files = 0
        last_progress_time = time.time()
        
        while completed_files < stats["total_files"]:
            try:
                result = result_queue.get(timeout=0.5)
                if result:
                    update_stats(result)
                    results.append(result)
                    completed_files += 1
                    
                    # Print progress every second
                    current_time = time.time()
                    if current_time - last_progress_time >= 1:
                        last_progress_time = current_time
                        elapsed_time = current_time - stats["start_time"]
                        files_per_second = completed_files / elapsed_time if elapsed_time > 0 else 0
                        
                        print(json.dumps({
                            "status": "progress",
                            "completed": completed_files,
                            "total": stats["total_files"],
                            "percent": (completed_files / stats["total_files"] * 100),
                            "files_per_second": files_per_second,
                            "elapsed_time": elapsed_time
                        }))
                    
            except queue.Empty:
                # Check if all threads are dead (indicating an error)
                if all(not t.is_alive() for t in scanner_threads):
                    print(json.dumps({
                        "status": "error",
                        "message": "All scanner threads died unexpectedly"
                    }))
                    break
                continue
        
        # Calculate final statistics
        total_time = time.time() - stats["start_time"]
        avg_scan_time = sum(stats["scan_times"]) / len(stats["scan_times"]) if stats["scan_times"] else 0
        
        summary = {
            "status": "summary",
            "scan_stats": {
                "total_files": stats["total_files"],
                "scanned_files": stats["scanned_files"],
                "error_files": stats["error_files"],
                "files_with_matches": stats["files_with_matches"],
                "total_matches": stats["total_matches"],
                "success_rate": (stats["scanned_files"] / stats["total_files"] * 100) if stats["total_files"] > 0 else 0
            },
            "timing": {
                "total_time_seconds": total_time,
                "average_scan_time": avg_scan_time,
                "files_per_second": stats["scanned_files"] / total_time if total_time > 0 else 0
            },
            "file_stats": {
                "total_size_bytes": stats["size_scanned"],
                "average_file_size": stats["size_scanned"] / stats["total_files"] if stats["total_files"] > 0 else 0,
                "largest_file": stats["largest_file"],
                "smallest_file": stats["smallest_file"],
                "file_types": dict(stats["file_types"])
            },
            "error_analysis": {
                "error_types": dict(stats["error_types"])
            }
        }
        print(json.dumps(summary))
        return results
        
    except Exception as e:
        error_result = {
            "status": "error",
            "message": f"Error scanning directory {directory_path}: {str(e)}"
        }
        print(json.dumps(error_result))
        return None

def find_and_scan_path(rules, search_path):
    """
    Smart path search and scan function.
    1. Checks if exact path exists
    2. If not, searches for the last folder name
    3. If not found, scans entire C drive
    """
    try:
        path = Path(search_path)
        
        # Case 1: Check if exact path exists
        if path.exists():
            print(json.dumps({
                "status": "info",
                "message": f"Found exact path: {path}"
            }))
            return scan_directory(rules, str(path))

        # Case 2: Try to find the last folder name
        last_folder = path.name
        print(json.dumps({
            "status": "info",
            "message": f"Searching for folder: {last_folder}"
        }))

        search_locations = [
            "C:\\Users",
            "C:\\Program Files",
            "C:\\Program Files (x86)",
            "C:\\Windows",
            "C:\\ProgramData"
        ]

        for base_path in search_locations:
            if os.path.exists(base_path):
                for root, dirs, files in os.walk(base_path):
                    if last_folder in dirs:
                        found_path = os.path.join(root, last_folder)
                        print(json.dumps({
                            "status": "info",
                            "message": f"Found matching folder: {found_path}"
                        }))
                        return scan_directory(rules, found_path)

        # Case 3: If nothing found, scan C drive
        print(json.dumps({
            "status": "info",
            "message": "Path not found, scanning entire C drive"
        }))
        return scan_directory(rules, "C:\\")

    except Exception as e:
        result = {
            "status": "error",
            "message": f"Error in path search: {str(e)}"
        }
        print(json.dumps(result))
        return None

def main():
    if len(sys.argv) < 3:
        print(json.dumps({
            "status": "error",
            "message": "Usage: python yara_scan_with_pool.py <rule_file> <search_path>"
        }))
        sys.exit(1)

    rule_file = sys.argv[1]
    search_path = sys.argv[2]

    try:
        rules = yara.compile(rule_file)
        find_and_scan_path(rules, search_path)
    except Exception as e:
        print(json.dumps({
            "status": "error",
            "message": f"Error: {str(e)}"
        }))
        sys.exit(1)

if __name__ == "__main__":
    main()