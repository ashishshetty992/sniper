import yara
import sys
import os
import json
from pathlib import Path
from datetime import datetime
import time
import os
from collections import defaultdict

def find_and_scan_path(rules, search_path):
    """
    Smart path search and scan function.
    1. Checks if exact path exists
    2. If not, searches for the last folder name
    3. If not found, scans entire C drive
    """
    try:
        # Convert to Path object for easier manipulation
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

        # Search in common Windows directories
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

# def scan_directory(rules, directory_path):
#     """
#     Recursively scan a directory and its subdirectories
#     """
#     results = []
#     try:
#         for root, dirs, files in os.walk(directory_path):
#             for file in files:
#                 try:
#                     file_path = os.path.join(root, file)
#                     matches = rules.match(file_path)
#                     result = {
#                         "status": "success",
#                         "file": file_path,
#                         "matches": [str(match) for match in matches],
#                         "message": "Match found" if matches else "No match found"
#                     }
#                     print(json.dumps(result))
#                     if matches:  # Only append if matches found
#                         results.append(result)
#                 except Exception as e:
#                     # Skip files that can't be scanned
#                     continue
#         return results
#     except Exception as e:
#         result = {
#             "status": "error",
#             "message": f"Error scanning directory {directory_path}: {str(e)}"
#         }
#         print(json.dumps(result))
#         return None

def scan_directory(rules, directory_path):
    """
    Recursively scan a directory and its subdirectories with detailed analytics
    """    
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
        "size_scanned": 0,  # in bytes
        "largest_file": {"path": None, "size": 0},
        "smallest_file": {"path": None, "size": float('inf')},
        "matches_by_rule": defaultdict(int),
        "scan_times": []  # list to calculate average scan time
    }
    
    try:
        for root, dirs, files in os.walk(directory_path):
            for file in files:
                stats["total_files"] += 1
                try:
                    file_path = os.path.join(root, file)
                    file_size = os.path.getsize(file_path)
                    file_ext = os.path.splitext(file)[1].lower() or 'no_extension'
                    stats["file_types"][file_ext] += 1
                    stats["size_scanned"] += file_size
                    
                    # Track file size statistics
                    if file_size > stats["largest_file"]["size"]:
                        stats["largest_file"] = {"path": file_path, "size": file_size}
                    if file_size < stats["smallest_file"]["size"]:
                        stats["smallest_file"] = {"path": file_path, "size": file_size}
                    
                    # Time the scan for this file
                    file_scan_start = time.time()
                    matches = rules.match(file_path)
                    file_scan_time = time.time() - file_scan_start
                    stats["scan_times"].append(file_scan_time)
                    
                    stats["scanned_files"] += 1
                    if matches:
                        stats["files_with_matches"] += 1
                        stats["total_matches"] += len(matches)
                        for match in matches:
                            stats["matches_by_rule"][str(match.rule)] += 1
                    
                    result = {
                        "status": "success",
                        "file": file_path,
                        "file_size": file_size,
                        "scan_time": file_scan_time,
                        "matches": [str(match) for match in matches],
                        "message": "Match found" if matches else "No match found",
                        "timestamp": datetime.now().isoformat()
                    }
                    results.append(result)
                    print(json.dumps(result))
                    
                except Exception as e:
                    stats["error_files"] += 1
                    error_type = type(e).__name__
                    stats["error_types"][error_type] += 1
                    
                    error_result = {
                        "status": "error",
                        "file": file_path,
                        "error_type": error_type,
                        "message": str(e),
                        "timestamp": datetime.now().isoformat()
                    }
                    results.append(error_result)
                    print(json.dumps(error_result))
        
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
                "largest_file": {
                    "path": stats["largest_file"]["path"],
                    "size": stats["largest_file"]["size"]
                },
                "smallest_file": {
                    "path": stats["smallest_file"]["path"],
                    "size": stats["smallest_file"]["size"]
                },
                "file_types": dict(stats["file_types"])
            },
            "error_analysis": {
                "error_types": dict(stats["error_types"])
            },
            "rule_matches": {
                "matches_by_rule": dict(stats["matches_by_rule"])
            },
            "scan_info": {
                "start_time": datetime.fromtimestamp(stats["start_time"]).isoformat(),
                "end_time": datetime.now().isoformat(),
                "directory": directory_path
            }
        }
        print(json.dumps(summary))
        return results
        
    except Exception as e:
        result = {
            "status": "error",
            "message": f"Error scanning directory {directory_path}: {str(e)}",
            "timestamp": datetime.now().isoformat()
        }
        print(json.dumps(result))
        return None


def main():
    try:
        # Check if we have the correct number of arguments
        if len(sys.argv) != 3:
            result = {
                "status": "error",
                "message": "Usage: python script.py <rules_path> <scan_path>"
            }
            print(json.dumps(result))
            return

        # Get paths from command line arguments
        rules_path = sys.argv[1]
        scan_path = sys.argv[2]

        # write the paths in a file for debugging
        with open("paths.txt", "w") as f:
            f.write(f"rules_path: {rules_path}\nscan_path: {scan_path}")

        # Validate rules path
        if not os.path.exists(rules_path):
            result = {
                "status": "error",
                "message": f"Rules path does not exist: {rules_path}"
            }
            print(json.dumps(result))
            return

        # Compile YARA rules
        try:
            rules = yara.compile(rules_path)
        except Exception as e:
            result = {
                "status": "error",
                "message": f"Error compiling rules: {str(e)}"
            }
            print(json.dumps(result))
            return

        # Use the smart path search and scan function
        find_and_scan_path(rules, scan_path)

    except Exception as e:
        result = {
            "status": "error",
            "message": str(e)
        }
        print(json.dumps(result))

if __name__ == "__main__":
    main()