import yara
import os
import sys
import json

def compile_yara_rules(rule_path):
    """Compiles the YARA rules."""
    try:
        return yara.compile(filepath=rule_path)
    except yara.SyntaxError as e:
        return {"error": f"Error in YARA rules: {str(e)}"}
    except Exception as e:
        return {"error": f"Unexpected error compiling rules: {str(e)}"}

def scan_file(rules, file_path):
    """Scans a single file with the compiled YARA rules."""
    try:
        if isinstance(rules, dict) and "error" in rules:
            return rules
        
        matches = rules.match(file_path)
        result = {
            "status": "success",
            "file": file_path,
            "matches": [str(match) for match in matches],
            "message": "Match found" if matches else "No match found"
        }
        print(json.dumps(result))
        return result
    except Exception as e:
        result = {
            "status": "error",
            "file": file_path,
            "error": str(e),
            "message": f"Error scanning file"
        }
        print(json.dumps(result))
        return result

def scan_directory(rules, directory_path):
    """Scans all files in a directory with the compiled YARA rules."""
    try:
        for root, _, files in os.walk(directory_path):
            for file in files:
                file_path = os.path.join(root, file)
                scan_file(rules, file_path)
    except Exception as e:
        result = {
            "status": "error",
            "directory": directory_path,
            "error": str(e),
            "message": "Error scanning directory"
        }
        print(json.dumps(result))

def main():
    try:
        # Check if we have the correct number of arguments
        if len(sys.argv) != 3:
            result = {
                "status": "error",
                "message": "Usage: python test_yara_agent.py <rules_path> <scan_path>"
            }
            print(json.dumps(result))
            return

        # Get paths from command line arguments
        rules_path = sys.argv[1]
        scan_path = sys.argv[2]

        # write the paths in a file
        with open("paths.txt", "w") as f:
            f.write(f"rules_path: {rules_path}\nscan_path: {scan_path}")

        # Read the paths from the file
        with open("paths.txt", "r") as f:
            paths = f.read().splitlines()
            rules_path = paths[0].split(": ")[1]
            scan_path = paths[1].split(": ")[1]


        # Validate paths
        if not os.path.exists(rules_path):
            result = {
                "status": "error",
                "message": f"Rules path does not exist: {rules_path}"
            }
            print(json.dumps(result))
            return

        if not os.path.exists(scan_path):
            result = {
                "status": "error",
                "message": f"Scan path does not exist: {scan_path}"
            }
            print(json.dumps(result))
            return

        # Compile the YARA rules
        rules = compile_yara_rules(rules_path)
        
        # If compilation failed, return the error
        if isinstance(rules, dict) and "error" in rules:
            print(json.dumps(rules))
            return

        # Scan based on path type
        if os.path.isfile(scan_path):
            scan_file(rules, scan_path)
        elif os.path.isdir(scan_path):
            scan_directory(rules, scan_path)
        else:
            result = {
                "status": "error",
                "message": f"Invalid scan path type: {scan_path}"
            }
            print(json.dumps(result))

    except Exception as e:
        result = {
            "status": "error",
            "message": f"Unexpected error: {str(e)}"
        }
        print(json.dumps(result))

if __name__ == "__main__":
    main()