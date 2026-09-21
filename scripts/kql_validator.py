import argparse
import re
import sys
import glob

def validate_kql(file_path):
    with open(file_path, 'r', encoding='utf-8') as f:
         content = f.read()

    errors = []

    # Check for basic KQL patterns
    if not (re.search(r'\|\s*where ', content, re.IGNORECASE) or 
            re.search(r'\|\s*summarize ', content, re.IGNORECASE) or 
            re.search(r'\|\s*extend ', content, re.IGNORECASE)):
        # Highly simplistic heuristic, but catches obvious non-queries in large files
        errors.append("Warning: Could not find common KQL operators (| where, | summarize, | extend).")

    # Look for trailing pipes which cause syntax errors in Azure Sentinel
    if re.search(r'\|\s*$', content):
        errors.append("Error: Query ends with a trailing pipe character (|).")

    # Look for common case sensitivity mistakes (Timegenerated vs TimeGenerated)
    if 'Timegenerated' in content:
        errors.append("Warning: Found 'Timegenerated'. Ensure it is properly capitalized as 'TimeGenerated' for schema accuracy.")

    return errors

def main():
    parser = argparse.ArgumentParser(description="Basic regex-based KQL validator.")
    parser.add_argument("path", help="Path to a .kql or .json file containing KQL queries, or a directory path.")
    
    args = parser.parse_args()
    
    files_to_check = []
    
    if '*' in args.path or '?' in args.path:
        files_to_check = glob.glob(args.path)
    else:
        files_to_check = [args.path]

    total_errors = 0
    for file_path in files_to_check:
        try:
             print(f"Validating: {file_path}")
             errors = validate_kql(file_path)
             if errors:
                 for err in errors:
                     print(f"  - {err}")
                 total_errors += 1
             else:
                 print("  - OK")
        except Exception as e:
             print(f"  - Failed to read/parse {file_path}: {e}")
             total_errors += 1
             
    if total_errors > 0:
         sys.exit(1)
    
if __name__ == "__main__":
    main()
