
import json
import re

def fix_date(d):
    if not d:
        return d
    # If it already has timezone Z or offset, leave it (simple check)
    if d.endswith("Z") or re.search(r"[+-]\d{2}:\d{2}$", d):
        return d
    
    # If it ends in .000, replace with Z (or append Z if you prefer millisecond precision, but Go's RFC3339 parsing is strict)
    # Go's RFC3339 format: "2006-01-02T15:04:05Z07:00"
    if d.endswith(".000"):
        return d[:-4] + "Z"
        
    return d + "Z"

def main():
    with open("configs/cve_seed_extended.json", "r") as f:
        data = json.load(f)
    
    clean_data = []
    seen_ids = set()
    
    for item in data:
        if item["cve_id"] in seen_ids:
            continue
        seen_ids.add(item["cve_id"])
        
        # Validate critical fields
        if not item.get("published_date"):
            continue

        item["published_date"] = fix_date(item.get("published_date"))
        item["last_modified"] = fix_date(item.get("last_modified"))
        
        # Ensure last_modified is set
        if not item["last_modified"]:
            item["last_modified"] = item["published_date"]
            
        clean_data.append(item)
        
    with open("configs/cve_seed_final.json", "w") as f:
        json.dump(clean_data, f, indent=2)
        
    print(f"Fixed {len(clean_data)} CVEs")

if __name__ == "__main__":
    main()
