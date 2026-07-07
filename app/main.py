from publisher import load_config, copy_project, sanitize
from scanner import scan,generate_report
from collections import Counter


config = load_config()

copy_project(config)
sanitize(config)

findings = scan(config)
generate_report(config, findings)
print()


counter = Counter()

for item in findings:
    counter[item["type"]] += 1

print("\n==============================")
print("      Scan Summary")
print("==============================\n")

print(f"URLs          : {counter['URL']}")
print(f"Emails        : {counter['Email']}")
print(f"Windows Paths : {counter['Windows Path']}")
print(f"\nTotal Findings: {len(findings)}")

print("\n------------------------------\n")

current_file = ""

for item in findings:

    if item["file"] != current_file:
        current_file = item["file"]
        print(f"\n📄 {current_file}")

    print(f"   [{item['type']}]")
    print(f"   {item['value']}")