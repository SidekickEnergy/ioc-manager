# main.py
import sys
import os

# Add the parent directory (backend/) to sys.path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if project_root not in sys.path:
    sys.path.insert(0, project_root)
    
import argparse
from core.enrichment.pipeline import run_enrichment  # moved logic here

def main():
    parser = argparse.ArgumentParser(description="IoC Manager - Enrich and Check IoCs")
    parser.add_argument("-i", "--input", nargs="+", required=True, help="IoC(s) to process")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    args = parser.parse_args()

    input_iocs = args.input
    verbose = args.verbose

    print(f"\n[+] Starting IoC enrichment pipeline for {len(input_iocs)} input(s)...")

    ioc_objects = run_enrichment(input_iocs, verbose)

    print(f"\n[+] Final Enrichment Summary ({len(ioc_objects)} IoC(s)):\n")

    for ioc in ioc_objects:
        print(f"[DEBUG] IoC type for {ioc.value}: {ioc.type}")
        print(ioc.summary())
        print("-" * 40)


if __name__ == "__main__":
    main()
