import argparse
import json
import csv
from scanner import main_scanner


def save_results_json(results, filename):
    """
    Saves scan results to JSON file
    I used indent=2 to make the JSON file readable and easy to inspect
    """
    with open(filename, 'w') as json_file:
        json.dump(results, json_file, indent=2)
    print(f"✓ Results saved to {filename}")


def save_results_csv(results, filename):
    """
    Saves scan findings to CSV file
    I chose CSV because it's easy to open in Excel or import into other tools
    """
    if not results['success'] or not results['findings']:
        print("No findings to save to CSV")
        return

    # I selected these specific fields because they contain the most important
    # vulnerability information for reporting
    fieldnames = ['port', 'service', 'version', 'cve_id', 'severity', 'summary', 'mitigation', 'reference']

    with open(filename, 'w', newline='', encoding='utf-8') as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results['findings'])

    print(f"✓ Results saved to {filename}")


def main():
    """
    Command line interface for vulnerability scanner
    I used argparse because it's the standard way to handle CLI arguments in Python
    and it automatically generates help messages
    """
    parser = argparse.ArgumentParser(
        description='Vulnerability Scanner - Scan network targets for known CVEs',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python cli.py --target 192.168.1.10
  python cli.py --target 192.168.1.10 --output json --file results.json
  python cli.py --target 127.0.0.1 --ports 22,80,443

DISCLAIMER: This tool is for authorized security testing only.
        """
    )

    # Target IP
    parser.add_argument(
        '--target',
        required=True,
        help='Target IP address to scan'
    )

    # Ports are optional, if not specified, scanner uses default ports
    parser.add_argument(
        '--ports',
        help='Comma-separated list of ports to scan (e.g., 22,80,443)',
        default=None
    )

    # I added three output formats to give users flexibility
    parser.add_argument(
        '--output',
        choices=['console', 'json', 'csv'],
        default='console',
        help='Output format (default: console)'
    )

    parser.add_argument(
        '--file',
        help='Output filename (required for json/csv output)',
        default=None
    )

    args = parser.parse_args()

    # Parse the comma-separated port list into actual integers
    # I handle the ValueError to give users a useful error message
    port_list = None
    if args.ports:
        try:
            port_list = [int(p.strip()) for p in args.ports.split(',')]
        except ValueError:
            print("Error: Invalid port format. Use comma-separated numbers (e.g., 22,80,443)")
            return

    # Make sure user provides a filename when using json/csv output
    if args.output in ['json', 'csv'] and not args.file:
        print(f"Error: --file is required when using --output {args.output}")
        return

    # Display ethical use warning before every scan
    print("\n!!!  ETHICAL USE DISCLAIMER !!!")
    print("This tool should only be used on systems you own or have permission to test.")
    print("Unauthorized scanning may be illegal in your jurisdiction.\n")

    # Run the actual scan
    scan_results = main_scanner.run_full_scan(args.target, port_list)

    # Output results in the format user requested
    if args.output == 'console':
        print(main_scanner.format_results_for_console(scan_results))
    elif args.output == 'json':
        save_results_json(scan_results, args.file)
    elif args.output == 'csv':
        save_results_csv(scan_results, args.file)


if __name__ == '__main__':
    main()