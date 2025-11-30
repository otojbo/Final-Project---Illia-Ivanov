from scanner import cve_loader, port_scanner, version_matcher, risk_scorer


def run_full_scan(target_ip, ports=None):
    """
    Main function that orchestrates the entire scanning process
    I broke this into 5 steps to make it easy to understand and debug
    """
    print("=" * 60)
    print(f"Starting vulnerability scan for {target_ip}")
    print("=" * 60)

    # 1. Make sure the IP address is valid before wasting time scanning
    if not port_scanner.validate_ip_address(target_ip):
        return {
            'success': False,
            'error': f'Invalid IP address: {target_ip}',
            'target': target_ip
        }

    # 2. Load the CVE database that we generated with fetch_nvd.py
    print("\n[1/5] Loading CVE database...")
    cve_database = cve_loader.load_cve_database()

    if cve_database is None or cve_database.empty:
        return {
            'success': False,
            'error': 'Failed to load CVE database. Run scripts/fetch_nvd.py first.',
            'target': target_ip
        }

    # 3. Scan the target for open ports using nmap
    print("\n[2/5] Scanning ports...")
    open_ports = port_scanner.scan_target(target_ip, ports)

    # If no ports are open, return empty results (not an error)
    if not open_ports:
        print("No open ports found or scan failed")
        return {
            'success': True,
            'target': target_ip,
            'open_ports': [],
            'findings': [],
            'risk_assessment': {
                'total_score': 0,
                'total_findings': 0,
                'severity_breakdown': {},
                'risk_level': 'No vulnerabilities found'
            }
        }

    # 4. Match found services against CVE database
    print("\n[3/5] Matching CVEs...")
    all_findings = []

    for port_info in open_ports:
        port_number = port_info['port']
        service_name = port_info['service']
        service_version = port_info['version']
        service_product = port_info.get('product', '')

        # Normalize the service name so it matches with our CVE database entries
        # For example, nmap returns 'ssh' but CVE database has 'OpenSSH'
        normalized_service = port_scanner.get_service_name_normalized(service_name, service_product)

        # Get all CVEs that affect this service
        matching_cves = cve_loader.get_cves_for_service(cve_database, normalized_service)

        if matching_cves.empty:
            print(f"  Port {port_number} ({service_name}): No CVEs found in database")
            continue

        # Check each CVE to see if the detected version is vulnerable
        for _, cve_row in matching_cves.iterrows():
            version_range = cve_row['version_range']

            is_vulnerable = version_matcher.match_version(service_version, version_range)

            # For demonstration, i'm showing CVEs even if version is unknown
            if service_version == 'unknown':
                is_vulnerable = True

            if is_vulnerable:
                finding = {
                    'port': port_number,
                    'service': service_name,
                    'version': service_version,
                    'cve_id': cve_row['cve_id'],
                    'severity': cve_row['severity'],
                    'summary': cve_row['summary'],
                    'mitigation': cve_row['mitigation'],
                    'reference': cve_row['reference']
                }
                all_findings.append(finding)
                print(f"  ✓ Port {port_number}: Found {cve_row['cve_id']} ({cve_row['severity']})")

    # 5. Calculate overall risk based on severity of findings
    print("\n[4/5] Calculating risk score...")
    risk_assessment = risk_scorer.calculate_risk_score(all_findings)

    print(f"\n[5/5] Scan complete!")
    print(f"  Total findings: {len(all_findings)}")
    print(f"  Risk level: {risk_assessment['risk_level']}")
    print(f"  Risk score: {risk_assessment['total_score']}")

    # Package everything into a nice dictionary for return
    scan_results = {
        'success': True,
        'target': target_ip,
        'open_ports': open_ports,
        'findings': all_findings,
        'risk_assessment': risk_assessment
    }

    return scan_results


def format_results_for_console(scan_results):
    """
    Formats scan results into a readable console report
    I created this separate function to keep the main scanner cleaner
    """
    if not scan_results['success']:
        return f"Scan failed: {scan_results.get('error', 'Unknown error')}"

    output = []
    output.append("\n" + "=" * 60)
    output.append(f"VULNERABILITY SCAN REPORT")
    output.append(f"Target: {scan_results['target']}")
    output.append("=" * 60)

    # Show all open ports found
    output.append(f"\nOPEN PORTS ({len(scan_results['open_ports'])} found):")
    for port_info in scan_results['open_ports']:
        output.append(f"  Port {port_info['port']}: {port_info['service']} ({port_info['version']})")

    # Show all vulnerabilities found
    findings = scan_results['findings']
    output.append(f"\nVULNERABILITIES ({len(findings)} found):")

    if findings:
        for finding in findings:
            output.append(f"\n  [{finding['severity']}] {finding['cve_id']}")
            output.append(f"    Port: {finding['port']} ({finding['service']})")
            # I truncate the summary to 150 chars to keep output readable
            output.append(f"    Summary: {finding['summary'][:150]}...")
            output.append(f"    Mitigation: {finding['mitigation']}")
    else:
        output.append("  No vulnerabilities found!")

    # Show risk assessment
    risk = scan_results['risk_assessment']
    output.append(f"\nRISK ASSESSMENT:")
    output.append(f"  Overall Risk: {risk['risk_level']}")
    output.append(f"  Risk Score: {risk['total_score']}")
    output.append(f"  Severity Breakdown:")
    for severity, count in risk['severity_breakdown'].items():
        if count > 0:
            output.append(f"    {severity}: {count}")

    output.append("\n" + "=" * 60)

    return "\n".join(output)