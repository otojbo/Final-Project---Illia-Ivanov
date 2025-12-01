import nmap
import ipaddress

# I chose these ports because they're the most commonly used
DEFAULT_PORTS = [21, 22, 80, 443, 3306, 3389, 5432, 8080]


def validate_ip_address(ip_string):
    """
    Validates if the input is a valid IP address
    I'm using the ipaddress library because it handles both IPv4 and IPv6
    """
    try:
        ipaddress.ip_address(ip_string)
        return True
    except ValueError:
        return False


def scan_target(target_ip, ports=None, timeout=10):
    #Scans the target IP for open ports and identifies running services

    if not validate_ip_address(target_ip):
        print(f"Error: Invalid IP address: {target_ip}")
        return []

    if ports is None:
        ports = DEFAULT_PORTS

    # nmap expects ports as a comma-separated string like "22,80,443"
    ports_string = ','.join(map(str, ports))

    print(f"Scanning {target_ip} on ports: {ports_string}")

    try:
        # Initialize the nmap scanner
        network_scanner = nmap.PortScanner()

        # I'm using -sV for service version detection and -T4 for faster scanning,
        # -T4 is aggressive but acceptable for authorized testing
        network_scanner.scan(target_ip, ports_string, arguments='-sV -T4')

        scan_results = []

        # Check if the target responded
        if target_ip not in network_scanner.all_hosts():
            print(f"No results for {target_ip}")
            return []

        host_info = network_scanner[target_ip]

        # Usually this will be 'tcp', but I'm iterating to be thorough
        for protocol in host_info.all_protocols():
            port_list = host_info[protocol].keys()

            for port_number in port_list:
                port_info = host_info[protocol][port_number]
                port_state = port_info['state']

                # I only care about open ports, closed/filtered ports aren't useful
                if port_state == 'open':
                    service_name = port_info.get('name', 'unknown')
                    service_product = port_info.get('product', '')
                    service_version = port_info.get('version', 'unknown')

                    # Create a banner by combining product name and version
                    # This helps with CVE matching later
                    service_banner = f"{service_product} {service_version}".strip()
                    if not service_banner:
                        service_banner = service_name

                    result_entry = {
                        'port': port_number,
                        'service': service_name,
                        'version': service_version,
                        'banner': service_banner,
                        'product': service_product
                    }

                    scan_results.append(result_entry)
                    print(f"  ✓ Port {port_number}: {service_name} ({service_banner})")

        return scan_results

    except nmap.PortScannerError as error:
        print(f"Nmap error: {error}")
        print("Make sure nmap is installed on your system")
        return []
    except Exception as error:
        print(f"Error during scan: {error}")
        return []


def get_service_name_normalized(service_name, product_name):
    """
    Normalizes service names to match CVE database entries
    I created this because nmap returns names like "ssh" but CVE database
    has "OpenSSH" so they need to match, for vulnerability detection
    """
    # I manually mapped common service names to their CVE database equivalents
    service_mapping = {
        'ssh': 'OpenSSH',
        'http': 'Apache HTTP',
        'https': 'Apache HTTP',
        'mysql': 'MySQL',
        'ftp': 'vsftpd',
    }

    service_lower = service_name.lower()

    # Check product name first since it provides more specific identification
    # This handles cases where service is generic (like http) but product reveals the actual software (nginx)
    if product_name:
        product_lower = product_name.lower()
        if 'apache' in product_lower:
            return 'Apache HTTP'
        elif 'nginx' in product_lower:
            return 'nginx'
        elif 'openssh' in product_lower:
            return 'OpenSSH'
        elif 'mysql' in product_lower:
            return 'MySQL'
        elif 'ftp' in product_lower:
            if 'vsftpd' in product_lower:
                return 'vsftpd'
            elif 'proftpd' in product_lower:
                return 'ProFTPD'

    # If product name didn't match, try the generic service mapping
    if service_lower in service_mapping:
        return service_mapping[service_lower]

    # If nothing matches, just return the original name
    return service_name