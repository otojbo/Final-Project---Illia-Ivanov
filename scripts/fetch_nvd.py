import requests
import csv
import time
import os

# NVD API endpoint
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def fetch_cves_for_service(service_keyword, max_results=5):
    """
    Fetches CVEs from NVD API for a specific service/software
    I chose to fetch 5 CVEs per service to keep the database manageable
    """
    print(f"Searching for {service_keyword} vulnerabilities...")

    params = {
        'keywordSearch': service_keyword,
        'resultsPerPage': max_results
    }

    try:
        # Making GET request to NVD API with 30 second timeout
        response = requests.get(NVD_API_URL, params=params, timeout=30)
        response.raise_for_status()
        data = response.json()

        cve_list = []

        if 'vulnerabilities' in data:
            for item in data['vulnerabilities']:
                cve_data = item.get('cve', {})
                cve_id = cve_data.get('id', 'Unknown')

                # Extract description from the CVE data
                descriptions = cve_data.get('descriptions', [])
                summary = descriptions[0].get('value', 'No description available') if descriptions else 'No description available'

                # Get severity score - I check v3.1 first, then v3.0, then fall back to v2
                # This is because newer CVEs use CVSS v3 scoring
                metrics = cve_data.get('metrics', {})
                severity = 'Unknown'

                if 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
                    severity = metrics['cvssMetricV31'][0].get('cvssData', {}).get('baseSeverity', 'Unknown')
                elif 'cvssMetricV30' in metrics and metrics['cvssMetricV30']:
                    severity = metrics['cvssMetricV30'][0].get('cvssData', {}).get('baseSeverity', 'Unknown')
                elif 'cvssMetricV2' in metrics and metrics['cvssMetricV2']:
                    # For v2, I had to manually map numeric scores to severity levels
                    base_score = metrics['cvssMetricV2'][0].get('cvssData', {}).get('baseScore', 0)
                    if base_score >= 9.0:
                        severity = 'CRITICAL'
                    elif base_score >= 7.0:
                        severity = 'HIGH'
                    elif base_score >= 4.0:
                        severity = 'MEDIUM'
                    else:
                        severity = 'LOW'

                # Build the NVD reference URL for each CVE
                reference = f"https://nvd.nist.gov/vuln/detail/{cve_id}"

                # I'm using a placeholder for version ranges because parsing the actual
                # affected versions from NVD is really complicated.
                # For this project the scanner will match all versions.
                version_range = ">=0.0,<999.0"

                cve_entry = {
                    'cve_id': cve_id,
                    'service': service_keyword,
                    'version_range': version_range,
                    'severity': severity,
                    'summary': summary[:200] + '...' if len(summary) > 200 else summary,
                    'mitigation': 'Update to latest version',
                    'reference': reference
                }

                cve_list.append(cve_entry)
                print(f"  ✓ Found {cve_id} ({severity})")

        return cve_list

    except requests.exceptions.RequestException as e:
        print(f"  ✗ Error fetching CVEs for {service_keyword}: {e}")
        return []


def save_to_csv(cve_data, filename='data/cve_database.csv'):
    # Saves CVE data to CSV file

    fieldnames = ['cve_id', 'service', 'version_range', 'severity', 'summary', 'mitigation', 'reference']

    with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(cve_data)

    print(f"\n✓ Saved {len(cve_data)} CVEs to {filename}")


def main():
    """
    Fetches CVEs for common network services
    I selected these services because they're commonly found in networks
    """
    print("=" * 60)
    print("NVD CVE Database Fetcher")
    print("=" * 60)

    # I chose these specific services because they're commonly scanned
    # and likely to have known vulnerabilities in the NVD database
    services = [
        ('OpenSSH', 5),
        ('Apache HTTP', 5),
        ('nginx', 4),
        ('MySQL', 5),
        ('vsftpd', 3),
        ('ProFTPD', 3)
    ]

    all_cves = []

    for service_name, count in services:
        cves = fetch_cves_for_service(service_name, max_results=count)
        all_cves.extend(cves)

        # NVD API rate limit is 5 requests per 30 seconds without an API key
        # I'm waiting 7 seconds between requests to stay under the limit
        print(f"  Waiting to avoid rate limit...\n")
        time.sleep(7)

    if all_cves:
        save_to_csv(all_cves)
        print(f"\n{'=' * 60}")
        print(f"Total CVEs fetched: {len(all_cves)}")
        print(f"{'=' * 60}")
    else:
        print("\nx No CVEs were fetched. Please check your internet connection.")


if __name__ == '__main__':
    main()
