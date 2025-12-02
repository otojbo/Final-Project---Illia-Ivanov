# INF 601 - Advanced Python
# Illia Ivanov
# Final Project

import pandas as pd
import os


def load_cve_database(csv_path='data/cve_database.csv'):
    """
    Loads CVE database from CSV file
    I'm using pandas because it makes working with CSV data much easier
    """
    # Check if the database file exists before trying to load it
    if not os.path.exists(csv_path):
        print(f"Error: CVE database not found at {csv_path}")
        print("Please run 'python scripts/fetch_nvd.py' to generate the database first.")
        return None

    try:
        cve_dataframe = pd.read_csv(csv_path)

        # Make sure all required columns are present in the CSV
        required_columns = ['cve_id', 'service', 'version_range', 'severity', 'summary', 'mitigation', 'reference']
        missing_columns = [col for col in required_columns if col not in cve_dataframe.columns]

        if missing_columns:
            print(f"Error: CVE database is missing required columns: {missing_columns}")
            return None

        print(f"✓ Loaded {len(cve_dataframe)} CVEs from database")
        return cve_dataframe

    except Exception as error:
        print(f"Error loading CVE database: {error}")
        return None


def get_cves_for_service(cve_dataframe, service_name):
    """
    Filters CVEs for a specific service
    I use case-insensitive matching so 'OpenSSH' matches 'openssh'
    """
    if cve_dataframe is None:
        return pd.DataFrame()

    # Search for service name ignoring case differences
    matching_cves = cve_dataframe[cve_dataframe['service'].str.lower().str.contains(service_name.lower(), na=False)]
    return matching_cves


def validate_cve_database(cve_dataframe):
    """
    Validates CVE database integrity
    I check for duplicates and invalid severity levels to catch data issues
    """
    if cve_dataframe is None or cve_dataframe.empty:
        return False

    # Look for duplicate CVE IDs which shouldn't happen
    duplicates = cve_dataframe[cve_dataframe.duplicated(subset=['cve_id'], keep=False)]
    if not duplicates.empty:
        print(f"Warning: Found {len(duplicates)} duplicate CVE entries")

    # Make sure all severity values are valid
    valid_severities = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL', 'Unknown']
    invalid_severities = cve_dataframe[~cve_dataframe['severity'].isin(valid_severities)]
    if not invalid_severities.empty:
        print(f"Warning: Found {len(invalid_severities)} entries with invalid severity levels")

    return True