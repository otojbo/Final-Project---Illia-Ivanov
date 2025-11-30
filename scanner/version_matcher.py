from packaging import version
import re


def parse_version_range(version_range_string):
    """
    Parses version range string like ">=7.0,<8.9"
    Returns list of (operator, version) tuples
    """
    if not version_range_string or version_range_string.strip() == "":
        return []

    # Split by comma to get individual conditions
    conditions = version_range_string.split(',')
    parsed_conditions = []

    for condition in conditions:
        condition = condition.strip()

        # Match operator and version number
        # Supports: >=, <=, >, <, ==, =
        match = re.match(r'([><=]+)([\d.]+)', condition)
        if match:
            operator = match.group(1)
            version_number = match.group(2)
            parsed_conditions.append((operator, version_number))

    return parsed_conditions


def compare_versions(service_version, operator, target_version):
    """
    Compares two versions using the specified operator
    Returns True if condition is met, False otherwise
    """
    try:
        service_ver = version.parse(service_version)
        target_ver = version.parse(target_version)

        if operator == '>=' or operator == '=>':
            return service_ver >= target_ver
        elif operator == '<=' or operator == '=<':
            return service_ver <= target_ver
        elif operator == '>':
            return service_ver > target_ver
        elif operator == '<':
            return service_ver < target_ver
        elif operator == '==' or operator == '=':
            return service_ver == target_ver
        else:
            print(f"Unknown operator: {operator}")
            return False

    except Exception as error:
        print(f"Error comparing versions: {error}")
        return False


def match_version(service_version, version_range_string):
    """
    Checks if a service version falls within the specified range
    Returns True if version is vulnerable, False otherwise
    """
    if not service_version or service_version == "unknown":
        # If version is unknown, we can't determine vulnerability
        # Return False for unknown versions to avoid false positives
        return False

    # Parse the version range
    conditions = parse_version_range(version_range_string)

    if not conditions:
        return False

    # All conditions must be met (AND logic)
    for operator, target_version in conditions:
        if not compare_versions(service_version, operator, target_version):
            return False

    return True


def extract_version_from_banner(service_banner, service_name):
    """
    Attempts to extract version number from service banner text
    Returns version string or "unknown"
    """
    if not service_banner:
        return "unknown"

    # I created two patterns to match different version formats:
    # x.y.z (like 2.4.6) or just x.y (like 7.4)

    version_patterns = [
        r'(\d+\.\d+\.\d+)',  # Match x.y.z
        r'(\d+\.\d+)',  # Match x.y
    ]

    for pattern in version_patterns:
        match = re.search(pattern, service_banner)
        if match:
            return match.group(1)

    return "unknown"