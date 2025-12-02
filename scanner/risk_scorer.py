# INF 601 - Advanced Python
# Illia Ivanov
# Final Project

# Severity to numeric weight mapping
SEVERITY_WEIGHTS = {
    'LOW': 1,
    'MEDIUM': 3,
    'HIGH': 5,
    'CRITICAL': 8,
    'Unknown': 2  # Default weight for unknown severity
}


def calculate_risk_score(findings_list):
    """
    Calculates overall risk score based on findings
    I multiply each finding by its severity weight to get a total risk score
    """
    total_score = 0
    severity_counts = {
        'LOW': 0,
        'MEDIUM': 0,
        'HIGH': 0,
        'CRITICAL': 0,
        'Unknown': 0
    }

    for finding in findings_list:
        severity = finding.get('severity', 'Unknown')

        # Add the weight of this vulnerability to the total
        weight = SEVERITY_WEIGHTS.get(severity, 2)
        total_score += weight

        # Keep track of how many vulnerabilities of each severity we found
        if severity in severity_counts:
            severity_counts[severity] += 1
        else:
            severity_counts['Unknown'] += 1

    risk_assessment = {
        'total_score': total_score,
        'total_findings': len(findings_list),
        'severity_breakdown': severity_counts,
        'risk_level': get_risk_level(total_score)
    }

    return risk_assessment


def get_risk_level(total_score):
    """
    Converts numeric risk score to risk level category
    I created these thresholds based on what seemed reasonable for classification
    """
    if total_score == 0:
        return 'No vulnerabilities found'
    elif total_score <= 5:
        return 'Low Risk'
    elif total_score <= 15:
        return 'Medium Risk'
    elif total_score <= 30:
        return 'High Risk'
    else:
        return 'Critical Risk'


def calculate_port_risk(port_number, findings_for_port):
    """
    Calculates risk score for a specific port
    Returns risk score for that port
    """
    port_score = 0

    for finding in findings_for_port:
        severity = finding.get('severity', 'Unknown')
        weight = SEVERITY_WEIGHTS.get(severity, 2)
        port_score += weight

    return port_score


def get_severity_color(severity):
    """
    Returns color code for severity level
    """
    color_mapping = {
        'CRITICAL': '#DC2626',  # Red
        'HIGH': '#EA580C',  # Orange
        'MEDIUM': '#F59E0B',  # Yellow
        'LOW': '#10B981',  # Green
        'Unknown': '#6B7280'  # Gray
    }

    return color_mapping.get(severity, '#6B7280')