import streamlit as st
import pandas as pd

from scanner import main_scanner

st.set_page_config(
    page_title="Vulnerability Scanner",
    layout="wide"
)

# Header
st.markdown("<h1 style='text-align: center;'>Vulnerability Scanner</h1>", unsafe_allow_html=True)

# Ethical disclaimer
st.markdown("""
<p style='text-align: center; color: #ff6b6b;'>
This tool should only be used on systems you own or have permission to test. 
Unauthorized scanning may be illegal in your jurisdiction.
</p>
""", unsafe_allow_html=True)

st.markdown("---")

# Scan form
col1, col2, col3 = st.columns([1, 2, 1])

with col2:
    # Target IP input field
    target_ip = st.text_input(
        "Target IP Address",
        placeholder="192.168.1.10 or 127.0.0.1",
        help="Enter the IP address to scan"
    )

    # Custom ports checkbox and input
    use_custom_ports = st.checkbox("Use custom ports")
    custom_ports_input = None

    if use_custom_ports:
        custom_ports_input = st.text_input(
            "Ports (comma-separated)",
            placeholder="22,80,443,3306",
            help="Enter comma-separated port numbers"
        )

    # Scan button
    scan_button = st.button("Scan", type="primary", width='stretch')

st.markdown("---")

# Handle scan results
if scan_button:
    if not target_ip:
        st.error("Please enter a target IP address")
    else:
        # Parse custom ports if provided
        ports_list = None
        if use_custom_ports and custom_ports_input:
            try:
                ports_list = [int(p.strip()) for p in custom_ports_input.split(',')]
            except ValueError:
                st.error("Invalid port format. Use comma-separated numbers (e.g., 22,80,443)")
                st.stop()

        # Run the scan with a loading spinner
        with st.spinner(f'Scanning {target_ip}...'):
            scan_results = main_scanner.run_full_scan(target_ip, ports_list)

        # Check if scan was successful
        if not scan_results['success']:
            st.error(f"Scan failed: {scan_results.get('error', 'Unknown error')}")
            st.stop()

        # Display success message
        st.success(f"Scan completed for {target_ip}")

        # Risk Assessment section
        st.markdown("<h3 style='text-align: center;'>Risk Assessment</h3>", unsafe_allow_html=True)
        risk = scan_results['risk_assessment']

        # Display metrics in 3 columns
        metric_col1, metric_col2, metric_col3 = st.columns(3)

        with metric_col1:
            st.metric("Risk Level", risk['risk_level'])

        with metric_col2:
            st.metric("Risk Score", risk['total_score'])

        with metric_col3:
            st.metric("Total Findings", risk['total_findings'])

        # Severity Distribution chart
        st.markdown("<h3 style='text-align: center;'>Severity Distribution</h3>", unsafe_allow_html=True)
        severity_data = pd.DataFrame([
            {'Severity': sev, 'Count': count}
            for sev, count in risk['severity_breakdown'].items()
            if count > 0
        ])

        if not severity_data.empty:
            # Using bar chart for severity distribution
            st.bar_chart(severity_data.set_index('Severity'))
        else:
            st.info("No vulnerabilities found")

        # Open Ports section
        st.markdown("<h3 style='text-align: center;'>Open Ports</h3>", unsafe_allow_html=True)
        if scan_results['open_ports']:
            ports_df = pd.DataFrame(scan_results['open_ports'])
            st.dataframe(ports_df, width="stretch", hide_index=True)
        else:
            st.info("No open ports found")

        # Vulnerability Findings section
        st.markdown("<h3 style='text-align: center;'>Vulnerability Findings</h3>", unsafe_allow_html=True)
        if scan_results['findings']:
            findings_df = pd.DataFrame(scan_results['findings'])
            # Display the findings table
            st.dataframe(findings_df, width="stretch", hide_index=True)
        else:
            st.success("No vulnerabilities found")

else:
    # Show instructions when no scan is running
    col1, col2, col3 = st.columns([1, 2, 1])

    with col2:
        st.markdown("<h3 style='text-align: center;'>How to use</h3>", unsafe_allow_html=True)

        st.markdown("""
        <div style="background-color:#0E2A47; padding:20px; border-radius:10px;">
            <ol>
                <li>Enter a target IP address</li>
                <li>Enable custom ports and specify which ports to scan (Optional)</li>
                <li>Click "Scan" to begin</li>
            </ol>
            <p><strong>Note:</strong> Make sure you have generated the CVE database first by running:</p>
            <pre style="background-color:#08263F; padding:10px; border-radius:5px;">python scripts/fetch_nvd.py</pre>
        </div>
        """, unsafe_allow_html=True)