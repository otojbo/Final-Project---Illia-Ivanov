# INF 601 - Advanced Python
# Illia Ivanov
# Final Project

from flask import Flask, request, jsonify
from scanner import main_scanner

app = Flask(__name__)

@app.route('/', methods=['GET'])
def home():
    # Returns basic API information
    return jsonify({
        'name': 'Vulnerability Scanner API',
        'version': '1.0',
        'endpoints': {
            '/scan': 'POST - Scan a target IP for vulnerabilities',
            '/health': 'GET - Check API health status'
        }
    })


@app.route('/health', methods=['GET'])
def health_check():
    # Simple health check endpoint
    return jsonify({
        'status': 'healthy',
        'message': 'API is running'
    })


@app.route('/scan', methods=['POST'])
def scan_target():
    """
    Main scanning endpoint which accepts target IP and returns vulnerability results
    Expects JSON: {"target": "192.168.1.10", "ports": [22, 80, 443]}
    """
    try:
        # Get JSON data from request body
        request_data = request.get_json()

        if not request_data:
            return jsonify({
                'success': False,
                'error': 'No JSON data provided'
            }), 400

        # Extract target IP
        target_ip = request_data.get('target')
        if not target_ip:
            return jsonify({
                'success': False,
                'error': 'Missing required field: target'
            }), 400

        # Extract ports list / optional
        ports_list = request_data.get('ports', None)

        # Run the actual scan using our main scanner
        scan_results = main_scanner.run_full_scan(target_ip, ports_list)

        # Return error if scan failed
        if not scan_results['success']:
            return jsonify(scan_results), 400

        return jsonify(scan_results), 200

    except Exception as error:
        # Catch any unexpected errors
        return jsonify({
            'success': False,
            'error': f'Internal server error: {str(error)}'
        }), 500


@app.errorhandler(404)
def not_found(error):
    # Handle requests to non-existent endpoints
    return jsonify({
        'success': False,
        'error': 'Endpoint not found'
    }), 404


if __name__ == '__main__':
    print("=" * 60)
    print("Vulnerability Scanner API")
    print("=" * 60)
    print("Starting Flask server on http://127.0.0.1:5000")
    print("\nAvailable endpoints:")
    print("  GET  /         - API information")
    print("  GET  /health   - Health check")
    print("  POST /scan     - Scan a target")
    print("\nExample usage:")
    print('  curl -X POST http://127.0.0.1:5000/scan \\')
    print('       -H "Content-Type: application/json" \\')
    print('       -d \'{"target": "192.168.1.10"}\'')
    print("=" * 60)

    app.run(debug=False, host='127.0.0.1', port=5000)