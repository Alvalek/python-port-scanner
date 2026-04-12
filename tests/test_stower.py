import pytest
import socket
from unittest.mock import patch, MagicMock
from stower import STower

# --- Test 1: Initialization ---
def test_stower_initialization():
    """Test that the scanner initializes with correct attributes."""
    scanner = STower("127.0.0.1", start_port=80, end_port=90)
    assert scanner.target == "127.0.0.1"
    assert scanner.start_port == 80
    assert scanner.end_port == 90
    assert scanner.open_ports == []
    assert scanner.results == []

# --- Test 2: Successful Port Scan (Open Port) ---
@patch('socket.socket')
def test_scan_port_open(mock_socket_class):
    """Test scanning an open port with mocked socket."""
    # Setup mock behavior
    mock_socket_instance = MagicMock()
    mock_socket_instance.connect_ex.return_value = 0  # 0 means success (open)
    mock_socket_class.return_value = mock_socket_instance

    scanner = STower("127.0.0.1", start_port=80, end_port=80)
    
    # Run the scan
    scanner.scan_port(80)

    # Assertions
    assert 80 in scanner.open_ports
    assert len(scanner.results) == 1
    assert scanner.results[0]["port"] == 80
    assert scanner.results[0]["state"] == "OPEN"
    mock_socket_instance.connect_ex.assert_called_once_with(("127.0.0.1", 80))

# --- Test 3: Closed Port Scan ---
@patch('socket.socket')
def test_scan_port_closed(mock_socket_class):
    """Test scanning a closed port."""
    # Setup mock behavior
    mock_socket_instance = MagicMock()
    mock_socket_instance.connect_ex.return_value = 1  # Non-zero means closed
    mock_socket_class.return_value = mock_socket_instance

    scanner = STower("127.0.0.1", start_port=80, end_port=80)
    
    # Run the scan
    scanner.scan_port(80)

    # Assertions
    assert 80 not in scanner.open_ports
    assert len(scanner.results) == 0  # Closed ports are not stored in results
    mock_socket_instance.connect_ex.assert_called_once_with(("127.0.0.1", 80))

# --- Test 4: Banner Grabbing Logic ---
@patch('socket.socket')
def test_banner_grabbing(mock_socket_class):
    """Test that banner grabbing works when port is open."""
    mock_socket_instance = MagicMock()
    mock_socket_instance.connect_ex.return_value = 0
    
    # Mock the recv method to return a fake HTTP banner
    mock_socket_instance.recv.return_value = b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.41\r\n\r\n"
    
    mock_socket_class.return_value = mock_socket_instance

    scanner = STower("127.0.0.1", start_port=80, end_port=80)
    scanner.scan_port(80)

    # Assertions
    assert len(scanner.results) == 1
    assert scanner.results[0]["service"] == "Apache"
    assert "Apache/2.4.41" in scanner.results[0]["banner"]
    # Verify send was called
    mock_socket_instance.send.assert_called()

# --- Test 5: Export to JSON ---
import json
import os

def test_export_json(tmp_path):
    """Test exporting results to a JSON file."""
    scanner = STower("127.0.0.1", start_port=80, end_port=80)
    # Manually add a result to simulate a scan
    scanner.results = [{"port": 80, "state": "OPEN", "service": "HTTP", "banner": "Test"}]
    
    output_file = tmp_path / "test_output.json"
    scanner.export_results(str(output_file), "json")

    assert output_file.exists()
    with open(output_file, 'r') as f:
        data = json.load(f)
    
    assert len(data) == 1
    assert data[0]["port"] == 80

# --- Test 6: Export to CSV ---
import csv

def test_export_csv(tmp_path):
    """Test exporting results to a CSV file."""
    scanner = STower("127.0.0.1", start_port=80, end_port=80)
    scanner.results = [{"port": 80, "state": "OPEN", "service": "HTTP", "banner": "Test"}]
    
    output_file = tmp_path / "test_output.csv"
    scanner.export_results(str(output_file), "csv")

    assert output_file.exists()
    with open(output_file, 'r') as f:
        reader = csv.DictReader(f)
        rows = list(reader)
    
    assert len(rows) == 1
    assert rows[0]["port"] == "80"
