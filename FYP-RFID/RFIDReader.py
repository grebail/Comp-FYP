import socket

def extract_middle_segment(hex_data):
    """Extract the segment '00000000' from the HEX string."""
    if len(hex_data) >= 16:
        return hex_data[8:16]  # Extract the segment '00000000'
    return None

def start_rfid_server(host='0.0.0.0', port=65432):
    # Create a TCP/IP socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        # Bind the socket to the address and port
        server_socket.bind((host, port))
        server_socket.listen()
        print(f"Listening for RFID data on {host}:{port}...")

        while True:
            # Wait for a connection
            connection, client_address = server_socket.accept()
            with connection:
                print(f"Connected by {client_address}")
                while True:
                    data = connection.recv(1024)
                    if not data:
                        break
                    
                    # Convert received bytes to hex
                    hex_data = data.hex().upper()  # Convert bytes to HEX string
                    middle_segment = extract_middle_segment(hex_data)
                    
                    if middle_segment:
                        print(middle_segment)  # Print only the extracted segment
                    else:
                        print("No valid segment found.")

if __name__ == "__main__":
    start_rfid_server()