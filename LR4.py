import os
import subprocess
import socket
import ssl
import threading

# Сертифікати
CERT_FILE = "cert.pem"
KEY_FILE = "private.key"
PCAP_FILE = "capture.pcap"

# Конфігурація для сервера
HOST = 'localhost'
PORT = 4443

# Функція для генерації сертифікатів
def generate_certificates():
    if not os.path.exists(CERT_FILE) or not os.path.exists(KEY_FILE):
        print("[INFO] Certificates not found. Generating new certificates...")
        try:
            subprocess.run([
                "openssl", "req", "-x509", "-newkey", "rsa:4096",
                "-keyout", KEY_FILE, "-out", CERT_FILE,
                "-days", "365", "-nodes",
                "-subj", "/CN=localhost"
            ], check=True)
            print(f"[INFO] Certificates generated: {CERT_FILE}, {KEY_FILE}")
        except FileNotFoundError:
            print("[ERROR] OpenSSL is not installed. Please install OpenSSL to generate certificates.")
            exit(1)
        except subprocess.CalledProcessError as e:
            print(f"[ERROR] Failed to generate certificates: {e}")
            exit(1)
    else:
        print("[INFO] Certificates already exist. Skipping generation.")

# Функція для запуску захоплення трафіку
def start_packet_capture():
    if not os.path.exists(PCAP_FILE):
        print("[INFO] Starting packet capture...")
        try:
            capture_process = subprocess.Popen(
                ["tcpdump", "-i", "lo", "-w", PCAP_FILE, "port", str(PORT)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            print(f"[INFO] Packet capture started. Output file: {PCAP_FILE}")
            return capture_process
        except FileNotFoundError:
            print("[ERROR] tcpdump is not installed. Please install tcpdump to capture traffic.")
            return None
    else:
        print("[INFO] Capture file already exists. Skipping capture.")
        return None

# Функція для зупинки захоплення трафіку
def stop_packet_capture(capture_process):
    if capture_process:
        capture_process.terminate()
        capture_process.wait()
        print("[INFO] Packet capture stopped.")

# Функція сервера
def start_server():
    capture_process = start_packet_capture()  # Почати захоплення трафіку

    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
        sock.bind((HOST, PORT))
        sock.listen(5)
        print(f"[SERVER] Listening on {HOST}:{PORT}...")

        with context.wrap_socket(sock, server_side=True) as ssock:
            while True:
                conn, addr = ssock.accept()
                print(f"[SERVER] Connection established with {addr}")
                if not handle_client(conn):
                    break

    stop_packet_capture(capture_process)  # Зупинити захоплення трафіку

def handle_client(conn):
    try:
        with conn:
            while True:
                data = conn.recv(1024)
                if not data:
                    break
                message = data.decode()
                print(f"[SERVER] Received: {message}")

                if message.lower() == "exit":
                    conn.sendall("Goodbye!".encode())
                    print("[SERVER] Client disconnected.")
                    break

                response = "Message received"
                conn.sendall(response.encode())
    except Exception as e:
        print(f"[SERVER] Error: {e}")

    while True:
        choice = input("[SERVER] Do you want to continue? (Yes/No): ").strip().lower()
        if choice == 'yes':
            return True
        elif choice == 'no':
            print("[SERVER] Shutting down server.")
            return False

# Функція клієнта
def start_client():
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    context.load_verify_locations(CERT_FILE)

    try:
        with socket.create_connection((HOST, PORT)) as sock:
            with context.wrap_socket(sock, server_hostname=HOST) as ssock:
                print("[CLIENT] Secure connection established")
                print("[CLIENT] Type your message below. To exit, type 'exit'.")
                while True:
                    message = input("[CLIENT] Enter message: ")
                    if message.lower() == "exit":
                        ssock.sendall(message.encode())
                        print("[CLIENT] Exiting...")
                        break
                    ssock.sendall(message.encode())
                    data = ssock.recv(1024)
                    if data.decode() == "Message received":
                        print("[CLIENT] Message received")
    except Exception as e:
        print(f"[CLIENT] Error: {e}")

# Основна функція
if __name__ == "__main__":
    # Генеруємо сертифікати
    generate_certificates()

    # Вибір між сервером та клієнтом
    print("1. Start Server")
    print("2. Start Client")
    choice = input("Choose an option: ")

    if choice == '1':
        start_server()
    elif choice == '2':
        start_client()
    else:
        print("Invalid choice. Exiting.")