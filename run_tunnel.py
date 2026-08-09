import os
import re
import sys
import time
import socket
import subprocess
import threading

def find_free_port(start_port: int = 8095) -> int:
    port = start_port
    while True:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(("127.0.0.1", port))
                return port
            except OSError:
                port += 1

def run_uvicorn(port: int):
    print(f"[Server] Starting uvicorn on port {port}...", flush=True)
    app_dir = os.path.dirname(os.path.abspath(__file__))
    while True:
        try:
            cmd = [
                sys.executable, "-m", "uvicorn", "app:app", 
                "--host", "127.0.0.1", "--port", str(port), 
                "--log-level", "info"
            ]
            process = subprocess.Popen(cmd, cwd=app_dir)
            process.wait()
            print(f"[Server] Uvicorn exited with code {process.returncode}. Restarting in 2s...", flush=True)
        except Exception as e:
            print(f"[Server] Error running uvicorn: {e}. Restarting in 2s...", flush=True)
        time.sleep(2)

def run_tunnel(port: int):
    print(f"[Tunnel] Starting SSH tunnel for port {port}...", flush=True)
    url_pattern = re.compile(r'https?://[a-zA-Z0-9.-]+\.run|https?://[a-zA-Z0-9.-]+\.lhr\.life')
    
    while True:
        cmd = f"ssh -n -o StrictHostKeyChecking=no -R 80:127.0.0.1:{port} nokey@localhost.run"
        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                shell=True
            )
            
            for line in iter(process.stdout.readline, ''):
                sys.stdout.write(f"[Tunnel] {line}")
                sys.stdout.flush()
                
                matches = url_pattern.findall(line)
                for url in matches:
                    if "admin.localhost.run" in url or "docs" in url or url.strip().endswith("localhost.run"):
                        continue
                    print(f"\n==================================================")
                    print(f"RELEASE GATE PUBLIC URL: {url}/release-gate")
                    print(f"==================================================\n", flush=True)
                    try:
                        with open("tunnel_url.txt", "w") as f:
                            f.write(f"{url}/release-gate")
                    except Exception as e:
                        print(f"Error writing URL to file: {e}", flush=True)
            
            process.wait()
            print(f"[Tunnel] SSH process exited with code {process.returncode}. Restarting in 2s...", flush=True)
        except Exception as e:
            print(f"[Tunnel] Tunnel error: {e}. Restarting in 2s...", flush=True)
        time.sleep(2)

def main():
    port = find_free_port(8095)
    print(f"Selected Port: {port}", flush=True)
    server_thread = threading.Thread(target=run_uvicorn, args=(port,), daemon=True)
    server_thread.start()
    time.sleep(2)
    run_tunnel(port)

if __name__ == "__main__":
    main()
