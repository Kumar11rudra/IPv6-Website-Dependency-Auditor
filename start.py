#!/usr/bin/env python3
"""Launcher for A3-PS027-TC039 (IPv6 Website & Dependency Readiness Auditor).
Starts both the FastAPI backend and the React/Vite frontend concurrently,
handles live log streaming, and ensures clean shutdown on Ctrl+C.
"""
import os
import signal
import subprocess
import sys
import threading
import time
import urllib.request

ROOT = os.path.dirname(os.path.abspath(__file__))
BACKEND_DIR = os.path.join(ROOT, "backend")
FRONTEND_DIR = os.path.join(ROOT, "frontend")

processes = []


def stream_logs(pipe, prefix):
    try:
        for line in iter(pipe.readline, b""):
            print(f"[{prefix}] {line.decode('utf-8', errors='replace')}", end="", flush=True)
    except Exception:
        pass


def wait_for_url(url, timeout_s=15):
    t0 = time.time()
    while time.time() - t0 < timeout_s:
        try:
            with urllib.request.urlopen(url, timeout=1.0) as resp:
                if resp.status == 200:
                    return True
        except Exception:
            time.sleep(0.4)
    return False


def shutdown(*_):
    print("\n[launcher] Shutting down servers gracefully...")
    for p in processes:
        if p.poll() is None:
            try:
                if sys.platform == "win32":
                    subprocess.run(["taskkill", "/F", "/T", "/PID", str(p.pid)],
                                   capture_output=True, check=False)
                else:
                    p.terminate()
            except Exception:
                pass
    print("[launcher] All services stopped.")
    sys.exit(0)


def get_python_executable():
    candidates = [
        os.path.join(BACKEND_DIR, ".venv", "bin", "python"),
        os.path.join(BACKEND_DIR, ".venv", "Scripts", "python.exe"),
        os.path.join(ROOT, ".venv", "bin", "python"),
        os.path.join(ROOT, ".venv", "Scripts", "python.exe"),
    ]
    for c in candidates:
        if os.path.isfile(c):
            return c
    return sys.executable


def free_port(port):
    if sys.platform == "win32":
        try:
            out = subprocess.check_output(f"netstat -ano | findstr :{port}", shell=True).decode()
            pids = set()
            for line in out.splitlines():
                parts = line.strip().split()
                if len(parts) >= 5 and f":{port}" in parts[1] and parts[3] == "LISTENING":
                    pids.add(parts[4])
            for pid in pids:
                subprocess.run(f"taskkill /F /PID {pid}", shell=True, capture_output=True)
        except Exception:
            pass
    else:
        try:
            out = subprocess.check_output(f"lsof -ti :{port}", shell=True).decode().strip()
            for pid in out.split():
                if pid:
                    subprocess.run(["kill", "-9", pid], capture_output=True, check=False)
        except Exception:
            pass


def main():
    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    print("=" * 66)
    print(" IPv6 Website & Dependency Readiness Auditor (A3-PS027-TC039)")
    print("=" * 66)

    free_port(8000)
    free_port(5173)

    py_bin = get_python_executable()
    print(f"[launcher] Using Python runtime: {py_bin}")

    # 1. Start Backend (FastAPI / Uvicorn)
    print("[launcher] Starting backend on http://127.0.0.1:8000 ...")
    backend_cmd = [
        py_bin, "-m", "uvicorn", "app.main:app",
        "--host", "127.0.0.1", "--port", "8000", "--reload"
    ]
    backend_proc = subprocess.Popen(
        backend_cmd,
        cwd=BACKEND_DIR,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT
    )
    processes.append(backend_proc)

    t_backend = threading.Thread(target=stream_logs, args=(backend_proc.stdout, "BACKEND"), daemon=True)
    t_backend.start()

    # Wait for backend health check
    if wait_for_url("http://127.0.0.1:8000/api/health", timeout_s=10):
        print("[launcher] Backend is healthy at http://127.0.0.1:8000/docs")
    else:
        print("[launcher] Warning: backend health check timed out, proceeding anyway...")

    # 2. Start Frontend (Vite)
    print("[launcher] Starting frontend on http://localhost:5173 ...")
    npm_cmd = "npm.cmd" if sys.platform == "win32" else "npm"
    frontend_proc = subprocess.Popen(
        [npm_cmd, "run", "dev"],
        cwd=FRONTEND_DIR,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT
    )
    processes.append(frontend_proc)

    t_frontend = threading.Thread(target=stream_logs, args=(frontend_proc.stdout, "FRONTEND"), daemon=True)
    t_frontend.start()

    time.sleep(1.5)

    print("\n" + "=" * 66)
    print("  SERVICES RUNNING:")
    print("  - Frontend Dashboard: http://localhost:5173")
    print("  - Backend API:        http://localhost:8000")
    print("  - Interactive Docs:   http://localhost:8000/docs")
    print("=" * 66)
    print("  Press Ctrl+C to terminate both servers.\n")

    try:
        while True:
            for p in processes:
                if p.poll() is not None:
                    print(f"[launcher] A service process (PID {p.pid}) exited with code {p.returncode}.")
                    shutdown()
            time.sleep(1)
    except KeyboardInterrupt:
        shutdown()


if __name__ == "__main__":
    main()
