#!/usr/bin/env python3
import subprocess, time, sys

UERANSIM = "/home/kali/UERANSIM/build"
GNB_CONF = "/home/kali/did-auth-5g/config/open5gs-gnb.yaml"
UE_CONF  = "/home/kali/did-auth-5g/config/open5gs-ue.yaml"
N = int(sys.argv[1]) if len(sys.argv) > 1 else 5
MODE = sys.argv[2] if len(sys.argv) > 2 else "did"

results = []
print(f"=== Registration Latency Test (n={N}, mode={MODE}) ===")

for i in range(1, N+1):
    subprocess.run(["pkill", "-f", "nr-ue"], capture_output=True)
    subprocess.run(["pkill", "-f", "nr-gnb"], capture_output=True)
    # Restart sidecar to clear cache for cold-start measurement
    if MODE == "did":
        subprocess.run(["pkill", "-f", "sidecar.py"], capture_output=True)
        time.sleep(1)
        subprocess.Popen(["python3", "/home/kali/did-auth-5g/sidecar/sidecar.py"],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(3)
    time.sleep(2)
    subprocess.Popen([f"{UERANSIM}/nr-gnb", "-c", GNB_CONF],
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(2)
    t_start = time.time()
    ue_proc = subprocess.Popen([f"{UERANSIM}/nr-ue", "-c", UE_CONF],
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True)
    latency = None
    deadline = time.time() + 60
    while time.time() < deadline:
        line = ue_proc.stdout.readline()
        if not line:
            time.sleep(0.1)
            continue
        if "PDU Session establishment is successful" in line or ("TUN interface" in line and "is up" in line):
            latency = int((time.time() - t_start) * 1000)
            break
        if "rejected" in line.lower():
            latency = -1
            break
    ue_proc.terminate()
    if latency and latency > 0:
        results.append(latency)
        print(f"  Run {i:2d}: {latency}ms  SUCCESS")
    else:
        print(f"  Run {i:2d}: FAILED or timeout")
    time.sleep(3)

if results:
    print(f"\n--- Summary ({MODE}) ---")
    print(f"Min: {min(results)}ms  Max: {max(results)}ms  Avg: {sum(results)//len(results)}ms")
    print(f"All: {results}")
    with open("/home/kali/did-auth-5g/thesis-results.txt", "a") as f:
        f.write(f"\n=== Registration Latency ({MODE}, n={N}) - {time.strftime('%Y-%m-%d %H:%M')} ===\n")
        for idx, lat in enumerate(results, 1):
            f.write(f"  Run {idx}: {lat}ms\n")
        f.write(f"  Min: {min(results)}ms  Max: {max(results)}ms  Avg: {sum(results)//len(results)}ms\n")
    print("Results saved.")
