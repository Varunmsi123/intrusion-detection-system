# IPS Defender — Real-Time Intrusion Detection & Prevention System

A real-time network monitoring project that combines machine-learning-based intrusion classification with an intrusion prevention workflow and a live dashboard. It is designed to identify normal traffic and four attack categories—DoS, Probe, Remote-to-Local (R2L), and User-to-Root (U2R)—and display mitigation decisions.

> **Safety note:** The dashboard currently supports **Simulation (Safe)** mode. A displayed `BLOCK` or `DROP` event does not, by itself, prove that operating-system firewall rules were applied. Verify the active-enforcement implementation in an isolated test environment before relying on it.

## Features

- **Machine-learning classification:** Loads a trained Random Forest model and its supporting artifacts.
- **Attack categories:** Normal, DoS, Probe, R2L, and U2R.
- **Live packet monitoring:** Uses Scapy with Npcap on Windows for packet capture.
- **Prevention decision workflow:** Displays `ALLOW`, `RATE_LIMIT`, `BLOCK`, and `DROP` decisions.
- **Temporary blocklist:** Shows blocked source IPs, attack family, reason, and time-to-live (TTL).
- **Redis integration:** Stores IPS state when Redis is available; the backend may fall back to in-memory storage if Redis is unavailable.
- **Real-time dashboard:** Displays packet counters, attack statistics, active blocks, alerts, and traffic history.
- **Attack-flow simulations:** Dashboard controls for DoS Flood, Port Probe, R2L Exploit, and U2R Privilege test scenarios.
- **Protected IP allowlist:** The event stream can identify protected host, loopback, or gateway addresses.

## Attack categories

| Category | Description |
| --- | --- |
| Normal | Traffic classified as normal or legitimate |
| DoS | Denial-of-Service-like traffic patterns |
| Probe | Reconnaissance or port-scanning-like behavior |
| R2L | Remote-to-Local attack category |
| U2R | User-to-Root privilege-escalation category |

Classification quality depends on the trained model, input features, thresholds, and capture conditions. A classification is an alert, not proof that an event is malicious.

## Technology stack

- **Backend:** Python, Flask
- **Machine learning:** scikit-learn, Random Forest
- **Packet capture:** Scapy, Npcap (Windows)
- **State/cache:** Redis, with an in-memory fallback
- **Frontend:** JavaScript, HTML, CSS (frontend tooling depends on the project configuration)
- **Container support:** Docker for Redis

## Architecture

```text
Network interface
       |
       v
Scapy packet capture (Npcap on Windows)
       |
       v
Feature extraction / traffic processing
       |
       v
Trained ML model (Random Forest)
       |
       v
IPS decision logic
(ALLOW / RATE_LIMIT / BLOCK / DROP)
       |
       +------> Redis / in-memory state
       |
       v
Flask API + real-time event stream
       |
       v
Frontend dashboard
```

The exact feature-extraction and enforcement behavior depends on the implementation in the repository. Inspect the relevant code before treating the diagram as proof of OS-level enforcement.

## Repository structure

```text
intrusion-detection-system/
├── backend/
│   ├── app.py
│   ├── capture.py
│   ├── predict.py
│   ├── models/
│   ├── requirements.txt
│   └── ...
├── frontend/
│   └── ...
└── README.md
```

Some filenames or folders may differ between branches. Use the files present in your checked-out version.

## Prerequisites

- Windows 10/11 (the instructions below target Windows)
- Python compatible with the dependencies in `backend/requirements.txt`
- Node.js and npm for the frontend
- Docker Desktop (optional, for Redis)
- Npcap installed for Windows packet capture
- Administrator privileges may be required for some packet-capture configurations

## Getting started

### 1. Clone the repository

```powershell
git clone https://github.com/Varunmsi123/intrusion-detection-system.git
cd intrusion-detection-system
```

### 2. Set up the Python backend

```powershell
cd backend
py -m venv venv
.\venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

If PowerShell blocks virtual-environment activation, run this in the current terminal and retry activation:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\venv\Scripts\Activate.ps1
```

### 3. Install Npcap on Windows

Download Npcap from the [official Npcap website](https://npcap.com/#download) and run its installer. Enable **WinPcap API-compatible Mode** if the installer offers it and your capture library requires it.

Restart the terminal after installation. The capture interface and permissions can affect whether packet capture works. A capture thread starting does not guarantee that packets are being received successfully.

### 4. Start Redis (optional but recommended)

Make sure Docker Desktop is running, then open another terminal and run:

```powershell
docker run -d --name ips-redis -p 6379:6379 redis:7-alpine
```

If a container named `ips-redis` already exists, start it instead:

```powershell
docker start ips-redis
```

Verify the service:

```powershell
docker ps
docker exec ips-redis redis-cli ping
```

The expected response to `redis-cli ping` is:

```text
PONG
```

The backend must be configured to connect to `127.0.0.1:6379` (or the appropriate Redis host and port for your environment). If Redis is unavailable, this project may use its in-memory fallback, which is not shared across processes and may not survive a restart.

### 5. Run the backend

From the `backend/` directory, with the virtual environment activated:

```powershell
python app.py
```

The current configuration prints the Flask API address, typically:

- API: [http://127.0.0.1:5000](http://127.0.0.1:5000)

The root URL may not serve a webpage if the Flask app exposes only API routes.

### 6. Run the frontend

Open a **separate terminal**:

```powershell
cd path\to\intrusion-detection-system\frontend
npm install
npm run dev
```

Replace the example path with your actual repository path. Open the URL printed by the frontend development server. The backend currently prints `http://localhost:3000` as the expected frontend URL, but use the actual URL shown by your frontend tooling.

## Using the dashboard

1. Start Redis if you want the Redis-backed state store.
2. Start the Flask backend and confirm the model loads successfully.
3. Start the frontend and open its local URL.
4. Keep **Simulation (Safe)** mode enabled while testing.
5. Use the built-in simulation controls to test:
   - DoS Flood
   - Port Probe
   - R2L Exploit
   - U2R Privilege
6. Inspect the event stream, attack counters, blocklist, and TTL countdown.
7. Test manual block/unblock and TTL expiry using a reserved documentation IP address, such as `198.51.100.99`.

Simulation controls may generate synthetic events rather than real malicious network traffic. Label demo results accordingly.

## Configuration and compatibility

### scikit-learn model version

If the saved model was created with a different scikit-learn version, loading it may produce an `InconsistentVersionWarning`. Prefer the version used to train and serialize the model, as recorded in the project environment or training files. For example, if the artifacts were created with scikit-learn 1.7.1, test with:

```powershell
python -m pip install scikit-learn==1.7.1
```

Do not assume that changing the library version alone guarantees valid predictions; test the model and its preprocessing artifacts together.

### Packet capture

If Scapy reports that layer-2 capture is unavailable or Npcap is missing:

- Confirm Npcap is installed.
- Confirm the selected interface exists and is the intended network adapter.
- Check permissions and the capture library's Windows configuration.
- Review backend logs for actual packet-receive errors.

### Redis connection

If the backend logs a Redis timeout:

- Confirm the container is running with `docker ps`.
- Test Redis with `docker exec ips-redis redis-cli ping`.
- Confirm the backend's configured Redis host and port.
- Check whether the application is using its in-memory fallback.

## Security and safe testing

- Keep **Simulation (Safe)** enabled until active enforcement is reviewed and tested.
- Do not test against networks, devices, or IP addresses without authorization.
- Use an isolated lab or test environment for packet-capture and prevention tests.
- Before enabling active enforcement, verify that the implementation installs real OS-level firewall rules, uses safe rule scoping, preserves management access, expires temporary rules, and supports rollback/emergency flush.
- Ensure the emergency-flush operation cannot accidentally remove unrelated firewall rules.
- Do not expose the Flask development server directly to the public internet.
- Do not commit credentials, secrets, private traffic captures, or environment files to Git.

## Known limitations / validation checklist

- A dashboard `BLOCK` or `DROP` entry may represent a software decision rather than a real firewall action.
- A started capture thread does not necessarily mean packets are being received and classified.
- Model predictions depend on training data, preprocessing consistency, and thresholds.
- Redis in-memory fallback is not durable or shared between independent backend processes.
- Real enforcement, rate limiting, TTL cleanup, and rollback must be validated in code and through controlled tests.

## Troubleshooting

| Problem | What to check |
| --- | --- |
| `requirements.txt` installation fails | Python version, dependency versions, and the first pip error |
| Npcap/layer-2 capture error | Npcap installation, selected interface, and permissions |
| Redis timeout | Docker status, Redis `PING`, host, and port |
| scikit-learn version warning | Match the version used to create the saved artifacts and test predictions |
| Frontend cannot reach backend | API base URL, backend port, CORS configuration, and browser console |
| Dashboard has no new events | Backend capture logs, selected interface, frontend API/socket connection, and filters |

## Contributing

Contributions and issue reports are welcome. Before submitting changes:

1. Describe the issue or feature clearly.
2. Test backend and frontend changes locally.
3. Avoid including secrets or real sensitive packet data.
4. Document any new configuration values and safety implications.

## License

No license was specified in the repository information provided for this README. Add a `LICENSE` file before describing the project as open source under a particular license.

## Acknowledgements

- [Scapy](https://scapy.net/)
- [Npcap](https://npcap.com/)
- [Flask](https://flask.palletsprojects.com/)
- [scikit-learn](https://scikit-learn.org/)
- [Redis](https://redis.io/)
