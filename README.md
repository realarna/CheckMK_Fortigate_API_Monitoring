# FortiOS Checkmk Special Agent (Extended)

Extended FortiGate monitoring for **Checkmk 2.4+** via REST API.

This package combines the original FortiOS special agent with integrated firmware monitoring and additional device metadata services.

---

## 🚀 Features

### ✅ Core FortiOS Monitoring
- Hostname
- FortiOS Version
- Build Number
- System Status

### ✅ Firmware Monitoring (Integrated)
- Available firmware updates
- Branch change detection
- Optional CRITICAL state on branch change
- Optional OK state for immature branch updates

### ✅ New Device Metadata Services (NEW)
- **FortiOS Model** (separate service)
- **FortiOS Serial Number** (separate service)

These are created as individual services to allow:
- Inventory filtering
- Dashboard grouping
- BI aggregation
- Alerting on device identity changes

No additional API calls are required — data is reused from the device info endpoint.

---

## 📦 Installation

Upload the MKP to your Checkmk site and install it:

```bash
omd su <SITE>
mkp install fortios-<VERSION>.mkp
cmk -R
After installation:

Go to Setup → Hosts

Run Service Discovery on your FortiGate host

Activate changes

If you previously installed the standalone firmware package, remove it to avoid duplicates:

mkp remove fortigate_firmware
cmk -R
⚙️ Configuration

Navigate to:
Setup → Agents → VM, cloud, container → Special agents → FortiOS Agent
Configure:

API Token

Port

SSL handling

Firmware branch handling behavior:

CRITICAL on branch change

Allow immature branch updates

🔐 Requirements

FortiGate with REST API enabled

API Token with read permissions

Checkmk 2.4 or newer

🧠 API Endpoints Used

/api/v2/monitor/system/status

/api/v2/monitor/system/firmware

👥 Credits

This project builds upon the excellent work of:

Simon Meister

Roland Wyss (opensource@wagner.ch
)

Jacox98

Ahmet Arnautovic (ahmet.arnautovic@acp.at
)

Thank you for the original implementation and contributions to the Checkmk community.

📜 License

Please refer to the original licensing terms of the base FortiOS Checkmk extension.
