# FortiOS Checkmk Special Agent (Extended)

Extended FortiGate monitoring for **Checkmk 2.4+** via REST API.

All credits belong to the original creators. This package combines two ready-to-use Checkmk FortiGate extensions into one package and adds additional monitoring services and rule-based enhancements for better visualization, alerting, and operational use.

The extension combines the original FortiOS special agent with integrated firmware monitoring, additional device metadata services, enhanced IPSec tunnel checks, and HA cluster synchronization monitoring.

---

## 🚀 Features

### ✅ Core FortiOS Monitoring

- Hostname
- FortiOS version
- Build number
- System status

### ✅ Firmware Monitoring

Integrated FortiGate firmware monitoring is included in the package.

- Available firmware updates
- Branch change detection
- Optional **CRITICAL** state on branch change
- Optional **OK** state for immature branch updates

### ✅ Device Metadata Services

Additional FortiGate device information is provided as separate Checkmk services.

- **FortiOS Model**
- **FortiOS Serial Number**

These services are useful for:

- Inventory filtering
- Dashboard grouping
- BI aggregation
- Alerting on device identity changes

No additional API calls are required for these services. The data is reused from the existing device information endpoint.

### ✅ HA Cluster Synchronization Monitoring

This release adds a dedicated HA synchronization status check for FortiGate clusters.

- New service: **HA sync status**
- Uses FortiOS HA checksum information
- Automatically discovered only when an HA cluster with more than one member is detected
- Reports **OK** when HA members are synchronized
- Reports **CRIT** if FortiOS reports an out-of-sync state or if HA checksum values differ between cluster members
- Reports **UNKNOWN** if an HA cluster is detected but the returned sync/checksum data cannot be interpreted reliably

This helps detect HA configuration synchronization problems that could affect failover consistency.

### ✅ IPSec Tunnel Redundancy Grouping

IPSec phase1 tunnel monitoring now supports redundant tunnel bundles.

New rule options:

- **Redundancy group name**
- **Redundant IPSec tunnel members**

When multiple IPSec phase1 tunnels are configured as one redundancy group:

- The service stays **OK** as long as at least one configured member is effectively up
- The service becomes **CRIT** only when all known members of the redundancy group are down
- The service output includes the redundancy group name, configured members, up/down members, and missing members

This is useful for environments where multiple IPSec tunnels provide redundant connectivity and only a complete redundancy group outage should trigger a critical alert.

### ✅ Improved IPSec Phase2 Evaluation

The IPSec tunnel check logic was improved to reduce false positives and provide clearer troubleshooting output.

Improvements include:

- Ignored phase2 entries are excluded from the effective tunnel health calculation
- If all phase2 entries of a tunnel are intentionally ignored by rule, the service remains **OK**
- Destination-subnet ignore handling is safer for missing or empty proxy destination data
- Check output includes:
  - Effective phase2 tunnel count
  - Effective up/down count
  - Ignored phase2 names
  - Ignored destination subnets

---

## 📦 Installation

Upload the MKP to your Checkmk site and install it:

```bash
omd su <SITE>
mkp install fortios-<VERSION>.mkp
cmk -R
```

After installation:

1. Go to **Setup → Hosts**
2. Run **Service Discovery** on your FortiGate host
3. Activate changes

If you previously installed the standalone firmware package, remove it to avoid duplicate services:

```bash
mkp remove fortigate_firmware
cmk -R
```

---

## ⚙️ Configuration

Navigate to:

**Setup → Agents → VM, cloud, container → Special agents → FortiOS Agent**

Configure:

- API token
- Port
- SSL handling
- Firmware branch handling behavior:
  - Critical on branch change
  - Allow immature branch updates

For IPSec redundancy grouping, configure the IPSec tunnel check parameters and apply the same redundancy group definition to all relevant tunnel members.

For HA cluster synchronization monitoring, no additional configuration is normally required. The service is discovered automatically when the FortiGate API reports multiple HA members.

---

## 🔐 Requirements

- FortiGate with REST API enabled
- API token with read permissions
- Checkmk 2.4 or newer

---

## 🧠 API Endpoints Used

Depending on the enabled checks and available FortiGate features, the extension can use the following FortiOS REST API endpoints:

```text
/api/v2/monitor/system/status
/api/v2/monitor/system/firmware
/api/v2/monitor/system/ha-checksums
```

The HA checksum endpoint is used for HA cluster synchronization monitoring.

---

## 🔄 Upgrade Notes

After upgrading from an older version:

1. Install the new MKP package.
2. Restart/reload Checkmk.
3. Run service discovery on FortiGate hosts.
4. Review newly discovered services, especially:
   - **HA sync status**
   - Updated IPSec tunnel services
5. Configure IPSec redundancy groups if required.

Existing checks continue to work without additional configuration.

---

## 👥 Credits

This project builds upon the excellent work of:

- Simon Meister
- Roland Wyss / Wagner AG  
  https://github.com/WagnerAG/checkmk_fortigate
- Jacox98  
  https://github.com/Jacox98/checkmk-fortios-fw

Thank you for the original implementation and contributions to the Checkmk community.

---

## 📜 License

Please refer to the original licensing terms of the base FortiOS Checkmk extension.
