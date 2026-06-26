# FortiOS Checkmk Special Agent Extended

Extended FortiGate monitoring for **Checkmk 2.4.x and 2.5.x** via the FortiOS REST API.

This package combines and extends existing Checkmk FortiGate monitoring extensions into one ready-to-use MKP package. It adds additional monitoring services, firmware monitoring, HA cluster synchronization checks, improved IPSec tunnel evaluation, FortiOS interface inventory, and rule-based enhancements for better visualization, alerting, and operational use.

All credits belong to the original creators. This package builds on their work and adds compatibility and functionality improvements for modern Checkmk environments.

---

## Compatibility

This package is intended for:

- Checkmk 2.4.x
- Checkmk 2.5.x

The current release includes a compatibility import for Checkmk 2.4 and 2.5 GUI extensions.

Package metadata used for the Checkmk 2.5-compatible builds:

```text
version.min_required = 2.3.0p1
version.packaged     = 2.5.0p6
version.usable_until = 2.5.99
```

---

## Current release

Current package version:

```text
2.1.7
```

The 2.1.7 release keeps the interface inventory functionality from 2.1.6 and adds Checkmk 2.4/2.5 GUI compatibility fixes.

---

## Changelog

### [2.1.7] - 2026-06-26

#### Fixed

- Fixed GUI compatibility between **Checkmk 2.4.x** and **Checkmk 2.5.x**.
- Added a version-compatible `UserId` import in `views/fortios_inventory`:

  ```python
  try:
      # Checkmk >= 2.5
      from cmk.ccc.user import UserId
  except ModuleNotFoundError:
      # Checkmk <= 2.4
      from cmk.utils.user import UserId
  ```

- Kept both GUI search metadata keys for compatibility:

  ```python
  "main_menu_search_terms": [],
  "megamenu_search_terms": [],
  ```

- Fixed MKP packaging format so the package can be uploaded through the Checkmk GUI and no longer fails with:

  ```text
  not a gzip file
  ```

#### Included

- Includes all interface inventory and interface service output improvements from version 2.1.6.

---

### [2.1.6] - 2026-06-26

#### Added

- Added FortiOS interface configuration inventory based on:

  ```text
  /api/v2/cmdb/system/interface
  ```

- Added a new HW/SW inventory table:

  ```text
  Networking → FortiOS → Interfaces
  ```

- Inventory includes normalized interface fields such as:

  - Interface name
  - Alias
  - Description
  - Type
  - Role
  - Status
  - Mode
  - Configured IPv4 address
  - Configured subnet / prefix
  - Secondary IP addresses
  - VLAN ID
  - Parent interface
  - VDOM
  - Management access
  - MAC address

- Inventory also stores raw FortiOS CMDB interface fields as additional `raw_*` inventory columns where possible, so returned FortiGate interface data is not lost.

#### Changed

- Existing interface service output was extended to show only VLAN and IP address information from the FortiOS interface configuration.

  Example output:

  ```text
  VLAN: 10, IP: 10.10.10.1/24
  ```

- The interface service state logic was not changed by this feature.

---

### [2.1.5] - 2026-06-26

#### Fixed

- Fixed package metadata so the MKP can be enabled on Checkmk 2.5.
- Fixed GUI extension loading error in `views/fortios_inventory`.
- Replaced the removed Checkmk 2.5 import:

  ```python
  from cmk.utils.user import UserId
  ```

  with the Checkmk 2.5 import:

  ```python
  from cmk.ccc.user import UserId
  ```

- Updated deprecated GUI view metadata:

  ```python
  megamenu_search_terms
  ```

  to:

  ```python
  main_menu_search_terms
  ```

- Fixed MKP archive path structure so activation and removal work correctly.
- Rebuilt the package as a clean Checkmk 2.5-compatible release.

---

## Features

### Core FortiOS Monitoring

The special agent collects basic FortiGate system information via the FortiOS REST API.

Monitored information includes:

- Hostname
- FortiOS version
- Build number
- System status

---

### Firmware Monitoring

Integrated FortiGate firmware monitoring is included in the package.

The firmware check can detect:

- Available firmware updates
- Firmware branch changes
- Immature branch updates

Supported rule options include:

- Optional **CRITICAL** state on branch change
- Optional **OK** state for immature branch updates

This allows controlled alerting when a FortiGate can be upgraded, while avoiding unwanted critical alerts for intentionally ignored firmware branches.

---

### Device Metadata Services

Additional FortiGate device information is provided as separate Checkmk services.

Included services:

- **FortiOS Model**
- **FortiOS Serial Number**

These services are useful for:

- Inventory filtering
- Dashboard grouping
- BI aggregation
- Alerting on device identity changes
- Documentation and operational overview

No additional API calls are required for these services. The data is reused from the existing device information endpoint.

---

### FortiOS Interface Inventory

The package can collect configured FortiGate interface information from the FortiOS CMDB interface endpoint.

Inventory path:

```text
Networking → FortiOS → Interfaces
```

The inventory can include:

- Interface name
- Alias
- Description
- Type
- Role
- Status
- Mode
- Configured IPv4 address
- Configured subnet / prefix
- Secondary IP addresses
- VLAN ID
- Parent interface
- VDOM
- Management access
- MAC address
- Additional raw FortiOS interface fields where available

The inventory is intended for documentation, auditing, filtering, and operational visibility.

To display the inventory data, HW/SW inventory must be enabled and executed for the FortiGate host.

---

### Interface Service Output

Existing interface services are enriched with configured VLAN and IP address information.

Example:

```text
VLAN: 10, IP: 10.10.10.1/24
```

Only VLAN and IP information are shown in the interface service output to keep the service output short and operationally useful.

The complete interface configuration is available in the HW/SW inventory table.

---

### HA Cluster Synchronization Monitoring

The package includes a dedicated HA synchronization status check for FortiGate clusters.

Service:

```text
HA sync status
```

The check uses FortiOS HA checksum information and is automatically discovered when an HA cluster with more than one member is detected.

The service reports:

- **OK** when HA members are synchronized
- **CRIT** if FortiOS reports an out-of-sync state
- **CRIT** if HA checksum values differ between cluster members
- **UNKNOWN** if an HA cluster is detected but the returned sync or checksum data cannot be interpreted reliably

This helps detect HA configuration synchronization problems that could affect failover consistency.

---

### IPSec Tunnel Redundancy Grouping

IPSec phase1 tunnel monitoring supports redundant tunnel bundles.

Rule options:

- **Redundancy group name**
- **Redundant IPSec tunnel members**

When multiple IPSec phase1 tunnels are configured as one redundancy group:

- The service stays **OK** as long as at least one configured member is effectively up.
- The service becomes **CRIT** only when all known members of the redundancy group are down.
- The service output includes:
  - Redundancy group name
  - Configured members
  - Up members
  - Down members
  - Missing members

This is useful for environments where multiple IPSec tunnels provide redundant connectivity and only a complete redundancy group outage should trigger a critical alert.

---

### Improved IPSec Phase2 Evaluation

The IPSec tunnel check logic was improved to reduce false positives and provide clearer troubleshooting output.

Improvements include:

- Ignored phase2 entries are excluded from the effective tunnel health calculation.
- If all phase2 entries of a tunnel are intentionally ignored by rule, the service remains **OK**.
- Destination-subnet ignore handling is safer for missing or empty proxy destination data.
- The check output includes:
  - Effective phase2 tunnel count
  - Effective up count
  - Effective down count
  - Ignored phase2 names
  - Ignored destination subnets

---

## Requirements

### FortiGate requirements

The FortiGate must provide REST API access.

Required:

- FortiGate with REST API enabled
- REST API administrator
- API token authentication
- API token with read permissions for the monitored endpoints
- Network access from the Checkmk site to the FortiGate management interface
- HTTPS administrative access enabled on the FortiGate interface used by Checkmk

---

### Checkmk requirements

Required:

- Checkmk 2.4.x or 2.5.x
- Special agent execution from the Checkmk site
- Service discovery after installation or upgrade
- HW/SW inventory enabled if the FortiOS interface inventory table should be populated

---

## FortiGate API token setup

Before the Checkmk rule can be created, a REST API administrator must be configured on the FortiGate.

---

### 1. Create or verify an admin profile

Create a dedicated admin profile for monitoring, or use an existing read-only profile if it provides access to the required monitoring endpoints.

Recommended approach:

- Use a dedicated profile for Checkmk.
- Grant only the permissions required for monitoring.
- Avoid using a full `super_admin` profile for the API token.
- Restrict access with trusted hosts.

The API user must be able to read the FortiGate status, monitoring endpoints, and interface configuration endpoints used by this extension.

Used endpoints include:

```text
/api/v2/monitor/system/status
/api/v2/monitor/system/firmware
/api/v2/monitor/system/ha-checksums
/api/v2/cmdb/system/interface
```

Depending on the monitored FortiGate features, additional endpoints used by the original FortiOS special agent may also be required.

---

### 2. Create the REST API administrator

In the FortiGate GUI:

1. Go to **System → Administrators**.
2. Select **Create New → REST API Admin**.
3. Enter a dedicated username, for example:

   ```text
   checkmk_api
   ```

4. Select the monitoring admin profile.
5. Configure **Trusted Hosts**.

The trusted host should be the IP address of the Checkmk site or monitoring server.

Example:

```text
Trusted Host: 10.10.10.20/32
```

Using trusted hosts is strongly recommended so the token can only be used from the Checkmk server.

6. Save the REST API administrator.
7. Copy the generated API token.

Important:

```text
The API token is shown only once. Store it securely.
```

---

### 3. Test the API token manually

From the Checkmk site, test the token before configuring the Checkmk rule.

Example:

```bash
curl -k \
  -H "Authorization: Bearer <API_TOKEN>" \
  "https://<FORTIGATE_IP_OR_FQDN>/api/v2/monitor/system/status"
```

Example for the interface CMDB endpoint:

```bash
curl -k \
  -H "Authorization: Bearer <API_TOKEN>" \
  "https://<FORTIGATE_IP_OR_FQDN>/api/v2/cmdb/system/interface"
```

A successful response should return JSON data from the FortiGate.

If the request fails, check:

- FortiGate management interface is reachable from the Checkmk server.
- HTTPS administrative access is enabled on the FortiGate interface.
- The API token was copied correctly.
- The API administrator has sufficient read permissions.
- The Checkmk server IP is allowed as a trusted host.
- Firewall policies or local-in policies do not block the connection.

---

## Installation

Upload the MKP file to your Checkmk site and install it as the site user if you use the Raw/Community edition.

Example:

```bash
su - <SITE>
mkp add /tmp/fortios-2.1.7.mkp
mkp enable fortios 2.1.7
cmk -R
```

For commercial Checkmk editions, you can also upload and enable the MKP in the GUI:

```text
Setup → Extension packages
```

After installation, continue with the Checkmk host and rule configuration below.

---

## Checkmk host configuration

Create or edit the FortiGate host in Checkmk.

Recommended host settings for API-only monitoring:

1. Go to **Setup → Hosts**.
2. Create or edit the FortiGate host.
3. Set the host name.
4. Set the IPv4 address or DNS name of the FortiGate.
5. Configure the monitoring agent mode.

Recommended setting for API-only monitoring:

```text
Configured API integrations, no Checkmk agent
```

If you also monitor the FortiGate with SNMP, choose the option that matches your environment, for example:

```text
Configured API integrations and SNMP
```

Save the host.

---

## Checkmk FortiOS special agent rule

After installing the MKP, create the FortiOS special agent rule.

Navigate to:

```text
Setup → Agents → VM, cloud, container → Special agents → FortiOS Agent
```

Create a new rule.

Configure the connection settings:

```text
FortiGate address: <FortiGate IP or FQDN>
Port: 443
API token: <FortiGate REST API token>
SSL verification: according to your certificate setup
```

Recommended:

- Use the Checkmk password store for the API token if available.
- Use HTTPS.
- Enable SSL verification if the FortiGate uses a valid certificate.
- Disable SSL verification only if you use a self-signed certificate and accept that behavior.

Example rule values:

```text
FortiGate address: 10.10.10.1
Port: 443
API token: stored in Checkmk password store or entered directly
SSL verification: disabled for self-signed certificates
```

Configure additional rule options if required:

- Firmware branch handling
- Critical state on branch change
- Allow immature branch updates
- IPSec redundancy grouping
- IPSec phase2 ignore rules

---

## Rule conditions

Restrict the rule to the correct FortiGate host.

Recommended condition:

```text
Explicit hosts: <FortiGate host name in Checkmk>
```

Example:

```text
Explicit hosts: fw-office-01
```

Alternatively, apply the rule to a folder or host tag if you manage multiple FortiGate firewalls.

Example for multiple FortiGates:

```text
Folder: /network/firewalls/fortigate
```

or:

```text
Host tag: fortigate
```

Save the rule.

---

## Service discovery

After the host and the FortiOS special agent rule are configured:

1. Go to **Setup → Hosts**.
2. Open the FortiGate host.
3. Run **Service Discovery**.
4. Accept the discovered services.
5. Activate changes.

You can also run discovery from the command line:

```bash
su - <SITE>
cmk -vI <HOSTNAME>
cmk -R
```

Example:

```bash
su - mysite
cmk -vI fw-office-01
cmk -R
```

---

## HW/SW inventory

The FortiOS interface configuration table is written to the Checkmk HW/SW inventory.

To make the inventory visible:

1. Enable HW/SW inventory for the FortiGate host.
2. Run service discovery if required.
3. Execute the HW/SW inventory service.
4. Open the host inventory view.

Expected inventory path:

```text
Networking → FortiOS → Interfaces
```

Command-line example:

```bash
su - <SITE>
cmk -vI <HOSTNAME>
cmk --inventory <HOSTNAME>
cmk -R
```

---

## Quick setup summary

Minimal setup flow:

```text
1. Create FortiGate REST API admin.
2. Restrict API admin with trusted host = Checkmk server IP.
3. Copy the generated API token.
4. Test the API token with curl from the Checkmk site.
5. Install the MKP in Checkmk.
6. Create or edit the FortiGate host in Checkmk.
7. Create the FortiOS Agent rule.
8. Enter the FortiGate address and API token.
9. Restrict the rule to the FortiGate host.
10. Run service discovery.
11. Enable and run HW/SW inventory if interface inventory is required.
12. Activate changes.
```

---

## Upgrade from an older version

If you are upgrading from an older FortiOS package version, disable and remove the old package first.

Example:

```bash
su - <SITE>

mkp disable fortios <OLD_VERSION>
mkp remove fortios <OLD_VERSION>

mkp add /tmp/fortios-2.1.7.mkp
mkp enable fortios 2.1.7

omd restart apache
cmk -R
```

Existing rules and discovered services should remain intact because the package name, ruleset names, and check plug-in names were not changed.

---

## API endpoints used

Depending on the enabled checks and available FortiGate features, the extension can use the following FortiOS REST API endpoints:

```text
/api/v2/monitor/system/status
/api/v2/monitor/system/firmware
/api/v2/monitor/system/ha-checksums
/api/v2/cmdb/system/interface
```

The HA checksum endpoint is used for HA cluster synchronization monitoring.

The CMDB interface endpoint is used for configured interface IP addresses, subnets, VLAN information, and interface inventory.

Additional endpoints may be used by the original FortiOS special agent depending on the monitored FortiGate features.

---

## Troubleshooting

### Test API access from the Checkmk site

```bash
curl -k \
  -H "Authorization: Bearer <API_TOKEN>" \
  "https://<FORTIGATE_IP_OR_FQDN>/api/v2/monitor/system/status"
```

Test the interface endpoint:

```bash
curl -k \
  -H "Authorization: Bearer <API_TOKEN>" \
  "https://<FORTIGATE_IP_OR_FQDN>/api/v2/cmdb/system/interface"
```

---

### HTTP 401 Unauthorized

Possible causes:

- Wrong API token.
- Token was regenerated and the old token is still configured in Checkmk.
- API administrator does not have sufficient permissions.
- Request is not using the correct authorization header.

---

### HTTP 403 Forbidden

Possible causes:

- Trusted host does not include the Checkmk server IP.
- Admin profile does not allow access to the required endpoint.
- Local-in policy blocks access.

---

### Connection timeout

Possible causes:

- FortiGate IP or DNS name is wrong.
- HTTPS admin access is not enabled on the FortiGate interface.
- Firewall routing or local-in policy blocks the Checkmk server.
- Wrong port configured in the Checkmk rule.

---

### SSL certificate error

Possible causes:

- FortiGate uses a self-signed certificate.
- Certificate CN/SAN does not match the configured hostname.
- Checkmk does not trust the issuing CA.

Possible solutions:

- Use a valid certificate on the FortiGate.
- Configure the rule with the correct FQDN.
- Disable SSL verification only if this is acceptable in your environment.

---

### Package is enabled but not active

If Checkmk reports that the package is enabled but not active because of version requirements, verify that you are using a package version compatible with your Checkmk site version.

Check installed packages:

```bash
mkp list | grep fortios
```

---

### Package upload fails with "not a gzip file"

If Checkmk reports:

```text
This package cannot be uploaded: not a gzip file
```

make sure you are using the corrected gzip-compressed MKP build.

You can test the package file before upload:

```bash
file fortios-2.1.7.mkp
gzip -t fortios-2.1.7.mkp
```

---

### GUI extension cannot be loaded

If the GUI reports:

```text
Loading "views/fortios_inventory" failed
```

check the exact Python import error.

For Checkmk 2.4 and 2.5 compatibility, the file should contain a version-adaptive import:

```python
try:
    from cmk.ccc.user import UserId
except ModuleNotFoundError:
    from cmk.utils.user import UserId
```

Verify with:

```bash
grep -n "from cmk.ccc.user\|from cmk.utils.user\|ModuleNotFoundError" \
  ~/local/lib/python3/cmk/gui/plugins/views/fortios_inventory.py
```

Expected result:

```text
from cmk.ccc.user import UserId
except ModuleNotFoundError:
from cmk.utils.user import UserId
```

Important:

```text
cmk.utils.user is expected as a fallback for Checkmk 2.4.
It is not automatically an error in version 2.1.7.
```

---

### Interface inventory is not visible

Possible causes:

- HW/SW inventory is not enabled for the FortiGate host.
- HW/SW inventory has not run yet.
- The API token cannot access `/api/v2/cmdb/system/interface`.
- The FortiGate does not return interface IP data for the selected VDOM or API scope.

Recommended checks:

```bash
curl -k \
  -H "Authorization: Bearer <API_TOKEN>" \
  "https://<FORTIGATE_IP_OR_FQDN>/api/v2/cmdb/system/interface"
```

Run inventory:

```bash
su - <SITE>
cmk --inventory <HOSTNAME>
cmk -R
```

---

## Upgrade checklist

After upgrading:

1. Install the new MKP package.
2. Restart or reload Checkmk.
3. Run service discovery on FortiGate hosts.
4. Run HW/SW inventory if interface inventory is required.
5. Review newly discovered or updated services, especially:
   - **HA sync status**
   - Updated IPSec tunnel services
   - Firmware monitoring services
   - Device metadata services
   - FortiOS interface services with VLAN and IP output
6. Review the HW/SW inventory table:
   - **Networking → FortiOS → Interfaces**
7. Configure IPSec redundancy groups if required.
8. Activate changes.

Existing checks should continue to work without additional configuration.

---

## Credits

This project builds upon the excellent work of:

- Simon Meister
- Roland Wyss / Wagner AG  
  <https://github.com/WagnerAG/checkmk_fortigate>
- Jacox98  
  <https://github.com/Jacox98/checkmk-fortios-fw>

Thank you for the original implementation and contributions to the Checkmk community.

---

## License

Please refer to the original licensing terms of the base FortiOS Checkmk extensions.
