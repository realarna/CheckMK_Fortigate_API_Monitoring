# FortiOS Checkmk Special Agent Extended

Extended FortiGate monitoring for **Checkmk 2.4.x and 2.5.x** via the FortiOS REST API.

This package combines and extends existing Checkmk FortiGate monitoring extensions into one ready-to-use MKP package. It adds additional monitoring services, firmware monitoring, HA cluster synchronization checks, improved IPSec tunnel evaluation, and rule-based enhancements for better visualization, alerting, and operational use.

All credits belong to the original creators. This package builds on their work and adds compatibility and functionality improvements for modern Checkmk environments.

---

## Compatibility

This release has been updated for **Checkmk 2.5.x**.

Tested and rebuilt against:

```text
Checkmk 2.5.0p6
```

Package metadata:

```text
version.min_required = 2.3.0p1
version.packaged     = 2.5.0p6
version.usable_until = 2.5.99
```

The package is intended for:

* Checkmk 2.4.x
* Checkmk 2.5.x

---

## What is new in version 2.1.5

Version **2.1.5** includes the Checkmk 2.5 compatibility fixes.

### Fixed

* Fixed package metadata so the MKP can be enabled on Checkmk 2.5.

* Fixed GUI extension loading error in `views/fortios_inventory`.

* Replaced the removed Checkmk import:

  ```python
  from cmk.utils.user import UserId
  ```

  with the Checkmk 2.5-compatible import:

  ```python
  from cmk.ccc.user import UserId
  ```

* Updated deprecated GUI view metadata:

  ```python
  megamenu_search_terms
  ```

  to:

  ```python
  main_menu_search_terms
  ```

* Fixed MKP archive path structure so activation and removal work correctly.

* Rebuilt the package as a clean **2.1.5** release.

---

## Features

### Core FortiOS Monitoring

The special agent collects basic FortiGate system information via the FortiOS REST API.

Monitored information includes:

* Hostname
* FortiOS version
* Build number
* System status

---

### Firmware Monitoring

Integrated FortiGate firmware monitoring is included in the package.

The firmware check can detect:

* Available firmware updates
* Firmware branch changes
* Immature branch updates

Supported rule options include:

* Optional **CRITICAL** state on branch change
* Optional **OK** state for immature branch updates

This allows controlled alerting when a FortiGate can be upgraded, while avoiding unwanted critical alerts for intentionally ignored firmware branches.

---

### Device Metadata Services

Additional FortiGate device information is provided as separate Checkmk services.

Included services:

* **FortiOS Model**
* **FortiOS Serial Number**

These services are useful for:

* Inventory filtering
* Dashboard grouping
* BI aggregation
* Alerting on device identity changes
* Documentation and operational overview

No additional API calls are required for these services. The data is reused from the existing device information endpoint.

---

### HA Cluster Synchronization Monitoring

The package includes a dedicated HA synchronization status check for FortiGate clusters.

Service:

```text
HA sync status
```

The check uses FortiOS HA checksum information and is automatically discovered when an HA cluster with more than one member is detected.

The service reports:

* **OK** when HA members are synchronized
* **CRIT** if FortiOS reports an out-of-sync state
* **CRIT** if HA checksum values differ between cluster members
* **UNKNOWN** if an HA cluster is detected but the returned sync or checksum data cannot be interpreted reliably

This helps detect HA configuration synchronization problems that could affect failover consistency.

---

### IPSec Tunnel Redundancy Grouping

IPSec phase1 tunnel monitoring supports redundant tunnel bundles.

Rule options:

* **Redundancy group name**
* **Redundant IPSec tunnel members**

When multiple IPSec phase1 tunnels are configured as one redundancy group:

* The service stays **OK** as long as at least one configured member is effectively up.
* The service becomes **CRIT** only when all known members of the redundancy group are down.
* The service output includes:

  * Redundancy group name
  * Configured members
  * Up members
  * Down members
  * Missing members

This is useful for environments where multiple IPSec tunnels provide redundant connectivity and only a complete redundancy group outage should trigger a critical alert.

---

### Improved IPSec Phase2 Evaluation

The IPSec tunnel check logic was improved to reduce false positives and provide clearer troubleshooting output.

Improvements include:

* Ignored phase2 entries are excluded from the effective tunnel health calculation.
* If all phase2 entries of a tunnel are intentionally ignored by rule, the service remains **OK**.
* Destination-subnet ignore handling is safer for missing or empty proxy destination data.
* The check output includes:

  * Effective phase2 tunnel count
  * Effective up count
  * Effective down count
  * Ignored phase2 names
  * Ignored destination subnets

---

## Requirements

### FortiGate requirements

The FortiGate must provide REST API access.

Required:

* FortiGate with REST API enabled
* API token with read permissions for the monitored endpoints
* Network access from the Checkmk site to the FortiGate management interface
* HTTPS administrative access enabled on the FortiGate interface used by Checkmk

---

### Checkmk requirements

Required:

* Checkmk 2.4.x or 2.5.x
* Special agent execution from the Checkmk site
* Service discovery after installation or upgrade

---

## FortiGate API token setup

Before the Checkmk rule can be created, a REST API User must be configured on the FortiGate.

---

### 1. Create or verify an admin profile

Create a dedicated user profile for monitoring, or use an existing read-only profile if it provides access to the required monitoring endpoints.

Recommended approach:

* Use a dedicated profile for Checkmk.
* Grant only the permissions required for monitoring.
* Avoid using a full `super_admin` profile for the API token.
* Restrict access with trusted hosts.

The API user must be able to read the FortiGate status and monitoring endpoints used by this extension.

Used endpoints include:

```text
/api/v2/monitor/system/status
/api/v2/monitor/system/firmware
/api/v2/monitor/system/ha-checksums
```

Depending on the monitored FortiGate features, additional endpoints used by the original FortiOS special agent may also be required.

---

### 2. Create the REST API user

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

Example with placeholders:

```bash
curl -k \
  -H "Authorization: Bearer xxxxxxxxxxxxxxxxxxxxxxxxxxxxx" \
  "https://10.10.10.1/api/v2/monitor/system/status"
```

A successful response should return JSON data from the FortiGate.

If the request fails, check:

* FortiGate management interface is reachable from the Checkmk server.
* HTTPS administrative access is enabled on the FortiGate interface.
* The API token was copied correctly.
* The API administrator has sufficient read permissions.
* The Checkmk server IP is allowed as a trusted host.
* Firewall policies or local-in policies do not block the connection.

---

## Installation

Upload the MKP file to your Checkmk site and install it as the site user.

Example:

```bash
su - <SITE>
mkp add /tmp/fortios-2.1.5.mkp
mkp enable fortios 2.1.5
cmk -R
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

* Use the Checkmk password store for the API token if available.
* Use HTTPS.
* Enable SSL verification if the FortiGate uses a valid certificate.
* Disable SSL verification only if you use a self-signed certificate and accept that behavior.

Example rule values:

```text
FortiGate address: 10.10.10.1
Port: 443
API token: stored in Checkmk password store or entered directly
SSL verification: disabled for self-signed certificates
```

Configure additional rule options if required:

* Firmware branch handling
* Critical state on branch change
* Allow immature branch updates
* IPSec redundancy grouping
* IPSec phase2 ignore rules

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
11. Activate changes.
```

---

## Upgrade from an older version

If you are upgrading from an older FortiOS package version, disable and remove the old package first.

Example:

```bash
su - <SITE>

mkp disable fortios <OLD_VERSION>
mkp remove fortios <OLD_VERSION>

mkp add /tmp/fortios-2.1.5.mkp
mkp enable fortios 2.1.5

cmk -R
```

Existing rules and discovered services should remain intact because the package name, ruleset names, and check plug-in names were not changed.

---

---
## API endpoints used

Depending on the enabled checks and available FortiGate features, the extension can use the following FortiOS REST API endpoints:

```text
/api/v2/monitor/system/status
/api/v2/monitor/system/firmware
/api/v2/monitor/system/ha-checksums
```

The HA checksum endpoint is used for HA cluster synchronization monitoring.

Additional endpoints may be used by the original FortiOS special agent depending on the monitored FortiGate features.

---

## Troubleshooting

### Test API access from the Checkmk site

```bash
curl -k \
  -H "Authorization: Bearer <API_TOKEN>" \
  "https://<FORTIGATE_IP_OR_FQDN>/api/v2/monitor/system/status"
```

---

### HTTP 401 Unauthorized

Possible causes:

* Wrong API token.
* Token was regenerated and the old token is still configured in Checkmk.
* API administrator does not have sufficient permissions.
* Request is not using the correct authorization header.

---

### HTTP 403 Forbidden

Possible causes:

* Trusted host does not include the Checkmk server IP.
* Admin profile does not allow access to the required endpoint.
* Local-in policy blocks access.

---

### Connection timeout

Possible causes:

* FortiGate IP or DNS name is wrong.
* HTTPS admin access is not enabled on the FortiGate interface.
* Firewall routing or local-in policy blocks the Checkmk server.
* Wrong port configured in the Checkmk rule.

---

### SSL certificate error

Possible causes:

* FortiGate uses a self-signed certificate.
* Certificate CN/SAN does not match the configured hostname.
* Checkmk does not trust the issuing CA.

Possible solutions:

* Use a valid certificate on the FortiGate.
* Configure the rule with the correct FQDN.
* Disable SSL verification only if this is acceptable in your environment.

---

### Package is enabled but not active

If Checkmk reports that the package is enabled but not active because of version requirements, verify that you are using version **2.1.5** or newer.

Check installed packages:

```bash
mkp list | grep fortios
```

---

### GUI extension cannot be loaded

If the GUI reports:

```text
Loading "views/fortios_inventory" failed
```

check the exact Python import error.

For Checkmk 2.5, the file must not contain:

```python
from cmk.utils.user import UserId
```

It should contain:

```python
from cmk.ccc.user import UserId
```

Verify with:

```bash
grep -R "cmk.utils.user" ~/local/lib/python3/cmk/gui/plugins/views 2>/dev/null
grep -R "cmk.ccc.user" ~/local/lib/python3/cmk/gui/plugins/views/fortios_inventory.py 2>/dev/null
```

---

## Upgrade checklist

After upgrading:

1. Install the new MKP package.
2. Restart or reload Checkmk.
3. Run service discovery on FortiGate hosts.
4. Review newly discovered services, especially:

   * **HA sync status**
   * Updated IPSec tunnel services
   * Firmware monitoring services
   * Device metadata services
5. Configure IPSec redundancy groups if required.
6. Activate changes.

Existing checks should continue to work without additional configuration.

---

## Credits

This project builds upon the excellent work of:

* Simon Meister
* Roland Wyss / Wagner AG
  [https://github.com/WagnerAG/checkmk_fortigate](https://github.com/WagnerAG/checkmk_fortigate)
* Jacox98
  [https://github.com/Jacox98/checkmk-fortios-fw](https://github.com/Jacox98/checkmk-fortios-fw)

Thank you for the original implementation and contributions to the Checkmk community.

---

## License

Please refer to the original licensing terms of the base FortiOS Checkmk extensions.
