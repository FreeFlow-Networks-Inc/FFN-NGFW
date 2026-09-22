# Objects workspace

The Objects navigation follows the PAN-OS 12.1 ordering: Addresses, Address
Groups, Regions, Dynamic User Groups, Applications, Application Groups,
Application Filters, Services, Service Groups, Tags, Devices, External Dynamic
Lists. FFN security content remains below these categories. This is an FFN
implementation of the workflow, not a pixel-perfect copy or a claim of full
PAN-OS feature compatibility.

Each page supports search, shared/local-vsys selection, candidate/running
selection, typed add/edit dialogs, cloning, references and guarded deletion.
Running views are read only. OK saves candidate XML; the existing Commit
workflow is still required. No object mutation applies networking or restarts
an engine. Existing application database browsing remains available from
Applications.

## Supported definitions

| Page | Editable settings |
|---|---|
| Addresses | IPv4/IPv6 subnet, range or FQDN; tags and description |
| Address Groups | Static members or quoted tag expressions joined with and/or |
| Regions | IP addresses/subnets/ranges, optional latitude and longitude |
| Dynamic User Groups | Tag match criteria and object tags |
| Applications | Custom category, subcategory, technology, risk and default TCP/UDP ports |
| Application Groups | Custom applications and nested application groups |
| Application Filters | Category, subcategory, technology and risk criteria |
| Services | TCP/UDP destination and optional source ports |
| Service Groups | Services and nested service groups |
| Tags | Color, description |
| Devices | Category, profile, model, OS family/version and vendor |
| External Dynamic Lists | IP/domain/URL type, HTTP(S) source, update schedule and exceptions |

Application signatures, a predefined App-ID/Device-ID dictionary, country
geolocation data, dynamic user registration and feed fetching are not supplied
by these editors. Policy enforcement and dynamic resolution require runtime
provider integration. An external-list save does not fetch its URL. Credentials
embedded in source URLs are rejected. Imported definitions with unsupported
fields are displayed read only and retained verbatim.

## Data and API

`ffn_config_objects.py` uses the existing ConfigManager and candidate XML;
`ffn_object_schema.py` provides allowlisted field paths and form metadata.
The new API uses `/api/config/objects/{kind}` with GET/POST and
`/{name}` with PUT/DELETE, plus `/{name}/references`. Kinds are singular XML
container names, including `external-list` and `dynamic-user-group`.

All writes require administrator rights, a SHA-256 candidate revision, and the
configuration lock. Unknown properties and malformed values are rejected.
Group membership is scope-aware, must resolve, and must not form cycles. Tag
references include dynamic expressions; referenced objects cannot be deleted.
Existing inherited references use local-before-shared resolution. Renaming
requires cloning and updating references explicitly.

## Deployment and verification

Run `python image/install-objects-ui.py --target /opt/ffn-ngfw-v2` from the
checkout on the appliance, then restart `ffn-manager-v2`. The merge retains
unrelated live manager changes and creates a timestamped backup. No firewall
reboot, config commit or BCM/CP/DP restart is required.

API regressions: `python tests/test_config_objects.py`.
Browser regressions: install Playwright, its Chromium browser, and the Python
test dependencies, then run `node tests/test_objects_browser.cjs`. Set
`TEST_PYTHON` or `TEST_BROWSER` to override executables. This uses a loopback-only
fixture with an in-memory candidate and tests all twelve pages; it never
connects to an appliance. `TEST_SCREENSHOT` optionally saves a screenshot.

Reference: [PAN-OS 12.1 Objects help](https://docs.paloaltonetworks.com/ngfw/help/12-1/objects).
