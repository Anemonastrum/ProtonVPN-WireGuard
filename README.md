# ProtonVPN WireGuard and OpenClash

Download ProtonVPN WireGuard configurations, convert them into an OpenClash configuration, and publish both formats as GitHub release assets.

The generated `config.yaml` includes every valid `.conf` file in the input archive, a load-balance group for each country, a global load-balance group, and a manual server selector. It requires the **Mihomo / Clash Meta** core.

## Release downloads

Open this repository's **Releases** page and download the assets from the latest release.

| Asset | Contents |
| --- | --- |
| `config.yaml` | Complete OpenClash configuration with WireGuard proxies and country groups |
| `ProtonVPN_WireGuard_Configs.zip` | Original WireGuard `.conf` files organized by country code |
| `openclash-summary.json` | Configuration counts by country, load-balance strategy, and IPv6 setting |
| `SHA256SUMS` | SHA-256 checksums for the three files above |

The WireGuard archive is preserved as supplied to the generator. Files such as `US/wg-US-FREE-104.conf` become individual WireGuard proxies; adding a country to the ZIP automatically creates its load-balance group. Invalid configurations cause generation to fail rather than silently disappear from the output.

For a public repository, the latest OpenClash asset can also be used as a subscription URL:

```text
https://github.com/OWNER/REPOSITORY/releases/latest/download/config.yaml
```

Replace `OWNER` and `REPOSITORY` with your repository details. A private repository requires authenticated downloads; use a local upload if your OpenClash installation cannot authenticate.

## Repository setup

1. Copy the project into a repository you control and enable GitHub Actions. To keep generated keys private, create a private repository and push a copy of the project into it; a fork of a public repository cannot be made private.
2. Open **Settings > Secrets and variables > Actions** and create the secrets below.
3. Open **Actions > Download WireGuard and Publish Release > Run workflow**.
4. Select the download scope, load-balance strategy, and IPv6 setting, then run the workflow.
5. Download both formats from **Releases** after the workflow succeeds.

| Secret | Required | Purpose |
| --- | --- | --- |
| `VPN_USERNAME` | Yes, for new downloads | ProtonVPN account username used by the existing browser login flow |
| `VPN_PASSWORD` | Yes, for new downloads | ProtonVPN account password |
| `VPN_TOTP_SECRET` | Only for accounts using authenticator 2FA | Authenticator setup key (base32) or TOTP `otpauth://` URI; not a six-digit code |
| `TELEGRAM_BOT_TOKEN` | No | Send the downloaded WireGuard ZIP through the existing Telegram integration |
| `TELEGRAM_CHAT_ID` | No | Telegram destination; both Telegram secrets must be set to enable delivery |

Release publication uses the built-in `GITHUB_TOKEN`. No personal access token is required. The release job requests `contents: write`; repository or organization policies must permit that permission.

The browser downloader handles both combined username/password forms and username-first forms. It waits up to 120 seconds per login stage for visible page state instead of rejecting a login after a fixed three-second delay. Authenticator two-factor authentication is supported with `VPN_TOTP_SECRET`. Interactive CAPTCHA, email verification, and security key prompts still require user interaction and cannot be completed by this unattended workflow. Available servers depend on your account and plan.

### Troubleshooting login failures

`Still on login page after submitting credentials. Page error: none visible` was the old script's premature URL check. It did not establish whether the account credentials were wrong. The updated login waits for authenticated account navigation and ignores hidden inputs and disabled submit buttons.

Ensure `VPN_USERNAME` and `VPN_PASSWORD` are your **Proton Account** credentials, the ones used at `https://account.protonvpn.com`. OpenVPN / IKEv2 credentials are different and cannot sign in to this web account. Preserve the exact account password when adding the secret.

If authenticator 2FA is enabled, add `VPN_TOTP_SECRET` to **Settings > Secrets and variables > Actions**. Use the authenticator setup key associated with your Proton Account, not the changing six-digit code. The workflow generates the current code when Proton requests it; the seed and generated code are not logged.

For a slow runner, add the repository **variable** `LOGIN_TIMEOUT_SECONDS` with a value between `30` and `600`; the default is `120`. This is a timeout per stage, not an automatic retry count. Rejected credentials and rate limits are not repeatedly submitted.

On failure, the workflow uploads a `login-status` artifact with only status flags and a failure code, retained for one day. It contains no screenshots, HTML, form values, cookies, or account credentials. Use the failure code and the accompanying workflow log:

| Failure code | Next step |
| --- | --- |
| `credentials_rejected` | Check Account credentials; if a 2FA code was rejected, check the authenticator setup key |
| `totp_required` | Add the optional `VPN_TOTP_SECRET` repository secret |
| `invalid_totp_secret` | Correct the setup key or TOTP URI |
| `human_verification`, `email_verification`, `security_key` | Complete the required account verification; use a self-hosted runner if the GitHub-hosted runner consistently receives interactive challenges |
| `rate_limited` | Wait before another run |
| `login_timeout` | Check account sign-in, runner connectivity, and the status flags; increase the timeout only if the form is slow |
| `browser_error` | Check browser availability and compatibility with Selenium |

Increasing the timeout cannot repair rejected credentials or satisfy interactive verification. The release job remains blocked until login and fresh downloads succeed.

## GitHub Actions

### Download WireGuard and Publish Release

Workflow file: `.github/workflows/vpn_download.yml`.

Runs daily at **00:00 UTC / 07:00 Asia/Jakarta**, or manually. Scheduled workflows run on the default branch and may start later than the scheduled time.

The workflow:

1. Removes the checked-in ZIP and checkpoint from the runner so an old archive cannot be mistaken for a fresh download.
2. Downloads WireGuard files using `proton_downloader_chrome.py` and creates a country-organized ZIP. Server IDs are recorded after a completed browser download.
3. Passes the fresh ZIP to the reusable OpenClash workflow as an artifact.
4. Generates `config.yaml`, tests the converter, and validates the YAML using the current stable Mihomo core.
5. Creates checksums and release notes, uploads the assets to a draft release, then publishes it as the latest release.

Each successful run creates a release tagged `configs-RUN_ID-RUN_ATTEMPT`. Generated files are published to releases instead of being committed back to the branch. The existing checked-in ZIP remains available as an initial input for manual generation.

`download_scope: all` visits all country sections; `first` visits only the first country shown by ProtonVPN. The downloader includes files it successfully retrieves, so the release summary is the authoritative inventory. The existing throttling uses 60–90 seconds between downloads, up to 20 downloads per browser session, and up to 20 sessions. A failed login, empty download, session limit, validation failure, or job timeout prevents a new release.

### Generate OpenClash and Publish Release

Workflow file: `.github/workflows/openclash_release.yml`.

Called automatically after a successful download. It can also run manually without ProtonVPN credentials or another login:

- **`latest-release`**: read `ProtonVPN_WireGuard_Configs.zip` from the latest published release. This requires an existing release containing that asset.
- **`repository`**: read the ZIP stored in the selected branch. Use this to publish the first release or rebuild the supplied archive.

Both modes generate the OpenClash configuration and include that same WireGuard ZIP in the new release. To refresh the original configs, run the download workflow instead.

### Test Downloader and OpenClash Generator

Workflow file: `.github/workflows/test.yml`.

Runs converter tests and simulated browser login tests on relevant pushes and pull requests. Tests cover combined and two-step forms, slow login, 2FA, rejected credentials, challenges, and diagnostic privacy. They do not log in to ProtonVPN or publish a release.

## OpenClash usage

1. Install or select the **Mihomo / Clash Meta** core in OpenClash.
2. Download `config.yaml` from the latest release and upload it through OpenClash's configuration management page, or configure the release URL as a subscription.
3. Activate the configuration and open the proxy dashboard.
4. Choose a group in `PROTONVPN`.

| Group | Behavior |
| --- | --- |
| `US Load Balance`, `JP Load Balance`, and other country groups | Distribute connections among servers from that country |
| `All Countries Load Balance` | Distribute connections among all servers in the input archive |
| `Manual` | Select one individual WireGuard server |
| `DIRECT` | Send traffic directly when explicitly selected |

The first alphabetically sorted country group is the initial selection. `store-selected` lets the core retain your selection. Local/private address ranges route directly; other traffic matches `PROTONVPN`. There is no automatic direct fallback for internet traffic. OpenClash may override ports, DNS, and controller settings when applying the file.

The default strategy is `consistent-hashing`, which keeps a target on a consistent server. Choose `round-robin` to rotate connections among servers, or `sticky-sessions` to keep a source/target pair on the same server temporarily. Load balancing distributes separate connections; it does not combine VPN bandwidth for one connection. Health checks use `https://www.gstatic.com/generate_204` at a 300-second interval and run lazily when the group is used.

IPv6 is disabled by default for compatibility. Enable it in the workflow or pass `--ipv6` locally if your router and VPN path support IPv6. WireGuard local IPv6 addresses and allowed ranges are retained in the proxy data; IPv6 DNS answers and global IPv6 routing follow the selected setting.

## Local usage

Use Python 3.9 or newer. Selenium downloads require Google Chrome / Chromium and a compatible WebDriver; the generator alone only requires PyYAML.

```bash
python -m pip install -r requirements.txt

# Convert the existing country-organized ZIP.
python generate_openclash.py \
  --input ProtonVPN_WireGuard_Configs.zip \
  --output config.yaml \
  --summary openclash-summary.json

# Convert an extracted directory with a different strategy.
python generate_openclash.py \
  --input ./wireguard-configs \
  --output config.yaml \
  --strategy round-robin \
  --ipv6

# Run converter tests.
python -m unittest discover -s tests -v

# Validate with an installed Mihomo core.
mihomo -t -f config.yaml
```

The converter supports IPv4 and IPv6 endpoints, multiple peer sections, optional pre-shared keys, DNS addresses, MTU, and persistent keepalive. Multiple peers must have distinct allowed ranges and use the same keepalive value. Country codes come from the immediate parent folder or a filename such as `wg-US-FREE-104.conf`; unrecognized files go into `OTHER Load Balance`. Node names include their relative paths to avoid collisions between countries.

To download locally, set `VPN_USERNAME` and `VPN_PASSWORD` in your environment, then run:

```bash
python proton_downloader_chrome.py
```

Set `DOWNLOAD_SCOPE=first` for a smaller download. The downloader creates the ZIP and optional WireGuard URI file, then removes its temporary downloads. Run `generate_openclash.py` afterward to create the YAML.

## Configuration privacy

Both `config.yaml` and the `.conf` files contain WireGuard private keys. Publishing them in a public release makes those credentials available to everyone. Use your own ProtonVPN account and a private repository when you need private configuration files. Publicly shared configurations can be rate-limited, revoked, or unstable. GitHub Actions artifacts follow the repository's visibility and expire after seven days in these workflows; release assets remain until you remove them.

## References

- [Mihomo WireGuard configuration](https://wiki.metacubex.one/en/config/proxies/wg/)
- [Mihomo load-balance groups](https://wiki.metacubex.one/en/config/proxy-groups/load-balance/)
- [OpenClash project](https://github.com/vernesong/OpenClash)
