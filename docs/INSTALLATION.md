# Install and remove AegisDNS

The installer presents six aligned stages, a compact progress rail, clear status colors, and named activity indicators for long commands. Interactive runs use color even when a parent application exports `TERM=dumb` or `NO_COLOR`. Use `--plain` for unstyled output, or `--no-animation` to retain color without movement. Redirected output is automatically plain. `AEGIS_NO_ANIMATION=1` also disables animation. No extra TUI package is required.

## Install on Linux

Use a complete checkout on a native Linux host with Python 3.10+, curl, sudo, and at least 2 GiB free on the checkout filesystem. Docker needs additional space for its images and build cache. Source builds can take several minutes and may need more memory on small machines.

```sh
./install.sh
```

Run as a regular user. Tailscale is the default network path. The installer uses the connected Tailscale IPv4 address and offers its official installer when the command is missing; authentication still requires `sudo tailscale up`. Use `--no-tailscale` when this server should use its LAN address. The installer asks visibly for sudo access and offers to install missing Docker using its official script. Docker group membership is not changed. The Docker endpoint must be local and rootful; remote engines and rootless host networking are not supported by this host-DNS flow.

Interactive privileged commands use the normal visible sudo prompt. The installer
does not assume that a previous `sudo -v` remains cached, so it also works with
sudo policies that require authentication for every command. A long build may
therefore be followed by another prompt before the CLI is installed or host DNS
is changed.

### Effect on `/etc/resolv.conf`

If Tailscale is installed **and** currently accepting its DNS settings
(`"CorpDNS": true`), the installer turns that off for the duration of the build
so Docker can reach the internet, and restores it afterwards. Tailscale can
leave its own resolver behind when disabled, so `/etc/resolv.conf` is repaired
only when it points at Tailscale's stub (`100.100.100.100`) or lists no usable
nameserver. A working resolver — a corporate DNS server, a VPN, or a
systemd-resolved symlink — is left untouched. When the file is replaced, a
timestamped copy is kept alongside it as
`/etc/resolv.conf.aegis-backup.<seconds>`.

Hosts without Tailscale, or with Tailscale not managing DNS, have
`/etc/resolv.conf` left alone entirely during installation. Host DNS is
switched to AegisDNS in the final step, and `aegis restore-dns` reverts it.

The workflow:

1. Review the installation plan and prerequisites.
2. Check Docker, Compose, and ownership of existing containers.
3. Validate and back up configuration; preserve unrelated keys, secrets, and existing local zones.
4. Build both images and check configuration readability as container user 10001.
5. Install the `aegis` command without replacing someone else’s executable.
6. Start the service, verify both containers, protected administration, and DNS over UDP and TCP.

On Linux, startup saves the current resolver configuration, adjusts the systemd-resolved stub when applicable, and directs this host’s DNS to AegisDNS. It does not change router settings or other devices. Bind mounts use shared SELinux labels for the two containers.

After successful setup:

```sh
aegis status
aegis credentials
```

Open **http://localhost:5380** on the DNS host. The username is `admin`; passwords are retrieved separately and are not printed in setup logs. Use an SSH tunnel for a remote host. Test one device before changing the rest of your network.

## Options

| Command | Effect |
| --- | --- |
| `./install.sh --ip 192.168.1.20` | Use an explicit stable IPv4 address. |
| `./install.sh --tailscale` | Explicitly select the default Tailscale path. |
| `./install.sh --no-tailscale` | Use a detected LAN address instead of Tailscale. |
| `./install.sh --no-start` | Build and install the CLI without starting or taking over host DNS. |
| `./install.sh --rebuild` | Ignore the Docker build cache. |
| `./install.sh --plain` | Plain terminal output. |
| `./install.sh --no-animation` | Keep colors but disable animated activity indicators. |
| `./install.sh --build-timeout 7200` | Allow up to two hours for the build. |
| `./install.sh --ready-timeout 240` | Allow up to four minutes for DNS readiness. |

For an unattended Linux run, preauthorize sudo in the same session and make every dependency choice explicit:

```sh
sudo -v
./install.sh --yes --plain --install-deps --ip 192.168.1.20
```

Unattended mode never waits for input. If sudo expires during a long build, it fails with the log retained; rerun after `sudo -v` and reuse the build cache. Two setup/removal operations cannot run simultaneously in the same checkout.

The installer honours the recorded Compose project and existing Compose files within the checkout when it finds an owned installation. Missing or external override files and container-name conflicts stop setup instead of silently replacing another deployment. Keep the checkout in its original location while using its installed CLI.

## Windows

Run `install.bat` from a terminal with the Python 3 launcher (or `python`) available. It opens the same Python terminal workflow. Docker Desktop must use Linux containers with **host networking enabled**. Acknowledge its limitations interactively or use `--allow-desktop` for an unattended run. Windows host DNS is not rewritten by this installer.

Docker Desktop can hide client IP addresses. Use native Linux for reliable per-device policies and DHCP. Windows does not install the Bash CLI globally: use `docker compose` from the checkout and `uninstall.bat` for removal. Windows execution needs a Windows test host; the Linux test suite does not establish Windows runtime support.

## Removal

```sh
./uninstall.sh
# Same workflow through the installed CLI:
aegis uninstall
```

First move any router/device DNS settings away from this server. The uninstaller removes this installation’s containers, restores saved Linux host DNS, and removes only the CLI symlink that points into this checkout. It keeps the data volume, local configuration, blocklist files, images, and source. Docker and Tailscale stay installed.

To delete the Compose-managed data volume as well:

```sh
./uninstall.sh --purge
```

Interactive deletion requires typing `DELETE`. For a deliberate unattended purge, use `--yes --purge`. This deletes stored policies, devices, query history, credentials and other volume contents. Local configuration and bind-mounted blocklists remain. The actual Compose project is used; no guessed volume name or global Docker prune command is used.

If stopping containers or restoring DNS fails, removal returns an error and does not proceed to data deletion or remove the recovery command. It never deletes a failed DNS backup merely to report completion.

## Recovery

Each run prints a private log/configuration-backup directory beneath `$XDG_STATE_HOME/aegisdns` (normally `~/.local/state/aegisdns`). Windows uses `%LOCALAPPDATA%/aegisdns`. These may contain private configuration: review and redact them before sharing. They are deliberately retained after removal, so you can recover settings; delete your chosen run directory manually when no longer needed.

Host DNS backups are separate, in `.dns-backup/` inside the checkout. Keep them until restoration succeeds.

- **Build failed:** the existing service is left alone. Review the log, resolve disk, memory or connectivity problems, and rerun; Docker reuses completed build layers.
- **Startup/readiness failed:** the installer attempts to stop this installation and restore saved host DNS. Data stays in place. Resolve port conflicts or outbound DNS restrictions before retrying. If recovery also fails, retain `.dns-backup/` and run `aegis stop` after addressing the reported problem.
- **Docker unavailable during removal:** restore its connection and retry. If necessary, `aegis restore-dns` can restore saved host DNS separately; it does not remove containers. Stop containers first when possible, because a running AegisDNS listener can conflict with the system resolver stub.
- **Incomplete or missing DNS backup:** restoration does not invent nameservers or discard the backup. Review the saved files and recover host DNS manually if necessary.
- **Mounted configuration unreadable:** check its permissions and SELinux access. New nonsensitive configuration is readable by container user 10001; existing file modes are preserved. Keep credentials in `.env`, not in public configuration.
- **Ctrl+C or termination:** the active command group is stopped on Linux, the cursor is restored, and startup recovery is attempted if startup had begun. Forced power loss or `kill -9` cannot run cleanup; use the saved backup to recover on the next session.

No installer can guarantee recovery from every hardware failure or interrupted administrative action. These safeguards keep failures visible and recovery data available.
