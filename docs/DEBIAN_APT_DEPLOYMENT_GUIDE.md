# VaultSync Debian package and APT repository deployment guide

Prepared: 2026-10-19  
Scope: package the current VaultSync C++ application as a `.deb`, publish it from `https://repo.palash.pro`, and install it with APT.

## Decision and feasibility

**Feasible, with two small packaging changes and one security prerequisite.** VaultSync already builds cleanly as a C++17 executable and has no third-party link-time dependencies. A local Release build and `ctest` completed successfully; the executable links to the normal C/C++ runtime libraries only.

| Area | Status | What must happen |
| --- | --- | --- |
| Build | Ready | CMake Release build and the existing `test_cipher` test pass. |
| `.deb` payload | Not configured | Add an `install(TARGETS ...)` rule; without it CPack has nothing to place in the package. |
| Runtime dependencies | Straightforward | Build on the target Debian/Ubuntu family and enable CPack's `dpkg-shlibdeps` integration. |
| Persistent vault data | Needs a code change | Move from the current working-directory-relative `data/vault_<user>.bin` path to per-user XDG state data. |
| Repository | Ready to build | `reprepro` + GPG + static Nginx hosting is a good fit for one package and a small number of architectures. |
| HTTPS endpoint | External prerequisite | The operator must control DNS for `repo.palash.pro` and allow inbound TCP 80/443 to the Nginx host. |
| Security claim | Blocker for public credential use | The source explicitly labels its repeating-key XOR cipher educational and not cryptographically secure. Do not market this package as a secure password manager until it uses an audited authenticated-encryption design and a password KDF. |

This guide chooses a dedicated subdomain, `repo.palash.pro`, rather than mixing package files with the main site. It can be adapted to `https://palash.pro/vaultsync` if a subdomain is unavailable; see [Using a path instead](#using-a-path-instead-of-a-subdomain).

## Architecture

```text
release workstation / CI                    repository host
-------------------------                   ---------------------------------
CMake -> CPack -> .deb  -- authenticated --> reprepro private state
                                              |             |
                                              |             +-- GPG signs Release metadata
                                              v
                                            /srv/www/vaultsync-apt/{dists,pool,key}
                                                           |
                                                    Nginx + TLS
                                                           |
                                             https://repo.palash.pro
                                                           |
                                              client APT (Signed-By key)
```

Keep the following boundaries strict:

- The private GPG key and reprepro database are never in the Nginx document root, a Git repository, a container image, or an untrusted CI log.
- Nginx exposes only `dists/`, `pool/`, and the public archive key.
- A repository signing key authenticates the repository metadata; it does **not** make an insecure application cryptographically safe.
- Publish an immutable new package version for each release. Never replace a `.deb` that has the same version and filename.

## 1. Make the application package-ready

### 1.1 Add CMake install and CPack DEB configuration

Change `project(VaultSync VERSION 1.0 ...)` to `VERSION 1.0.0` and add the following **after** the `VaultSync` target is declared, before `include(CPack)`. Keep the test target out of the installation payload.

```cmake
# Install only the end-user program and documentation.
install(TARGETS VaultSync
    RUNTIME DESTINATION bin
)
install(FILES README.md architecture.md
    DESTINATION share/doc/vaultsync
)

# CPack / Debian binary package metadata.
set(CPACK_GENERATOR "DEB")
set(CPACK_PACKAGE_NAME "vaultsync")
set(CPACK_PACKAGE_VENDOR "Palash Patel")
set(CPACK_PACKAGE_CONTACT "packages@palash.pro") # Replace if this mailbox does not exist.
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY
    "Terminal vault manager for personal credential records")
set(CPACK_PACKAGE_DESCRIPTION
    "VaultSync is a C++17 terminal vault manager for personal credential records.")
set(CPACK_DEBIAN_PACKAGE_MAINTAINER "Palash Patel <packages@palash.pro>")
set(CPACK_DEBIAN_PACKAGE_SECTION "utils")
set(CPACK_DEBIAN_PACKAGE_PRIORITY "optional")
set(CPACK_DEBIAN_PACKAGE_HOMEPAGE "https://github.com/palash-08/VaultSync")
set(CPACK_DEBIAN_FILE_NAME "DEB-DEFAULT")
set(CPACK_DEBIAN_PACKAGE_RELEASE "1")
set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS ON)
set(CPACK_DEBIAN_COMPRESSION_TYPE "gzip")
set(CPACK_DEBIAN_PACKAGE_CONTROL_STRICT_PERMISSION TRUE)

include(CPack)
```

`DEB-DEFAULT` asks CPack to produce the conventional `vaultsync_1.0.0-1_amd64.deb` filename. `CPACK_DEBIAN_PACKAGE_SHLIBDEPS` makes CPack use `dpkg-shlibdeps`; do not manually hard-code libc dependency versions unless a package inspection proves that is necessary. CMake documents the DEB control fields, `DEB-DEFAULT`, and `dpkg-shlibdeps` integration at <https://cmake.org/cmake/help/latest/cpack_gen/deb.html>.

Use a real monitored address for `CPACK_PACKAGE_CONTACT` and the Maintainer field. That is where security and packaging reports should land.

### 1.2 Relocate mutable vault data before distribution

This is essential for an installed executable. `MasterVault::getVaultPathForUser()` currently returns `data/vault_<username>.bin`, and `FileStorage::resolvePath()` searches the current and parent working directory. After `/usr/bin/vaultsync` is installed, this could create data under whichever directory the user happened to be in. It also allows a username containing path separators to influence the output path.

Before public distribution, make a small source change with these rules:

1. Resolve the state root as `$XDG_STATE_HOME/vaultsync`, otherwise `$HOME/.local/state/vaultsync`.
2. Create the directory with permissions `0700`; create each vault file with `0600`.
3. Do not fall back to the caller's working directory.
4. Validate or encode the username before it becomes any filename component. A stable opaque user ID or a hex digest is safer than concatenating raw input.
5. Add a migration path that detects the old project-local file, imports it once only after explicit user confirmation, and preserves a backup.
6. Add a test covering state-root resolution, filename traversal rejection, and restrictive permissions.

For a password manager, also replace the documented educational XOR cipher with a reviewed authenticated-encryption scheme (for example an AEAD construction) and derive its key using a well-reviewed, memory-hard password KDF. Package signing cannot mitigate weak at-rest encryption.

### 1.3 Build, test, package, and inspect

Run these on a clean Debian or Ubuntu build host. `dpkg-dev` supplies `dpkg-shlibdeps`; `fakeroot` is useful for package-oriented workflows.

```bash
sudo apt-get update
sudo apt-get install --yes build-essential cmake dpkg-dev fakeroot

cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
ctest --test-dir build --output-on-failure

# Pin the release version at configure time, or set it from a signed release tag.
cpack --config build/CPackConfig.cmake --generator DEB

dpkg-deb --info build/vaultsync_1.0.0-1_amd64.deb
dpkg-deb --contents build/vaultsync_1.0.0-1_amd64.deb
```

The package contents should include `/usr/bin/VaultSync` (or preferably rename the target to install as lowercase `vaultsync`) and documentation beneath `/usr/share/doc/vaultsync/`. It should not include the test program, source tree, build directory, or a vault data directory.

Test the exact artifact in a disposable Debian/Ubuntu VM or container of the oldest supported release:

```bash
sudo apt-get install --yes ./build/vaultsync_1.0.0-1_amd64.deb
command -v VaultSync
dpkg-query -W -f='${Package} ${Version} ${Architecture}\n' vaultsync
```

Build separately on each supported architecture. A native `amd64` build produces an `amd64` package; it does not produce an `arm64` package merely by changing the filename.

### 1.4 Version discipline

- Use upstream version plus Debian revision: `1.0.0-1`, then `1.0.0-2` for a packaging-only correction, then `1.0.1-1` for a product release.
- Use `~` for pre-releases, for example `1.1.0~rc1-1`, so stable APT ordering works as intended.
- Never overwrite a published version. APT caches index and package data, and repository tools can cache package metadata.
- Set `SOURCE_DATE_EPOCH` from the signed source tag or commit timestamp in release CI for more reproducible CPack output. CPack's DEB generator honors it.

## 2. Prepare the repository host

The following assumes a Debian or Ubuntu server and a dedicated service account. Substitute the server's real administrative group and SSH policy.

```bash
sudo apt-get update
sudo apt-get install --yes nginx reprepro gnupg curl ca-certificates

sudo adduser --system --group --home /srv/vaultsync-reprepro vaultsync-repo
sudo install -d -o vaultsync-repo -g vaultsync-repo -m 0750 \
  /srv/vaultsync-reprepro \
  /srv/vaultsync-reprepro/conf \
  /srv/vaultsync-reprepro/incoming
sudo install -d -o vaultsync-repo -g www-data -m 0755 /srv/www/vaultsync-apt
```

Use SSH/SFTP, a restricted deploy account, or a CI runner that can write only to `/srv/vaultsync-reprepro/incoming`. Do not let Internet clients upload to Nginx and do not make the repository host's signing key available to arbitrary CI jobs.

## 3. Create and protect the archive signing key

The key signs the repository `Release` metadata. Clients verify its public half during `apt update`.

### 3.1 Baseline: dedicated signing key

For a small personal archive, create a dedicated signing-only key in a dedicated GnuPG home. Do this as `vaultsync-repo` on a protected host, or create it on an offline workstation and import only an appropriate signing subkey to the repository host.

```bash
sudo -u vaultsync-repo -H sh -c '
  install -d -m 0700 "$HOME/.gnupg"
  gpg --quick-generate-key "VaultSync APT Archive <packages@palash.pro>" \
    rsa4096 sign 2y
'

sudo -u vaultsync-repo -H gpg --list-secret-keys --keyid-format LONG
sudo -u vaultsync-repo -H gpg --with-colons --list-keys "VaultSync APT Archive" \
  | awk -F: '$1 == "fpr" { print $10; exit }'
```

Record the displayed 40-hex-character fingerprint in the release runbook and on an independent authenticated channel (for example a signed Git release and project website). A URL served by the same repository is convenient but is not an independent fingerprint-verification channel.

Set a strong passphrase when GnuPG's pinentry prompts for it. Configure `gpg-agent` for the dedicated release account if releases must be attended or automated; do **not** create an unprotected private key merely to make unattended signing easier.

For a hardened setup, retain an offline, certify-only primary key and create a time-limited signing subkey for the online repository host. Keep an encrypted offline backup and rehearse key rotation. Never place a private key in Git, in `/srv/www/vaultsync-apt`, or in a CI secret that any pull request can access.

Set the variables used below:

```bash
export GNUPGHOME=/srv/vaultsync-reprepro/.gnupg
export FPR='REPLACE_WITH_THE_40_HEX_FINGERPRINT'
```

Ensure `GNUPGHOME` is owned by `vaultsync-repo`, mode `0700`, and that normal release commands run as that account.

### 3.2 Publish only the public archive key

Export both an armored copy (easy for people to inspect) and a binary keyring (easy for APT clients). The exported public key can be served by Nginx.

```bash
sudo -u vaultsync-repo -H env GNUPGHOME="$GNUPGHOME" \
  gpg --armor --export "$FPR" \
  | sudo tee /srv/www/vaultsync-apt/vaultsync-archive-keyring.asc >/dev/null

sudo -u vaultsync-repo -H env GNUPGHOME="$GNUPGHOME" \
  gpg --export "$FPR" \
  | sudo tee /srv/www/vaultsync-apt/vaultsync-archive-keyring.gpg >/dev/null

sudo chown root:root /srv/www/vaultsync-apt/vaultsync-archive-keyring.asc \
  /srv/www/vaultsync-apt/vaultsync-archive-keyring.gpg
sudo chmod 0644 /srv/www/vaultsync-apt/vaultsync-archive-keyring.asc \
  /srv/www/vaultsync-apt/vaultsync-archive-keyring.gpg
```

The pipeline shown above assumes the caller can use `sudo` and that `$GNUPGHOME` and `$FPR` are exported in the invoking shell. In a production runbook, prefer a short root-owned publish script with fixed paths rather than copying shell snippets blindly.

## 4. Publish with reprepro (recommended)

`reprepro` manages the archive database, creates `pool/` and `dists/`, and signs generated repository metadata. It is the preferred path here. Its `--basedir` is private state, while `--outdir` can be the public static directory; the Debian man page documents this separation.

### 4.1 Configure the distribution

Create `/srv/vaultsync-reprepro/conf/distributions` with exactly the following structure, replacing the fingerprint and adding architectures only after producing packages for them:

```text
Origin: VaultSync
Label: VaultSync
Codename: stable
Suite: stable
Architectures: amd64
Components: main
Description: VaultSync packages for Debian and Ubuntu
SignWith: REPLACE_WITH_THE_40_HEX_FINGERPRINT
```

Set safe permissions:

```bash
sudo chown vaultsync-repo:vaultsync-repo /srv/vaultsync-reprepro/conf/distributions
sudo chmod 0640 /srv/vaultsync-reprepro/conf/distributions
```

The public output will be:

```text
/srv/www/vaultsync-apt/
├── dists/
│   └── stable/
│       ├── InRelease
│       ├── Release
│       ├── Release.gpg
│       └── main/binary-amd64/Packages{,.gz}
├── pool/
│   └── main/v/vaultsync/vaultsync_1.0.0-1_amd64.deb
├── vaultsync-archive-keyring.asc
└── vaultsync-archive-keyring.gpg
```

`dists/` holds signed index metadata and `pool/` holds payloads. Do not use the same suite/component/architecture slot to keep multiple versions: reprepro intentionally keeps one active version there. Retain release artifacts elsewhere for rollback, or publish a separate `preview` suite for pre-release testing.

### 4.2 First publication

Copy the inspected `.deb` to the incoming directory, then include it as the service account:

```bash
sudo install -o vaultsync-repo -g vaultsync-repo -m 0644 \
  build/vaultsync_1.0.0-1_amd64.deb \
  /srv/vaultsync-reprepro/incoming/

sudo -u vaultsync-repo -H env GNUPGHOME=/srv/vaultsync-reprepro/.gnupg \
  reprepro \
    --basedir /srv/vaultsync-reprepro \
    --outdir /srv/www/vaultsync-apt \
    includedeb stable /srv/vaultsync-reprepro/incoming/vaultsync_1.0.0-1_amd64.deb

sudo -u vaultsync-repo -H env GNUPGHOME=/srv/vaultsync-reprepro/.gnupg \
  reprepro \
    --basedir /srv/vaultsync-reprepro \
    --outdir /srv/www/vaultsync-apt \
    list stable vaultsync
```

The first command performs the import, writes the package to the pool, regenerates index data, and creates signed `InRelease`/`Release.gpg` metadata because `SignWith` is configured. The second command is an inspection step, not a publication step.

Before each release, repeat: build -> test -> inspect `dpkg-deb` -> test-install in a clean VM -> copy to `incoming` -> `includedeb` -> test an external client. Use a lock around release commands if more than one publisher could run; never let two `reprepro` updates race.

### 4.3 Verify the published archive locally

```bash
sudo -u vaultsync-repo -H env GNUPGHOME=/srv/vaultsync-reprepro/.gnupg \
  gpg --verify /srv/www/vaultsync-apt/dists/stable/InRelease

test -f /srv/www/vaultsync-apt/dists/stable/main/binary-amd64/Packages.gz
test -f /srv/www/vaultsync-apt/pool/main/v/vaultsync/vaultsync_1.0.0-1_amd64.deb
```

`reprepro` writes new index files before making them final, but do not add a proxy cache that serves stale `InRelease` or `Release` files. Keep package payloads that are referenced by current metadata available.

## 5. Alternative: generate an archive with apt-ftparchive

Use this only if the archive is deliberately simple and there is a single disciplined publisher. Do **not** run it over a reprepro-managed public tree: choose one metadata writer.

Install the producer tool:

```bash
sudo apt-get install --yes apt-utils gnupg
```

For a one-architecture archive rooted at `/srv/www/vaultsync-apt`, use this release procedure:

```bash
cd /srv/www/vaultsync-apt
sudo install -d -m 0755 pool/main/v/vaultsync dists/stable/main/binary-amd64
sudo install -m 0644 /path/to/vaultsync_1.0.0-1_amd64.deb \
  pool/main/v/vaultsync/

apt-ftparchive packages pool/main \
  > dists/stable/main/binary-amd64/Packages
gzip --keep --force --best dists/stable/main/binary-amd64/Packages
```

Create a protected release configuration such as `/etc/vaultsync-apt/release.conf`:

```text
APT::FTPArchive::Release {
  Origin "VaultSync";
  Label "VaultSync";
  Suite "stable";
  Codename "stable";
  Architectures "amd64";
  Components "main";
  Description "VaultSync packages for Debian and Ubuntu";
};
```

Generate and sign metadata only after all pool and Packages files have been written:

```bash
cd /srv/www/vaultsync-apt
apt-ftparchive -c /etc/vaultsync-apt/release.conf release dists/stable \
  > dists/stable/Release

gpg --batch --yes --local-user "$FPR" --clearsign \
  --output dists/stable/InRelease dists/stable/Release
gpg --batch --yes --local-user "$FPR" --armor --detach-sign \
  --output dists/stable/Release.gpg dists/stable/Release
```

For zero client exposure to an update-in-progress, create the full next archive in a non-public staging directory and atomically replace a symlink that Nginx serves, retaining prior complete trees for rollback. `apt-ftparchive` generates `Packages` and `Release` metadata but does not manage this transactional lifecycle for you. Its Debian manual describes the `packages` and `release` generators and the Release metadata fields at <https://manpages.debian.org/trixie/apt-utils/apt-ftparchive.1.en.html>.

## 6. DNS, Nginx, and TLS

### 6.1 DNS and firewall prerequisites

1. Create an `A` record for `repo.palash.pro` pointing at the repository server's public IPv4 address; add an `AAAA` record only if IPv6 is actually routed and firewalled correctly.
2. Wait for public DNS resolution before requesting a certificate.
3. Allow TCP ports 80 and 443 through the cloud firewall and host firewall.
4. Keep port 80 reachable for HTTP-01 certificate renewal and redirect normal traffic to HTTPS. Let's Encrypt specifically recommends this pattern; if port 80 cannot be exposed, use DNS-01 validation instead.

The current environment cannot establish the actual public reachability of `palash.pro` or `repo.palash.pro`; complete this check from the chosen server and a separate external network before publishing.

### 6.2 Serve HTTP briefly for ACME validation

Install Certbot by the supported method for the server OS, then prepare the ACME challenge directory:

```bash
sudo install -d -o www-data -g www-data -m 0755 /var/www/certbot/.well-known/acme-challenge
```

Create `/etc/nginx/sites-available/repo.palash.pro` with this initial HTTP-only server block:

```nginx
server {
    listen 80;
    listen [::]:80;
    server_name repo.palash.pro;

    location ^~ /.well-known/acme-challenge/ {
        root /var/www/certbot;
        default_type "text/plain";
    }

    location / {
        return 404;
    }
}
```

Enable and validate it before requesting a certificate:

```bash
sudo ln -s /etc/nginx/sites-available/repo.palash.pro \
  /etc/nginx/sites-enabled/repo.palash.pro
sudo nginx -t
sudo systemctl reload nginx

sudo certbot certonly --webroot -w /var/www/certbot \
  -d repo.palash.pro \
  --email YOU@palash.pro --agree-tos --no-eff-email
```

If this fails, fix DNS, port 80 routing, or the Nginx challenge location. Do not bypass certificate validation or serve the repository over plain HTTP as a permanent workaround.

### 6.3 Final TLS virtual host

Replace the initial configuration with the following after Certbot has created the certificate. Review the HSTS decision: it is appropriate for this dedicated repository subdomain, but do not set `includeSubDomains` unless every present and future child name is HTTPS-only.

```nginx
server {
    listen 80;
    listen [::]:80;
    server_name repo.palash.pro;

    location ^~ /.well-known/acme-challenge/ {
        root /var/www/certbot;
        default_type "text/plain";
    }

    location / {
        return 301 https://$host$request_uri;
    }
}

server {
    listen 443 ssl;
    listen [::]:443 ssl;
    server_name repo.palash.pro;

    root /srv/www/vaultsync-apt;
    autoindex off;
    server_tokens off;

    ssl_certificate     /etc/letsencrypt/live/repo.palash.pro/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/repo.palash.pro/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;

    add_header Strict-Transport-Security "max-age=31536000" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "no-referrer" always;

    location / {
        try_files $uri =404;
    }
}
```

Apply and test:

```bash
sudo nginx -t
sudo systemctl reload nginx
sudo certbot renew --dry-run

curl --fail --silent --show-error --head \
  https://repo.palash.pro/dists/stable/InRelease
curl --fail --silent --show-error --head \
  https://repo.palash.pro/vaultsync-archive-keyring.gpg
```

Nginx's HTTPS documentation requires the `ssl` parameter on the listener plus certificate and key paths; it also notes that the private key must be restricted while remaining readable by the Nginx master process: <https://nginx.org/en/docs/http/configuring_https_servers.html>. Let Certbot's installed renewal mechanism manage renewal, and retain the dry-run check in routine operations.

### Using a path instead of a subdomain

If the endpoint must be `https://palash.pro/vaultsync`, place the public repository under `/srv/www/palash.pro/vaultsync`, configure an Nginx `location /vaultsync/ { alias /srv/www/palash.pro/vaultsync/; }`, and use this client source:

```text
deb [signed-by=/etc/apt/keyrings/vaultsync-archive-keyring.gpg] https://palash.pro/vaultsync stable main
```

Be exact about the trailing slash on `alias`; an incorrect `alias`/URI combination is a common way to expose the wrong filesystem path. The subdomain is simpler operationally and isolates cache and TLS policy from the main website.

## 7. Client installation with a scoped signing key

Do this from a clean supported Debian/Ubuntu client. Obtain the fingerprint from an independent channel first, then download the key over HTTPS and compare it before trusting the repository.

```bash
sudo apt-get update
sudo apt-get install --yes ca-certificates curl gpg

EXPECTED_FPR='REPLACE_WITH_THE_40_HEX_FINGERPRINT'

curl --fail --show-error --location \
  --output /tmp/vaultsync-archive-keyring.asc \
  https://repo.palash.pro/vaultsync-archive-keyring.asc

gpg --show-keys --with-colons /tmp/vaultsync-archive-keyring.asc \
  | awk -F: '$1 == "fpr" { print $10; exit }'
# Compare that output with $EXPECTED_FPR before continuing.

gpg --dearmor --yes \
  --output /tmp/vaultsync-archive-keyring.gpg \
  /tmp/vaultsync-archive-keyring.asc

sudo install -d -m 0755 /etc/apt/keyrings
sudo install -m 0644 /tmp/vaultsync-archive-keyring.gpg \
  /etc/apt/keyrings/vaultsync-archive-keyring.gpg
rm -f /tmp/vaultsync-archive-keyring.asc /tmp/vaultsync-archive-keyring.gpg
```

Use the modern deb822 source file at `/etc/apt/sources.list.d/vaultsync.sources`:

```text
Types: deb
URIs: https://repo.palash.pro
Suites: stable
Components: main
Architectures: amd64
Signed-By: /etc/apt/keyrings/vaultsync-archive-keyring.gpg
```

Then update and install:

```bash
sudo apt-get update
apt-cache policy vaultsync
sudo apt-get install --yes vaultsync
```

`Signed-By` deliberately scopes this archive key to this repository. Do not use `apt-key add`; APT's current documentation recommends `/etc/apt/keyrings` for locally administered keys and per-source `Signed-By` configuration: <https://manpages.debian.org/testing/apt/apt-secure.8.en.html>.

For older automation that cannot use deb822, the equivalent one-line source is:

```text
deb [arch=amd64 signed-by=/etc/apt/keyrings/vaultsync-archive-keyring.gpg] https://repo.palash.pro stable main
```

Put it in `/etc/apt/sources.list.d/vaultsync.list`, then run the same `apt-get update` and `apt-get install` commands. Do not configure both forms at once.

## 8. Release checklist and rollback plan

### Before release

- [ ] Source version, package version, and Git tag agree.
- [ ] Build and `ctest` pass on each target architecture.
- [ ] `dpkg-deb --info` has the intended package name, version, architecture, maintainer, and dependencies.
- [ ] A clean VM installed the exact `.deb` successfully and the executable starts.
- [ ] The version is new; no prior package filename/version is being reused.
- [ ] The signer fingerprint matches the expected archive key and no private key is in the document root or CI logs.
- [ ] DNS, HTTPS, renewal dry run, and external `curl` checks pass.

### After publication

- [ ] `reprepro list stable vaultsync` shows the expected package.
- [ ] `gpg --verify dists/stable/InRelease` passes.
- [ ] A clean remote client adds the key, runs `apt-get update`, and installs `vaultsync` without a trust warning.
- [ ] Archive state (`conf/`, `db/`, and `pool/`) is backed up; signing-key backup remains encrypted and offline.
- [ ] Monitor certificate expiry, Nginx errors, free disk space, and failed release jobs.

### Rollback

For a bad application release, publish a higher fixed version rather than silently replacing the bad `.deb`. If a release must be withdrawn, remove it from the suite with a planned `reprepro remove stable vaultsync`, export new signed metadata, and verify a clean client sees the intended result. Retain the old `pool` package and archive state long enough to support a controlled downgrade; do not delete a package still referenced by any published `Packages` index.

For a compromised archive key, stop publication, revoke and replace the key, publish the new key and signed metadata, and give clients explicit migration instructions that list both old and new fingerprints. Do not ask clients to disable APT signature checks.

## 9. Common failure modes

| Symptom | Likely cause | Correct response |
| --- | --- | --- |
| CPack creates a DEB with no executable | No `install()` rule | Add the `install(TARGETS VaultSync ...)` rule, reconfigure, and inspect the package contents. |
| `dpkg-shlibdeps` fails or dependencies are absent | Build host lacks Debian tools | Install `dpkg-dev`; build on the distribution family being targeted. |
| `apt update` says `NO_PUBKEY` | Wrong key, bad `Signed-By` path, unreadable key file | Verify the fingerprint, install the public key as `0644`, and point the source at that exact keyring. |
| `does not have a Release file` | Wrong URL, suite, component, or missing export | Check `https://repo.palash.pro/dists/stable/InRelease` and the reprepro configuration. |
| Hash mismatch | Partial update, CDN/proxy cache, or overwritten version | Publish atomically, avoid caching signed metadata, and never reuse a version. |
| Nginx returns 403 | Directory traversal permissions do not let `www-data` reach the document root | Keep public root and parents traversable (`0755`) while leaving private reprepro/GPG paths inaccessible. |
| Certificate request fails | DNS/port 80/ACME location problem | Verify public DNS and port 80 externally, then use the webroot location or switch deliberately to DNS-01. |
| Vault files appear in random directories | Current CWD-relative data path | Implement the XDG state-directory change before distribution. |

## Recommended implementation order

1. Fix data-path and cipher security posture; add tests for the data path.
2. Add CMake `install()` and CPack configuration, then test the `.deb` in a clean VM.
3. Register `repo.palash.pro` DNS and provision the locked-down repository host.
4. Create/protect the GPG signing key, publish its public half, and record the fingerprint independently.
5. Configure reprepro and publish the first tested package into `stable`.
6. Put Nginx and TLS in front of the static public output; verify renewal and remote reads.
7. Install from a second clean machine using the scoped `Signed-By` keyring.
8. Automate the guarded release flow only after the manual workflow has been proven and documented.

This order avoids the most damaging failure modes: a package with no payload, vault data written to an arbitrary directory, unscoped APT trust, unsigned metadata, or a public web root containing signing material.
