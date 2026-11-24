# ShadowNetX

ShadowNetX is a Java 21 terminal chat prototype with one central HTTPS server, MySQL account storage, invitation-based registration, owner/member roles, and one live group room. Chat messages and invitations are held in server memory only. **No Tor is used.**

## Supported deployment

- Server: your MacBook (must remain powered on, online, and running the server process).
- Clients: macOS and Windows laptops.
- Remote access: use a private Tailscale network so invited people can connect from other homes/countries without exposing port 8443 to the public internet.
- Transport: HTTPS on TCP 8443, with a SHA-256 certificate fingerprint pinned by each client.

This is a private-network deployment, not an unrestricted public website. Every remote user/device must be authorized in your Tailscale network and must have an invitation to create a ShadowNetX account.

## 1. Prepare the Mac server

1. Install Java 21+ and Maven on the Mac.
2. Install MySQL and complete the database setup below.
3. Install Tailscale on the Mac, sign in, and authorize it in your tailnet. Keep Tailscale running.
4. In Tailscale, find the Mac's Tailscale IPv4 address (usually `100.x.y.z`) or its MagicDNS name. Prefer the MagicDNS name if enabled.
5. Start the server from the project folder:

   ```sh
   ./startup/mac/startup.sh server
   ```

6. Keep the server Terminal open. The server binds to `0.0.0.0:8443`, so it can accept connections on the Mac's LAN and Tailscale interfaces. The app prints its certificate SHA-256 fingerprint. Keep that fingerprint and share it with invited users through a trusted channel (in person, voice call, or another channel you trust).

The Mac must not sleep while hosting. In macOS, enable the setting that prevents automatic sleep while the display is off, and keep it connected to power and the internet. If the Mac shuts down, loses internet, or the server process stops, clients cannot connect.

## 2. Configure remote clients

Install Tailscale on each Windows/Mac client device, have the user sign in to your tailnet, and approve the device. Confirm the client can reach the Mac's Tailscale IP/name. Do not configure router port forwarding and do not expose TCP 8443 to the public internet.

### macOS client

Open Terminal in the project folder and run (replace the example with the server's Tailscale IP or MagicDNS name):

```sh
export SHADOWNETX_SERVER_HOST=100.x.y.z
export SHADOWNETX_SERVER_PORT=8443
./startup/mac/startup.sh
```

To use MagicDNS instead, for example:

```sh
export SHADOWNETX_SERVER_HOST=macbook-name.your-tailnet.ts.net
./startup/mac/startup.sh
```

### Windows client (PowerShell)

Open PowerShell in the project folder and run:

```powershell
$env:SHADOWNETX_SERVER_HOST = '100.x.y.z'
$env:SHADOWNETX_SERVER_PORT = '8443'
.\startup\win\startup.bat
```

Or use the MagicDNS name as the host value. The variables apply to that PowerShell window; set them again in a new window.

## 3. First connection and certificate pinning

On the first connection, each client asks for the server's SHA-256 certificate fingerprint. Compare it character-for-character with the fingerprint printed in the Mac server terminal. Only enter it after verifying it with the server owner through a trusted, separate channel. The client stores the pin locally for that host and port. If the server certificate is regenerated, clients will reject the changed certificate until the new fingerprint is independently verified and the old local pin is updated.

The client uses certificate fingerprint pinning; it does not use a public certificate authority. The current self-signed certificate is suitable for this pinned prototype. Keep the server's `~/.shadownetx/server.p12` and `server-key.bin` files private and backed up securely; do not distribute them to clients.

## 4. MySQL setup (server Mac only)

Edit `db/setup.sql` and replace `REPLACE_WITH_A_LONG_RANDOM_PASSWORD` with a unique password. Run once from the project folder:

```sh
mysql -u root -p < db/setup.sql
```

The script creates the `shadownetx` database, a restricted `shadownetx_app` account, and the `users` table. The server prompts for the app database password when started. Clients do not need MySQL or database credentials. You can set `SHADOWNETX_DB_PASSWORD` in the server shell instead of entering it interactively.

## 5. Accounts and chat

The first registered account becomes the owner. The owner creates one-use invitation keys for additional members. Registration returns to the login/register prompt; successful login enters the live group room. Type `/back` to leave the room and access account/owner options. All users must have Tailscale connectivity and a valid invitation to register.

## 6. Troubleshooting

- **Connection refused / timeout:** confirm Tailscale is connected on both devices, the server is running, and the host is the Mac's Tailscale IP/MagicDNS name (not `127.0.0.1`).
- **Fingerprint mismatch:** stop and verify with the server owner. Do not bypass this warning. A changed certificate requires independently verifying and updating the pin.
- **Database error:** check MySQL is running and the app password in `db/setup.sql` matches the password entered by the server.
- **Windows cannot run launcher:** install Java 21+ and Maven, then run the PowerShell launcher from the project folder.
- **Mac sleeps:** keep the Mac awake, on power, and connected to the internet while hosting.

## Data and security notes

The MySQL `users` table stores user IDs and salted PBKDF2 password hashes. User ID 1 is the owner. Invitations, login sessions, and live-room queues are in memory and reset when the server stops. HTTPS encrypts traffic in transit, but TLS terminates at the server; this is **not end-to-end encryption**. Tailscale restricts network reachability to authorized tailnet devices, while ShadowNetX invitations restrict account registration. This is a course prototype, not a production-secure messaging service. Do not use it for sensitive communications.

## Build and tests

```sh
mvn clean test
mvn compile exec:java -Dexec.args=server
```

The automated tests cover password hashing, one-use invitation behavior, and live-room delivery. A successful build/test does not replace a real two-device remote integration test.
