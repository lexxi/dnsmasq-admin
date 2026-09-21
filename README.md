# dnsmasq-admin

Lightweight Flask web interface for managing **dnsmasq DHCP reservations, leases, IP segments and local DNS**.

> **Status:** early release / v0.1.0. Test in your environment before using it on a production DHCP server.

## Features

- View current DHCP reservations and dynamic leases
- Show remaining lease lifetime
- Convert a dynamic lease into a fixed reservation
- Organize addresses into configurable IP segments
- Move existing reservations between segments
- Automatically select the next free address in a segment
- Detect overlapping segments
- IPv4 network overview with reservations and leases
- Regenerate local host records after changes
- Optional lease cleanup when moving a device to a new fixed IP
- Automatic backups before modifying configuration files
- Health endpoint and config hot reload

## Requirements

- Linux
- Python 3.9+
- dnsmasq
- systemd (for the supplied service example)
- Flask

The application changes dnsmasq configuration and may stop/start dnsmasq when a lease has to be reassigned. The supplied service therefore runs as root. If you expose the web UI beyond a trusted management network, add authentication and a reverse proxy first.

## Installation

```bash
sudo apt install python3 python3-venv dnsmasq git

sudo git clone https://github.com/lexxi/dnsmasq-admin.git /opt/dnsmasq-admin
cd /opt/dnsmasq-admin

python3 -m venv myenv
./myenv/bin/pip install -r requirements.txt

cp config.example.json config.json
vi config.json
```

Install the host-generation helper:

```bash
sudo install -m 0755 scripts/convert_hosts.sh /opt/scripts/convert_hosts.sh
```

Edit the variables at the top of `/opt/scripts/convert_hosts.sh` for your environment.

Install the systemd service:

```bash
sudo cp systemd/dnsmasq-admin.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now dnsmasq-admin
```

The default web port is **8088**.

## dnsmasq configuration

The reservations file managed by this project contains normal dnsmasq configuration lines:

```ini
dhcp-host=00:11:22:33:44:55,192.168.1.50,workstation
```

Therefore include it from your main dnsmasq configuration with:

```ini
conf-file=/etc/dnsmasq.d/dhcp-reservations.conf
```

Do **not** use `dhcp-hostsfile=` for this format. `dhcp-hostsfile` expects a different file syntax.

A minimal example:

```ini
domain-needed
bogus-priv
expand-hosts
no-resolv

local=/home.local/
domain=home.local

interface=eth0
listen-address=127.0.0.1,192.168.1.2

server=1.1.1.1
server=8.8.8.8

dhcp-range=192.168.1.150,192.168.1.199,1d
dhcp-option=3,192.168.1.1

addn-hosts=/etc/hosts
dhcp-leasefile=/var/lib/misc/dnsmasq.leases
conf-file=/etc/dnsmasq.d/dhcp-reservations.conf
```

Validate dnsmasq after configuration changes:

```bash
dnsmasq --test
```

## Configuration

Copy `config.example.json` to `config.json`. The real `config.json` is intentionally ignored by Git.

Example segment:

```json
{
  "name": "Linux",
  "color": "#93c5fd",
  "start_ip": "192.168.1.20",
  "size": 10,
  "hostname_prefix": "linux"
}
```

The segment represents `start_ip` plus `size` consecutive IPv4 addresses.

### Lease reassignment

When a device first joins the network it may already have a dynamic lease. Moving it to a fixed segment can otherwise leave the old address active until the lease expires.

With:

```json
"force_lease_reassign_on_move": true
```

dnsmasq-admin performs the following operation after moving a reservation:

1. write the new fixed reservation;
2. regenerate host records;
3. stop dnsmasq;
4. remove only the lease belonging to that MAC address;
5. start dnsmasq again.

The client can then obtain its newly reserved address on the next DHCP request/reboot.

## Local DNS / hosts helper

`scripts/convert_hosts.sh` creates host entries from the managed `dhcp-host=` records. Configure `DNSMASQ_RES_FILE`, `HOSTS_FILE`, `DOMAIN` and `LOCAL_HOSTNAME` at the top of the script before installing it.

## Security

dnsmasq-admin is intended for a trusted administrative network. v0.1.0 does **not** provide built-in user authentication.

Do not expose port 8088 directly to the Internet.

The Flask secret in the supplied systemd unit is an example value. Change it before deployment.

## Development

Syntax check:

```bash
./myenv/bin/python -m py_compile app.py helpers/parser.py helpers/system.py
```

Run manually:

```bash
./myenv/bin/python app.py
```

## License

MIT License. See [LICENSE](LICENSE).
