# Xray Installer for Linux

This script allows you to install and configure Xray on your Linux server easily.

## Features

* Automatic installation of Xray
* Configures essential dependencies
* Supports various protocols such as VLESS, VMess, and Trojan

## Installation

To install Xray, run the following command:

```bash
curl -O https://raw.githubusercontent.com/sh4dowByte/xray-server/refs/heads/main/install.sh
chmod +x install.sh
sudo ./install.sh
```

## Requirements

* A Linux-based server (Ubuntu, Debian, CentOS, etc.)
* Root or sudo access
* Internet connection

## Configuration

After installation, you can configure Xray by modifying the configuration file located at:

```bash
/etc/xray/config.json
```

To apply changes, restart the Xray service:

```bash
sudo systemctl restart xray
```

## Uninstallation

If you want to remove Xray, use:

```bash
sudo systemctl stop xray
sudo systemctl disable xray
sudo rm -rf /etc/xray /usr/local/bin/xray /var/log/xray
```

## Troubleshooting

* Check the service status:
  ```bash
  sudo systemctl status xray
  ```
* View logs:
  ```bash
  journalctl -u xray --no-pager -n 50
  ```

## License

This script is provided under the MIT License.

---

**Note:** Use this script at your own risk. Ensure you review the script before execution.

## Disclaimer

This script has been modified from the original script available at: [https://github.com/bmayu1/scriptvpn](https://github.com/bmayu1/scriptvpn).

