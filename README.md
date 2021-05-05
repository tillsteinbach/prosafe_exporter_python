# prosafe_exporter_python
[![GitHub sourcecode](https://img.shields.io/badge/Source-GitHub-green)](https://github.com/tillsteinbach/prosafe_exporter_python/)
[![GitHub release (latest by date)](https://img.shields.io/github/v/release/tillsteinbach/prosafe_exporter_python)](https://github.com/tillsteinbach/prosafe_exporter_python/releases/latest)
[![GitHub Workflow Status](https://img.shields.io/github/workflow/status/tillsteinbach/prosafe_exporter_python/Build%20Python%20Package%20and%20Docker%20Image?label=Build%20Python%20Package%20and%20Docker%20Image)](https://github.com/tillsteinbach/prosafe_exporter_python/actions/workflows/build-and-deploy.yml)
[![GitHub](https://img.shields.io/github/license/tillsteinbach/prosafe_exporter_python)](https://github.com/tillsteinbach/prosafe_exporter_python/blob/master/LICENSE)
[![GitHub issues](https://img.shields.io/github/issues/tillsteinbach/prosafe_exporter_python)](https://github.com/tillsteinbach/prosafe_exporter_python/issues)
![Docker Image Size (latest semver)](https://img.shields.io/docker/image-size/tillsteinbach/prosafe_exporter_python?sort=semver)
[![Docker Pulls](https://img.shields.io/docker/pulls/tillsteinbach/prosafe_exporter_python)](https://hub.docker.com/r/tillsteinbach/prosafe_exporter_python)
[![PyPI - Python Version](https://img.shields.io/pypi/pyversions/prosafe-exporter)](https://pypi.org/project/prosafe-exporter/)
[![Donate at PayPal](https://img.shields.io/badge/Donate-PayPal-2997d8)](https://www.paypal.com/donate?hosted_button_id=2BVFF5GJ9SXAJ)

[Prometheus](https://prometheus.io) metrics exporter for NETGEAR switches of the Smart Managed Plus series.

## Exported Metrics

| metric                       | description                                    | labels                                   |
| ---------------------------- | ---------------------------------------------- | ---------------------------------------- |
| prosafe_switch_info          | Information about the switch exposed as labels | hostname, product_name, switch_name, serial_number, mac_adresse, bootloader_version, firmware_version, dhcp_mode, ip_adresse, subnetmask, gateway_adresse |
| prosafe_receive_bytes_total  | Incoming transfer in bytes                     | hostname, port                           |
| prosafe_transmit_bytes_total | Outgoing transfer in bytes                     | hostname, port                           |
| prosafe_error_packets_total  | Transfer error in packets                      | hostname, port                           |
| prosafe_link_speed           | Link speed in Mbps                             | hostname, port                           |
| prosafe_max_mtu*             | Maximum MTU                                    | hostname, port                           |

\* not available in all firmware versions

## Install
Setup a config.yml
```yml
global: 
  retrieve_interval: 20.0
  retries: 10
  host: "0.0.0.0"
  port: 9493
switches: 
  - hostname: "192.168.0.100"
    password: "password123"
  - hostname: "192.168.0.200"
    password: "password123"
```
Mount the config to folder /etc/prosafe_exporter/, e.g. when using docker-compose:
```yml
version: '3.3'

services:
  prosafe_exporter:
    build: .
    ports:
      - 9493:9493
    volumes:
            - "./config/prosafe_exporter/:/etc/prosafe_exporter/:ro"
```
In prometheus configure a scrape job, e.g. like this:
```yml
scrape_configs:
 - job_name: 'prosafe_switches'
    static_configs:
      - targets:
        - "prosafe_exporter:9493"
    metrics_path: /probe
    scrape_interval: 60s
```
## Query Example
Outgoing data rate of `port1` on `192.168.0.123` is below.
```
rate(prosafe_transmit_bytes_total{instance="192.168.0.123", port="1"}[1m])
```

## Tested Switches
- GS108Ev3
- GS108PEv3

## Tested Firmware
- V2.06.14GR
- V2.06.14EN
-	V2.06.03EN

## Known Issues
- May not work with older firmware, not all firmware versions are tested
- Does not work with Japanese firmware

## Credits
Inspired by [dalance/prosafe_exporter](https://github.com/dalance/prosafe_exporter/) that is providing the same functionality using the ProSAFE Plus utility instead of the switches webinterface
