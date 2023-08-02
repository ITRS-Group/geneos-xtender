# Geneos Xtender

![active console, metrics dataview](/img/metrics_dataview.png)

## Important
*Geneos Xtender* is a pre-release preview of functionality that may _or may not_ be included in a future release of *Geneos* and is provided without official support but on a best-effort basis.

## Introduction
*Geneos Xtender* extends the capabilities of [Geneos](https://www.itrsgroup.com/products/geneos) by utilizing the large ecosystem of [Nagios](https://en.wikipedia.org/wiki/Nagios) compatible plugins.

### xtender
The `xtender` cli tool runs one or more Nagios compatible checks and formats the output to be suitable for consumption by the [Geneos Toolkit Plugin](https://docs.itrsgroup.com/docs/geneos/current/data-collection/toolkit-plugin.html).

### Xtender Templates
Create individual _Xtender Templates_ for each type of device you want to check. Treat them like [Opsview Host Templates](https://docs.itrsgroup.com/docs/opsview/6.8.3/configuration/service-checks-and-host/host-templates/index.html). Make them small and combine them in a single `xtender` call when needed. Host specific details should then be passed to `xtender` using variables. Use [Geneos variables](https://docs.itrsgroup.com/docs/geneos/current/Gateway_Reference_Guide/gateway_user_variables_and_environments.htm#Variables) and map them to the [environment variables on the sampler](https://docs.itrsgroup.com/docs/geneos/current/data-collection/toolkit-plugin.html#Environment_variables). Note that all variables need to be set up using [the String type](https://docs.itrsgroup.com/docs/geneos/current/Gateway_Reference_Guide/geneos_rulesactionsalerts_tr.html#String).

The use of `$VARIABLES$` is encouraged for maximum re-usability. A single _Xtender Template_, like the example below, can be used for any number of entities through a shared sampler.

Each command should be a single line using the `|` character to denote a scalar block string.

Example _Xtender Template_ for a simple [SNMP](https://en.wikipedia.org/wiki/Simple_Network_Management_Protocol) capable device:

``` yaml
- name: lan connectivity
  command: |
    $PLUGIN_DIR$/check_icmp -H $HOSTADDRESS$ -w 100.0,20% -c 500.0,60%
- name: interface status
  command: |
    $PLUGIN_DIR$/check_snmp_interfaces -H $HOSTADDRESS$ -C $SNMP_COMMUNITY$ -v 2c
- name: snmp cpu usage
  command: |
    $PLUGIN_DIR$/check_snmp_loadavg -w 5 -c 8 -H $HOSTADDRESS$ -C $SNMP_COMMUNITY$ -v 2c
- name: snmp current users
  command: |
    $PLUGIN_DIR$/check_snmp_nousers -w 75 -c 90 -H $HOSTADDRESS$ -C $SNMP_COMMUNITY$ -v 2c
- name: snmp fs usage
  command: |
    $PLUGIN_DIR$/check_snmp_fsutil args: -w 85 -c 90 -m -H $HOSTADDRESS$ -C $SNMP_COMMUNITY$ -v 2c
- name: snmp interface status
  command: |
    $PLUGIN_DIR$/check_snmp_ifstatus -i eth0 -H $HOSTADDRESS$ -C $SNMP_COMMUNITY$ -v 2c
- name: snmp memory usage
  command: |
    $PLUGIN_DIR$/check_snmp_memutil -w 75 -c 85 -x 50 -d 75 -H $HOSTADDRESS$ -C $SNMP_COMMUNITY$ -v 2c
- name: snmp system info
  command: |
    $PLUGIN_DIR$/check_snmp_sysinfo -H $HOSTADDRESS$ -C $SNMP_COMMUNITY$ -v 2c
- name: snmp tcp connections
  command: |
    $PLUGIN_DIR$/check_snmp_tcpcurrestab -w 75 -c 90 -H $HOSTADDRESS$ -C $SNMP_COMMUNITY$ -v 2c
- name: snmp uptime
  command: |
    $PLUGIN_DIR$/check_snmp_uptime -H $HOSTADDRESS$ -C $SNMP_COMMUNITY$ -v 2c
```

Point your Toolkit Plugin sampler to the `xtender` binary followed by `--` and the path to one or more Xtender Templates. The checks will be run asynchronously, so the only real limiting factor is the I/O of the individual checks.

Your own Xtender Templates should be put in `/opt/xtender/templates/custom/` where they can then be found by name. `/opt/xtender/templates/` is reserved for standard templates that may be included in future releases.

#### Ranges
There is a basic support for ranges inside the Xtender Templates. They will be expanded at run time for every step in each range. The format is `!!range-name:start_inclusive..end_inclusive!!`; example: `!!A:1..4!!`. This is useful when you want a check to run several times, for example to check different interfaces on the same host, or even different interfaces on different hosts. The example below will check interfaces `1-10` on hosts `192.168.1.1-5`:

``` yaml
- name: 192.168.1.!!A:1..5!! Interface !!B:1..10!! Traffic
  command: |
    /opt/opsview/monitoringscripts/plugins/check_snmpif traffic -v 2c -C $SNMP_COMMUNITY$ -i !!B:1..10!! -H 192.168.1.!!A:1..5!! --warn-in 1m --warn-out 20m --crit-in 2m --crit-out 35m -b 100m
  timeout: 2

```
The `range-name` can only be `A` or `B`. Note that ranges will be populated in order sorted by the name and not the order in which they occur. Only 2 ranges are allowed, but they can be repeated multiple times. The same ranges must be present *both* in the `name` and the `command`. Ranges with any other names will not be processed.

#### Conversion of Opspack configuration JSON to compatible Xtender Template YAML
The option `-o` can be used to convert an [Opsview Opspack](https://www.opsview.com/product/system-monitoring) JSON file and print the output to stdout.

### Xtender Netprobes
An _Xtender Netprobe_ is a [Netprobe](https://docs.itrsgroup.com/docs/geneos/current/Netprobe/introduction/netprobe-overview.html) that has the `xtender` cli tool installed, as well as a collection of templates and plugins. It is used to connect to [managed entities](https://docs.itrsgroup.com/docs/geneos/current/Gateway_Reference_Guide/gateway_managed_entities.htm#Operation) using the provided, third party, or custom plugins. An Xtender Netprobe is typically installed within the environment that it's tasked to monitor to reduce latency and allow connections within closed networks.

### Compatible distributions
_Geneos Xtender_ is currently tested against the following distributions using the provided `deb` and `rpm` files (amd64 only):
- Alma Linux 8
- Alma Linux 9
- Debian 11
- Debian 12
- Oracle Linux 8
- Oracle Linux 9
- Rocky Linux 8
- Rocky Linux 9
- Ubuntu 20.04

The standalone binary is statically compiled using MUSL and should work on any modern x86_64 Linux distribution.

## Installation
Download the RPM or DEB from [the latest release page](https://github.com/ITRS-Group/geneos-xtender/releases/latest/) and install accordingly.

## License

The whole Geneos Xtender project is released under the Apache-2.0 license.

``` text
   Copyright 2023 ITRS Group

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
```

## Legal Disclaimer
Please note that this product is not endorsed by Nagios and was created by the [ITRS Group](https://itrsgroup.com).
