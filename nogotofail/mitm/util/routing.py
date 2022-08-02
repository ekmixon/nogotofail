r'''
Copyright 2014 Google Inc. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
'''
import logging
import subprocess
from nogotofail.mitm.util.ip import get_interface_addresses

logger = logging.getLogger("nogotofail.mitm")

def run_command(command, ignore_failed=False):
    try:
        _ = subprocess.check_output(
                command, stderr=subprocess.STDOUT, shell=True)
    except Exception as e:
        if not ignore_failed:
            raise e

def run_iptables_cmd(command, ipv4=True, ipv6=False, ignore_failed=False):
    if ipv4:
        ipv4_bin = "iptables"
        run_command(f"{ipv4_bin} {command}", ignore_failed)
    if ipv6:
        ipv6_bin = "ip6tables"

        run_command(f"{ipv6_bin} {command}", ignore_failed)

def run_ip_cmd(command, ipv4=True, ipv6=False, ignore_failed=True):
    if ipv4:
        ipv4_bin = "ip -4"
        run_command(f"{ipv4_bin} {command}", ignore_failed)
    if ipv6:
        ipv6_bin = "ip -6"
        run_command(f"{ipv6_bin} {command}", ignore_failed)

def add_local_bypass(table, chain, ipv6):
    """Add rules to skip anything destined for a local address
    to avoid breaking connections to ourselves, otherwise we might break
    SSH and that would be bad if ngtf is running on a remote server.
    """
    run_iptables_cmd(
        f"-t {table} -A {chain} -p tcp -m socket -j RETURN", ipv6=ipv6
    )


    v4_addrs, v6_addrs = get_interface_addresses()
    for addr in v4_addrs:
        run_iptables_cmd(
            f"-t {table} -A {chain} -p tcp -d {addr} -j RETURN", ipv6=False
        )

    for addr in v6_addrs:
        run_iptables_cmd(
            f"-t {table} -A {chain} -p tcp -d {addr} -j RETURN",
            ipv4=False,
            ipv6=ipv6,
        )

TPROXY_CHAIN = "ngtf_mangle_PREROUTING"

def disable_tproxy_rules(ipv6=False, mark=100):
    run_ip_cmd("rule del fwmark %d table %d" % (mark, mark),
            ipv6=ipv6, ignore_failed=True)
    run_iptables_cmd(
        f"-t mangle -D PREROUTING -j {TPROXY_CHAIN}",
        ipv6=ipv6,
        ignore_failed=True,
    )

    run_iptables_cmd(f"-t mangle -F {TPROXY_CHAIN}", ipv6=ipv6, ignore_failed=True)
    run_iptables_cmd(f"-t mangle -X {TPROXY_CHAIN}", ipv6=ipv6, ignore_failed=True)


def enable_tproxy_rules(port, ipv6=False, mark=100):
    disable_tproxy_rules(ipv6, mark)
    try:
        run_ip_cmd("rule add fwmark %d table %d" % (mark, mark), ipv6=ipv6)
        run_ip_cmd("route add local default dev lo table %d" % mark, ipv6=ipv6)
        run_iptables_cmd(f"-t mangle -N {TPROXY_CHAIN}", ipv6=ipv6)

        add_local_bypass("mangle", TPROXY_CHAIN, ipv6)

        run_iptables_cmd(f"-t mangle -A PREROUTING --jump {TPROXY_CHAIN}", ipv6=ipv6)

        run_iptables_cmd(
                "-t mangle -A %s -p tcp -j TPROXY --tproxy-mark %d --on-port %d" %
                (TPROXY_CHAIN, mark, port), ipv6=ipv6)

    except Exception:
        logger.exception("Failed to setup routing rules")
        disable_tproxy_rules(ipv6=ipv6, mark=mark)

REDIRECT_CHAIN = "ngtf_nat_PREROUTING"
def disable_redirect_rules(ipv6=False):
    run_iptables_cmd(
        f"-t nat -D PREROUTING -j {REDIRECT_CHAIN}",
        ipv6=ipv6,
        ignore_failed=True,
    )

    run_iptables_cmd(f"-t nat -F {REDIRECT_CHAIN}", ipv6=ipv6, ignore_failed=True)
    run_iptables_cmd(f"-t nat -X {REDIRECT_CHAIN}", ipv6=ipv6, ignore_failed=True)

def enable_redirect_rules(port, ipv6=False):
    disable_redirect_rules(ipv6=ipv6)
    try:
        run_iptables_cmd(f"-t nat -N {REDIRECT_CHAIN}", ipv6=ipv6)

        add_local_bypass("nat", REDIRECT_CHAIN, ipv6)
        run_iptables_cmd(f"-t nat -A PREROUTING --jump {REDIRECT_CHAIN}", ipv6=ipv6)

        run_iptables_cmd(
            f"-t nat -A {REDIRECT_CHAIN} -p tcp -j REDIRECT --to-ports {port}",
            ipv6=ipv6,
        )

    except Exception:
        logger.exception("Failed to setup routing rules")
        disable_redirect_rules(ipv6=ipv6)
