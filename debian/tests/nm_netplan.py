#!/usr/bin/python3

__author__ = "Danilo Egea Gondolfo <danilo.egea.gondolfo@canonical.com>"
__copyright__ = "(C) 2023 Canonical Ltd."
__license__ = "GPL v2 or later"

from glob import glob
import json
import shutil
import socket
import subprocess
import sys
import os
from time import sleep
import unittest
import yaml

import gi
gi.require_version("NM", "1.0")
from gi.repository import NM, GLib, Gio

import network_test_base

nmclient = NM.Client.new()

class TestNetplan(unittest.TestCase):

    def setUp(self):
        self._stop_network_manager()

        self._start_nm()
        sleep(1)
        self.nmclient = NM.Client.new()

    def tearDown(self):
        pass

    def _start_nm(self, auto_connect=True):
        """This method is basically a copy of start_nm() from nm.py
        without the parts we don't need
        """

        if not os.path.exists("/run/NetworkManager"):
            os.mkdir("/run/NetworkManager")
        for d in [
            "/etc/NetworkManager",
            "/var/lib/NetworkManager",
            "/run/NetworkManager",
            "/etc/netplan",
        ]:
            subprocess.check_call(["mount", "-n", "-t", "tmpfs", "none", d])
            self.addCleanup(subprocess.call, ["umount", d])
        os.mkdir("/etc/NetworkManager/system-connections")

        denylist = ""
        for iface in os.listdir("/sys/class/net"):
            if iface in ['bonding_masters']:
                continue
            with open("/sys/class/net/%s/address" % iface) as f:
                if denylist:
                    denylist += ";"
                denylist += "mac:%s" % f.read().strip()

        conf = "/etc/NetworkManager/NetworkManager.conf"
        extra_main = ""
        if not auto_connect:
            extra_main += "no-auto-default=*\n"

        with open(conf, "w") as f:
            f.write(
                "[main]\nplugins=keyfile\n%s\n[keyfile]\nunmanaged-devices=%s\n"
                % (extra_main, denylist)
            )

        log = "/tmp/NetworkManager.log"
        f_log = os.open(log, os.O_CREAT | os.O_WRONLY | os.O_SYNC)

        # build NM command line
        argv = ["NetworkManager", "--log-level=debug", "--debug", "--config=" + conf]
        # allow specifying extra arguments
        argv += os.environ.get("NM_TEST_DAEMON_ARGS", "").strip().split()

        p = subprocess.Popen(argv, stdout=f_log, stderr=subprocess.STDOUT)
        network_test_base.wait_nm_online()
        # automatically terminate process at end of test case
        self.addCleanup(p.wait)
        self.addCleanup(p.terminate)
        self.addCleanup(os.close, f_log)
        self.addCleanup(self._clear_connections)

        self._process_glib_events()

    def _process_glib_events(self):
        """Process pending GLib main loop events"""

        context = GLib.MainContext.default()
        while context.iteration(False):
            pass

    def _restart_network_manager(self):
        cmd = ['systemctl', 'restart', 'NetworkManager']
        subprocess.call(cmd, stdout=subprocess.DEVNULL)

    def _stop_network_manager(self):
        cmd = ['systemctl', 'stop', 'NetworkManager']
        subprocess.call(cmd, stdout=subprocess.DEVNULL)

    def _add_connection(self, connection):
        self.main_loop = GLib.MainLoop()
        self.cancel = Gio.Cancellable()
        self.timeout_tag = 0

        def add_cb(client, result, data):
            self.nmclient.add_connection_finish(result)
            self.main_loop.quit()

        def timeout_cb():
            self.timeout_tag = -1
            self.cancel.cancel()
            self.main_loop.quit()
            return GLib.SOURCE_REMOVE

        self.timeout_tag = GLib.timeout_add_seconds(120, timeout_cb)

        self.nmclient.add_connection_async(connection, True, self.cancel, add_cb, None)
        self.main_loop.run()

        if self.timeout_tag < 0:
            self.timeout_tag = 0
            self.fail('nm_netplan.py: main loop timed out during connection creation')


    def _delete_connection(self, connection):
        uuid = connection.get_uuid()
        cmd = ['nmcli', 'con', 'del', uuid]
        subprocess.call(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def _delete_interface(self, connection):
        iface = connection.get_interface_name()
        if iface:
            cmd = ['ip', 'link', 'del', iface]
            subprocess.call(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def _nmcli(self, parameters):
        cmd = ['nmcli'] + parameters
        return subprocess.call(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def _bridge_show(self, bridge):
        cmd = ['bridge', '-j', 'link', 'show', bridge]
        ret = subprocess.run(cmd, capture_output=True)
        return json.loads(ret.stdout)

    def _load_netplan_yaml_for_connection(self, connection):
        filename = '/etc/netplan/90-NM-' + connection.get_uuid() + '.yaml'

        file = open(filename)
        data = yaml.safe_load(file)
        file.close()
        return data

    def _get_number_of_yaml_files(self):
        return len(self._get_list_of_yaml_files())

    def _get_list_of_yaml_files(self):
        return glob("/etc/netplan/90-NM-*")

    def _commit_and_save_connection(self, connection):
        main_loop = GLib.MainLoop()

        def commit_cb(client, result, data):
            connection.commit_changes_finish(result)
            main_loop.quit()

        connection.commit_changes_async(True, None, commit_cb, None)
        main_loop.run()

    def _clear_connections(self):
        for conn in self.nmclient.get_connections():
            self._delete_connection(conn)
            self._delete_interface(conn)

    def _netplan_generate(self):
        cmd = ['netplan', 'generate']
        ret = subprocess.run(cmd, capture_output=True)

    def _nmcli_con_reload(self):
        self._nmcli(['con', 'reload'])

    # Tests

    def test_create_a_simple_bridge_with_dhcp(self):

        conn = NM.SimpleConnection.new()
        settings = NM.SettingConnection.new()
        settings.set_property(NM.SETTING_CONNECTION_ID, "bridge0")
        settings.set_property(NM.SETTING_CONNECTION_INTERFACE_NAME, "bridge0")
        settings.set_property(NM.SETTING_CONNECTION_TYPE, "bridge")

        bridge = NM.SettingBridge.new()
        ipv4 = NM.SettingIP4Config.new()
        ipv4.set_property(NM.SETTING_IP_CONFIG_METHOD, "auto")
        ipv6 = NM.SettingIP6Config.new()
        ipv6.set_property(NM.SETTING_IP_CONFIG_METHOD, "auto")

        conn.add_setting(settings)
        conn.add_setting(ipv4)
        conn.add_setting(ipv6)
        conn.add_setting(bridge)

        # There should be zero netplan NM yaml before adding a connection
        self.assertEqual(self._get_number_of_yaml_files(), 0)

        self._add_connection(conn)

        # There should be one netplan NM yaml after adding a connection
        self.assertEqual(self._get_number_of_yaml_files(), 1)

        connection = self.nmclient.get_connection_by_id("bridge0")
        yaml_data = self._load_netplan_yaml_for_connection(connection)

        # Validating some of the expected flags
        self.assertTrue(yaml_data['network']['bridges']['bridge0']['dhcp4'])
        self.assertTrue(yaml_data['network']['bridges']['bridge0']['dhcp6'])

        self._delete_connection(connection)

        # There should be zero netplan NM yaml after deleting a connection
        self.assertEqual(self._get_number_of_yaml_files(), 0)

    def test_create_a_simple_bridge_with_ip_addresses(self):
        conn = NM.SimpleConnection.new()
        settings = NM.SettingConnection.new()
        settings.set_property(NM.SETTING_CONNECTION_ID, "bridge0")
        settings.set_property(NM.SETTING_CONNECTION_INTERFACE_NAME, "bridge0")
        settings.set_property(NM.SETTING_CONNECTION_TYPE, "bridge")

        bridge = NM.SettingBridge.new()

        ipv4 = NM.SettingIP4Config.new()
        ipv4.set_property(NM.SETTING_IP_CONFIG_METHOD, "manual")
        ip4_addr1 = NM.IPAddress.new(socket.AF_INET, "10.20.30.40", 24)
        ip4_addr2 = NM.IPAddress.new(socket.AF_INET, "10.20.30.41", 24)
        ipv4.add_address(ip4_addr1)
        ipv4.add_address(ip4_addr2)

        ipv6 = NM.SettingIP6Config.new()
        ipv6.set_property(NM.SETTING_IP_CONFIG_METHOD, "manual")
        ip6_addr1 = NM.IPAddress.new(socket.AF_INET6, "dead:beef::1", 64)
        ip6_addr2 = NM.IPAddress.new(socket.AF_INET6, "dead:beef::2", 64)
        ipv6.add_address(ip6_addr1)
        ipv6.add_address(ip6_addr2)

        conn.add_setting(settings)
        conn.add_setting(ipv4)
        conn.add_setting(ipv6)
        conn.add_setting(bridge)

        # There should be zero netplan NM yaml before adding a connection
        self.assertEqual(self._get_number_of_yaml_files(), 0)

        self._add_connection(conn)

        # There should be one netplan NM yaml after adding a connection
        self.assertEqual(self._get_number_of_yaml_files(), 1)

        connection = self.nmclient.get_connection_by_id("bridge0")
        yaml_data = self._load_netplan_yaml_for_connection(connection)

        # Validating some of the expected flags
        self.assertNotIn('dhcp4', yaml_data['network']['bridges']['bridge0'])
        self.assertNotIn('dhcp6', yaml_data['network']['bridges']['bridge0'])

        addresses = yaml_data['network']['bridges']['bridge0']['addresses']
        expected_addresses = ['10.20.30.40/24', '10.20.30.41/24', 'dead:beef::1/64', 'dead:beef::2/64']

        self.assertListEqual(addresses, expected_addresses)

        self._delete_connection(connection)

        # There should be zero netplan NM yaml after deleting a connection
        self.assertEqual(self._get_number_of_yaml_files(), 0)

    def test_create_a_simple_bridge_with_ip_and_member(self):

        conn = NM.SimpleConnection.new()
        settings = NM.SettingConnection.new()
        settings.set_property(NM.SETTING_CONNECTION_ID, "bridge0")
        settings.set_property(NM.SETTING_CONNECTION_INTERFACE_NAME, "bridge0")
        settings.set_property(NM.SETTING_CONNECTION_TYPE, "bridge")

        bridge = NM.SettingBridge.new()

        ipv4 = NM.SettingIP4Config.new()
        ipv4.set_property(NM.SETTING_IP_CONFIG_METHOD, "manual")
        ip4_addr1 = NM.IPAddress.new(socket.AF_INET, "10.20.30.40", 24)
        ip4_addr2 = NM.IPAddress.new(socket.AF_INET, "10.20.30.41", 24)
        ipv4.add_address(ip4_addr1)
        ipv4.add_address(ip4_addr2)

        ipv6 = NM.SettingIP6Config.new()
        ipv6.set_property(NM.SETTING_IP_CONFIG_METHOD, "manual")
        ip6_addr1 = NM.IPAddress.new(socket.AF_INET6, "dead:beef::1", 64)
        ip6_addr2 = NM.IPAddress.new(socket.AF_INET6, "dead:beef::2", 64)
        ipv6.add_address(ip6_addr1)
        ipv6.add_address(ip6_addr2)

        conn.add_setting(settings)
        conn.add_setting(ipv4)
        conn.add_setting(ipv6)
        conn.add_setting(bridge)

        # There should be zero netplan NM yaml before adding a connection
        self.assertEqual(self._get_number_of_yaml_files(), 0)

        # Adding the bridge
        self._add_connection(conn)

        # There should be one netplan NM yaml after adding a connection
        self.assertEqual(self._get_number_of_yaml_files(), 1)

        # Creating a tap0 device to be a bridge member
        tap0 = NM.SimpleConnection.new()
        tap0_conn_settings = NM.SettingConnection.new()
        tap0_conn_settings.set_property(NM.SETTING_CONNECTION_ID, "tap0")
        tap0_conn_settings.set_property(NM.SETTING_CONNECTION_INTERFACE_NAME, "tap0")
        tap0_conn_settings.set_property(NM.SETTING_CONNECTION_TYPE, "tun")
        tap0_conn_settings.set_property(NM.SETTING_CONNECTION_SLAVE_TYPE, "bridge")
        tap0_conn_settings.set_property(NM.SETTING_CONNECTION_MASTER, "bridge0")

        tap0_settings = NM.SettingTun.new()
        tap0_settings.set_property(NM.SETTING_TUN_MODE, NM.SettingTunMode.TAP)

        tap0.add_setting(tap0_conn_settings)
        tap0.add_setting(tap0_settings)
        self._add_connection(tap0)

        # There should be two netplan NM yaml after adding the tap
        self.assertEqual(self._get_number_of_yaml_files(), 2)

        bridge0_connection = self.nmclient.get_connection_by_id("bridge0")
        yaml_data = self._load_netplan_yaml_for_connection(bridge0_connection)

        # Validating some of the bridge expected flags
        addresses = yaml_data['network']['bridges']['bridge0']['addresses']
        expected_addresses = ['10.20.30.40/24', '10.20.30.41/24', 'dead:beef::1/64', 'dead:beef::2/64']

        self.assertListEqual(addresses, expected_addresses)

        # Validating if tap0 is attached to the bridge
        # It might take a while for the new interface be created...
        limit = 10
        while (show_bridge := self._bridge_show('bridge0')) == [] and limit > 0:
            sleep(1)
            limit = limit - 1
        self.assertEqual(show_bridge[0]['master'], 'bridge0')
        self.assertEqual(show_bridge[0]['ifname'], 'tap0')

        tap0_connection = self.nmclient.get_connection_by_id("tap0")
        tap_yaml = self._load_netplan_yaml_for_connection(tap0_connection)

        tap0_uuid = tap0_connection.get_uuid()
        # Validating that the bridge information is in the tap yaml
        self.assertEqual(tap_yaml['network']['nm-devices']['NM-' + tap0_uuid]['networkmanager']['passthrough']['connection.master'], 'bridge0')

        self._delete_connection(tap0_connection)
        # There should be one netplan NM yaml after deleting the tap
        self.assertEqual(self._get_number_of_yaml_files(), 1)

        self._delete_connection(bridge0_connection)
        # There should be zero netplan NM yaml after deleting the bridge
        self.assertEqual(self._get_number_of_yaml_files(), 0)

    def test_create_an_interface_and_change_it(self):
        """Add a tap interface and change it after create adding IP addresses to it."""

        # Creating a tap0 device to be a bridge member
        tap0 = NM.SimpleConnection.new()
        tap0_conn_settings = NM.SettingConnection.new()
        tap0_conn_settings.set_property(NM.SETTING_CONNECTION_ID, "tap0")
        tap0_conn_settings.set_property(NM.SETTING_CONNECTION_INTERFACE_NAME, "tap0")
        tap0_conn_settings.set_property(NM.SETTING_CONNECTION_TYPE, "tun")

        tap0_settings = NM.SettingTun.new()
        tap0_settings.set_property(NM.SETTING_TUN_MODE, NM.SettingTunMode.TAP)

        tap0.add_setting(tap0_conn_settings)
        tap0.add_setting(tap0_settings)
        self._add_connection(tap0)

        # There should be one netplan NM yaml after adding a connection
        self.assertEqual(self._get_number_of_yaml_files(), 1)

        tap0_connection = self.nmclient.get_connection_by_id("tap0")

        ipv4_settings = tap0_connection.get_setting_ip4_config()
        ipv4_settings.set_property(NM.SETTING_IP_CONFIG_METHOD, "manual")
        ip4_addr1 = NM.IPAddress.new(socket.AF_INET, "10.20.30.40", 24)
        ip4_addr2 = NM.IPAddress.new(socket.AF_INET, "10.20.30.41", 24)
        ipv4_settings.add_address(ip4_addr1)
        ipv4_settings.add_address(ip4_addr2)

        ipv6_settings = tap0_connection.get_setting_ip6_config()
        ipv6_settings.set_property(NM.SETTING_IP_CONFIG_METHOD, "manual")
        ip6_addr1 = NM.IPAddress.new(socket.AF_INET6, "dead:beef::1", 64)
        ip6_addr2 = NM.IPAddress.new(socket.AF_INET6, "dead:beef::2", 64)
        ipv6_settings.add_address(ip6_addr1)
        ipv6_settings.add_address(ip6_addr2)

        self._commit_and_save_connection(tap0_connection)

        # There should be one netplan NM yaml files after chaging the only existing connection
        self.assertEqual(self._get_number_of_yaml_files(), 1)

        self._delete_connection(tap0_connection)

        # There should be zero netplan NM yaml files after removing the only existing connection
        self.assertEqual(self._get_number_of_yaml_files(), 0)

    def test_nmcli_add_device_and_change_it(self):
        """Uses the nmcli to add a connection and validates if the
        Netplan YAML file has the expected configuration.
        It also changes the configuration changing the ipv4 method from auto
        to manual and adding an IP address. After the change the Netplan YAML
        file should have the same name.
        """

        self.assertEqual(self._get_number_of_yaml_files(), 0)

        nmcli_add = ['con', 'add', 'type', 'tun', 'mode', 'tap', 'ifname', 'tap0', 'ipv4.method', 'auto']
        self._nmcli(nmcli_add)

        self.assertEqual(self._get_number_of_yaml_files(), 1)

        files_before = self._get_list_of_yaml_files()

        # After OOB changes, the client must be refreshed apparently
        self.nmclient = NM.Client.new()

        conn = self.nmclient.get_connection_by_id("tun-tap0")
        uuid = conn.get_uuid()
        data = self._load_netplan_yaml_for_connection(conn)

        ip4_method = data.get('network') \
                         .get('nm-devices') \
                         .get('NM-' + uuid) \
                         .get('networkmanager') \
                         .get('passthrough') \
                         .get('ipv4.method')

        self.assertEqual(ip4_method, 'auto')

        nmcli_mod = ['con', 'mod', 'tun-tap0', 'ipv4.method', 'manual', 'ipv4.addresses', '10.20.30.40/24']
        self._nmcli(nmcli_mod)

        self.assertEqual(self._get_number_of_yaml_files(), 1)

        files_after = self._get_list_of_yaml_files()

        self.assertListEqual(files_before, files_after)

        data = self._load_netplan_yaml_for_connection(conn)

        ip4_method = data.get('network') \
                         .get('nm-devices') \
                         .get('NM-' + uuid) \
                         .get('networkmanager') \
                         .get('passthrough') \
                         .get('ipv4.method')

        ip4_addr = data.get('network') \
                         .get('nm-devices') \
                         .get('NM-' + uuid) \
                         .get('networkmanager') \
                         .get('passthrough') \
                         .get('ipv4.address1')

        self.assertEqual(ip4_method, 'manual')
        self.assertEqual(ip4_addr, '10.20.30.40/24')

        self._delete_connection(conn)
        self.assertEqual(self._get_number_of_yaml_files(), 0)

    def test_nmcli_add_wifi_connection(self):
        """Create a wifi connection via nmcli and check if the expected
        fields were added to the netplan yaml file."""

        ssid = 'My network SSID'
        passwd = 'secretpasswd'
        method = 'wpa-psk'
        ip = '10.20.30.40/24'
        nmcli_add = ['con', 'add', 'type', 'wifi', 'ssid', ssid,
                     'wifi-sec.key-mgmt', method, 'wifi-sec.psk', passwd,
                     'ipv4.method', 'manual', 'ipv4.addresses', ip]

        self.assertEqual(self._get_number_of_yaml_files(), 0)

        self._nmcli(nmcli_add)

        self.assertEqual(self._get_number_of_yaml_files(), 1)

        # After OOB changes, the client must be refreshed apparently
        self.nmclient = NM.Client.new()

        conn = self.nmclient.get_connection_by_id("wifi")
        uuid = conn.get_uuid()
        data = self._load_netplan_yaml_for_connection(conn)

        ap_name = list(data.get('network') \
                .get('wifis') \
                .get('NM-' + uuid) \
                .get('access-points') \
                .keys())[0]

        ip_addr = data.get('network') \
                .get('wifis') \
                .get('NM-' + uuid) \
                .get('addresses')

        auth_method = data.get('network') \
                .get('wifis') \
                .get('NM-' + uuid) \
                .get('access-points') \
                .get(ap_name) \
                .get('auth') \
                .get('key-management')

        auth_passwd = data.get('network') \
                .get('wifis') \
                .get('NM-' + uuid) \
                .get('access-points') \
                .get(ap_name) \
                .get('auth') \
                .get('password')

        self.assertEqual(ap_name, ssid)
        self.assertListEqual(ip_addr, [ip])
        self.assertEqual(auth_method, 'psk')
        self.assertEqual(auth_passwd, passwd)

        self._delete_connection(conn)
        self.assertEqual(self._get_number_of_yaml_files(), 0)

    def test_create_connection_via_netplan(self):
        """
        Create a connection via netplan generate and check if NM will pick it up
        """

        netplan_yaml = '''network:
  renderer: NetworkManager
  ethernets:
    eth123:
      dhcp4: true'''

        with open('/etc/netplan/10-test.yaml', 'w') as f:
            f.write(netplan_yaml)

        self._netplan_generate()
        self._nmcli_con_reload()
        self.nmclient = NM.Client.new()

        expected = None
        for conn in self.nmclient.get_connections():
            if conn.get_id() == 'netplan-eth123':
                expected = conn

        self.assertIsNotNone(expected)

    def test_create_connection_via_netplan_and_remove_via_nmcli(self):
        """
        Create a connection via netplan generate and remove it with nmcli.

        The interface should be removed from the yaml file.
        """

        netplan_yaml = '''network:
  renderer: NetworkManager
  ethernets:
    eth123:
      dhcp4: true
    eth456:
      dhcp4: true'''

        with open('/etc/netplan/10-test.yaml', 'w') as f:
            f.write(netplan_yaml)

        self._netplan_generate()
        self._nmcli_con_reload()
        self.nmclient = NM.Client.new()

        expected1 = None
        expected2 = None
        for conn in self.nmclient.get_connections():
            if conn.get_id() == 'netplan-eth123':
                expected1 = conn
            if conn.get_id() == 'netplan-eth456':
                expected2 = conn

        self.assertIsNotNone(expected1)
        self.assertIsNotNone(expected1)

        self._delete_connection(expected1)

        with open('/etc/netplan/10-test.yaml', 'r') as f:
            yaml_data = yaml.safe_load(f)

            # eth123 shouldn't exist anymore
            self.assertIsNone(yaml_data.get('network').get('ethernets').get('eth123'))

            self.assertIsNotNone(yaml_data.get('network').get('ethernets').get('eth456'))

    def test_create_connection_via_netplan_and_change_it_via_nmcli(self):
        """
        Create a connection via netplan generate and change it via nmcli.
        """

        netplan_yaml = '''network:
  renderer: NetworkManager
  ethernets:
    eth123:
      dhcp4: false
      dhcp6: false
    eth456:
      dhcp4: true'''

        with open('/etc/netplan/10-test.yaml', 'w') as f:
            f.write(netplan_yaml)

        self._netplan_generate()
        self._nmcli_con_reload()
        self._nmcli(['con', 'mod', 'netplan-eth123', 'ipv4.method', 'auto'])

        # eth123.dhcp4 should be overriden by 90-NM-<UUID>.yaml (from 10-test.yaml)
        # The output of 'netplan get' should account for that.
        out = subprocess.check_output(['netplan', 'get'], universal_newlines=True)
        yaml_data = yaml.safe_load(out)
        dhcp = yaml_data.get('network').get('ethernets').get('eth123').get('dhcp4')
        self.assertTrue(dhcp)

    def test_openvpn_connection(self):
        """ Test case for LP#1998207"""

        server_config = """dev tun
ca /tmp/openvpn/pki/ca.crt
cert /tmp/openvpn/pki/issued/server.crt
key /tmp/openvpn/pki/private/server.key
dh /tmp/openvpn/pki/dh.pem
server 192.168.5.0 255.255.255.0
keepalive 10 120
cipher AES-256-GCM
compress lz4-v2
push "compress lz4-v2"
user root
log /tmp/openvpn.log
group root
"""

        client_config = """client
dev tun
remote 127.0.0.1 1194
nobind
ca /tmp/openvpn/pki/ca.crt
cert /tmp/openvpn/pki/issued/client.crt
key /tmp/openvpn/pki/private/client.key
cipher AES-256-GCM
"""

        # The minimum DH size accepted by OpenVPN these days is 2048.
        # It might take a while to be generated (like almost a minute)
        # It would be faster to use shared keys instead of TLS but it
        # seems it's not an option anymore in OpenVPN
        openvpn_spinup_script = """/usr/share/easy-rsa/easyrsa init-pki
EASYRSA_BATCH=1 /usr/share/easy-rsa/easyrsa build-ca nopass
EASYRSA_BATCH=1 /usr/share/easy-rsa/easyrsa build-server-full server nopass
EASYRSA_BATCH=1 /usr/share/easy-rsa/easyrsa build-client-full client nopass
/usr/share/easy-rsa/easyrsa gen-dh
"""

        tmpdir = '/tmp/openvpn'
        self.addCleanup(shutil.rmtree, tmpdir)
        os.mkdir(tmpdir)
        os.chdir(tmpdir)

        with open('openvpn_spinup.sh', 'w') as f:
            f.write(openvpn_spinup_script)

        with open('server.conf', 'w') as f:
            f.write(server_config)

        with open('client.conf', 'w') as f:
            f.write(client_config)

        cmd = ['bash', 'openvpn_spinup.sh']
        subprocess.call(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        openvpn_server_cmd = ['openvpn', '--config', 'server.conf']
        p_server = subprocess.Popen(openvpn_server_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        sleep(1) # Let's give OpenVPN a second to start

        # Add a useless default route to the loopback interface so NM will allow starting the VPN connection.
        # Apparently, if it doesn't own an *active connection* with a default route, it will not allow
        # us to start the VPN client.
        # As we set the main ethernet device as unmanaged, NM will not 'own' a default route when it starts.
        # Unfortunately, by doing this, NM will take over the interface 'lo' and add a new yaml file to /etc/netplan
        # We use metric 1000 so this default route will not be the preferred one.
        self._nmcli(['con', 'mod', 'lo', 'ipv4.gateway', '192.168.5.254', 'ipv4.route-metric', '1000'])

        # Create an OpenVPN connection based on the configuration found in client.conf
        self._nmcli(['con', 'import', 'type', 'openvpn', 'file', 'client.conf'])

        # At this point we should have 2 yaml files
        # One for the tun0 NM took over and one for the VPN connection
        self.assertEqual(self._get_number_of_yaml_files(), 2,
                         msg='More than expected YAML files were found after creating the connection')

        self._nmcli(['con', 'up', 'client'])
        sleep(2) # Let's give NM a couple of seconds to settle down
        # We still should have 2 files after starting the client
        self.assertEqual(self._get_number_of_yaml_files(), 2,
                         msg='More than expected YAML files were found after starting the connection')

        self._nmcli(['con', 'down', 'client'])
        sleep(2) # Let's give NM a couple of seconds to settle down
        # We still should have 2 files after stopping the client
        self.assertEqual(self._get_number_of_yaml_files(), 2,
                         msg='More than expected YAML files were found after stopping the connection')

        p_server.terminate()
        p_server.wait()
        # We still should have 2 files after stopping the server
        self.assertEqual(self._get_number_of_yaml_files(), 2,
                         msg='More than expected YAML files were found after stopping the OpenVPN server')

    def test_migrate_existing_tunnel_with_nmcli(self):
        """
        Change an existing tunnel defined in Netplan with nmcli so it will be "imported"
        to NM. See LP: #2016473.
        """

        netplan_yaml = '''network:
  renderer: NetworkManager
  tunnels:
    wg0:
      mode: wireguard
      port: 51821
      key: YCNQCAes1OTbD2ynY+aBlaA5x4ZFJhsc4co+XHpZ4FU=
      addresses:
        - 172.17.0.1/24
      peers:
        - allowed-ips: [172.17.0.0/24]
          endpoint: 4.4.4.4:51821
          keys:
            public: cwkb7k0xDgLSnunZpFIjLJw4u+mJDDr+aBR5DqzpmgI='''

        with open('/etc/netplan/10-test.yaml', 'w') as f:
            f.write(netplan_yaml)

        self._netplan_generate()
        self._nmcli_con_reload()
        self._nmcli(['con', 'mod', 'netplan-wg0', 'con-name', 'netplan-wireguard-wg0'])

        # After being processed by NM (and libnetplan) the new file shouldn't
        # redefine the interface type. If it does, "netplan get" will fail
        # when it tries to load the YAML hierarchy.
        out = subprocess.run(['netplan', 'get'],
                             capture_output=True, text=True)

        self.assertEqual(out.returncode, 0, f'"netplan get" failed due to issues in the resulting YAML files.')

    def test_create_wireguard_tunnel_in_multiple_steps_nmcli(self):
        """
        Network Manager should be able to create partial Wireguard connections

        See:  LP: #2016473
        """

        ret = self._nmcli(['con', 'add', 'type', 'wireguard', 'con-name', 'client-wg0', 'ifname', 'wg0', 'autoconnect', 'no'])
        self.assertEqual(ret, 0, 'nmcli con add failed.')
        ret = self._nmcli(['con', 'modify', 'client-wg0', 'ipv4.method', 'manual', 'ipv4.addresses', '10.1.2.3/24'])
        self.assertEqual(ret, 0, 'nmcli ipv4 modify failed.')
        ret = self._nmcli(['con', 'modify', 'client-wg0', 'wireguard.private-key', 'aPUcp5vHz8yMLrzk8SsDyYnV33IhE/k20e52iKJFV0A='])
        self.assertEqual(ret, 0, 'nmcli add private key failed.')

        # Use examples/python/gi/nm-wg-set to add one peer,
        # nmcli doesn't support adding peers yet.
        wg_peer_cmd = ['python3', 'examples/python/gi/nm-wg-set', 'client-wg0',
                       'peer', 'cwkb7k0xDgLSnunZpFIjLJw4u+mJDDr+aBR5DqzpmgI=',
                       'endpoint', '1.2.3.4:12345', 'allowed-ips', '192.168.0.0/24']
        out = subprocess.run(wg_peer_cmd, capture_output=True, text=True)
        self.assertEqual(out.returncode, 0, 'nm-wg-set failed to add the peer')

    def test_import_wireguard_profile_from_file(self):
        """
        Network Manager should be able to import a Wireguard connection
        from a configuration file.

        See:  LP: #2016473
        """
        wg_profile = '''[Interface]
PrivateKey = wFemfDk+MQbdHQnpADll/4fN/TaI7OPEMgbALP4BtF0=
Address = 10.8.1.2/24
DNS = 10.8.1.1
[Peer]
PublicKey = e3Yvr6qmGHGfOcF1wgsIWILT57FzpIgKjjP+AfcMwGI=
AllowedIPs = 192.168.0.0/24
Endpoint = 1.2.3.4:12345
PersistentKeepalive = 15'''

        wg_profile_path = '/etc/netplan/wg-client.conf'

        with open(wg_profile_path, 'w') as f:
            f.write(wg_profile)

        ret = self._nmcli(['con', 'import', 'type', 'wireguard', 'file', wg_profile_path])
        self.assertEqual(ret, 0, f'nmcli failed to import the Wireguard profile from {wg_profile_path}')

    def test_create_wifi_connection_with_8021x(self):
        """
        See LP: #2016625.
        """

        openssl_cmd = [
                'openssl', 'req', '-new', '-newkey', 'rsa:2048',
                '-nodes', '-x509', '-subj',
                '/C=US/ST=A/L=B/O=C/CN=www.a.com', '-keyout',
                '/etc/netplan/a.key',  '-out', '/etc/netplan/a.crt']

        subprocess.check_output(openssl_cmd, universal_newlines=True,
                                stderr=subprocess.DEVNULL)

        ret = self._nmcli(['con', 'add', 'con-name', 'eduroam',
                           'type', 'wifi', 'ssid', 'eduroam',
                           'wifi-sec.key-mgmt', 'wpa-eap', '802-1x.eap',
                           'peap', '802-1x.identity', 'user@example.org',
                           '802-1x.password', 'testing123',
                           '802-1x.phase2-auth', 'mschapv2',
                           '802-1x.ca-cert', '/etc/netplan/a.crt'])

        self.assertEqual(ret, 0, 'nmcli failed to add connection')

    def test_create_gre_connection(self):
        """
        Test case for LP: #1952967.
        """

        ret = self._nmcli(['con', 'add', 'con-name', '"IP tunnel connection 1"',
                           'type', 'ip-tunnel', 'ip-tunnel.mode', 'gre',
                           'ifname', 'gre10', 'remote',
                           '10.20.20.2', 'local', '10.20.20.1'])

        self.assertEqual(ret, 0, 'nmcli failed to add connection')

if __name__ == '__main__':
    runner = unittest.TextTestRunner(stream=sys.stdout, verbosity=2)
    unittest.main(testRunner=runner)
