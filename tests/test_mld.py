"""Test cases for mld module.
See https://github.com/pedrofran12/hpim_dm/blob/master/docs/PythonTests.pdf"""

from ctypes import create_string_buffer, addressof
from datetime import datetime
from ipaddress import IPv6Address
import socket
import struct
from time import sleep
import unittest

import nemu
from nsenter import Namespace
from psutil import Process

from mld.InterfaceMLD import InterfaceMLD, ETH_P_IPV6, SO_ATTACH_FILTER
from mld.packet.PacketMLDHeader import PacketMLDHeader
from mld.mld1 import mld_globals

IFA_F_TENTATIVE = 0x40
MLD_BPF_FILTER = create_string_buffer(b''.join(InterfaceMLD.FILTER_MLD))
MLD_BPF_PROG = struct.pack('HL', len(InterfaceMLD.FILTER_MLD), addressof(MLD_BPF_FILTER))
mld_globals.QUERY_INTERVAL = 0.1
mld_globals.OTHER_QUERIER_PRESENT_INTERVAL = 0.2


class NsInterface(InterfaceMLD):
    """Execute receive thread in the appropriate namespace."""
    def __init__(self, interface_name: str, ns_pid: int, vif_index: int = 0):
        super().__init__(interface_name=interface_name, vif_index=vif_index)
        self.ns_pid = ns_pid

    def receive(self):
        with Namespace(self.ns_pid, 'net'):
            super().receive()

class MLDTestCase(unittest.TestCase):
    """Test class for the entier module"""
    @classmethod
    def setUpClass(cls):
        cls.node_list = []
        cls.router_list = []
        for _ in range(2):
            cls.node_list.append(nemu.Node())
            cls.router_list.append({'nemu_if': nemu.NodeInterface(cls.node_list[-1])})
            cls.router_list[-1]['nemu_if'].up = True

        cls.host_list = []
        for _ in range(2):
            cls.node_list.append(nemu.Node())
            cls.host_list.append({'nemu_if': nemu.NodeInterface(cls.node_list[-1])})
            cls.host_list[-1]['nemu_if'].up = True

        switch = nemu.Switch()
        for node_dict in cls.router_list + cls.host_list:
            switch.connect(node_dict['nemu_if'])
        switch.up = True
        cls.node_list.append(switch)

        cls.switch_name = socket.if_indextoname(switch.index)
        # disable multicast snooping
        with open(f'/sys/devices/virtual/net/{cls.switch_name}/bridge/multicast_snooping',
                  'w', encoding='utf-8') as f:
            f.write('0')

        mrouter_path = '/sys/devices/virtual/net/' + cls.switch_name + '/brif/%s/multicast_router'
        if_base_name = 'NETNSif-' + cls.switch_name[8:-1]
        for index in range(len(cls.router_list)):
            # define r1 and r2 as routers
            with open(mrouter_path % (if_base_name + str(2 * index)), 'w', encoding='utf-8') as f:
                f.write('2')

        # wait for switch to have its link local ipv6 addres ready
        switch_ip_state = ''
        while switch_ip_state != '80':
            sleep(1)
            with open('/proc/net/if_inet6', encoding='utf-8') as f:
                for line in f.readlines():
                    ip_info_list = line.split()
                    if ip_info_list[-1] == cls.switch_name:
                        switch_ip_state = ip_info_list[-2]
                        break

        cls.dst_exclusion_list = [str(InterfaceMLD.IPv6_LINK_SCOPE_ALL_ROUTERS), 'ff02::1:ff00:0']
        for index, node_dict in enumerate(cls.router_list + cls.host_list):
            node_dict['addr'] = IPv6Address(node_dict['nemu_if'].get_addresses()[0]['address'])
            cls.dst_exclusion_list.append('ff02::1:ff' + str(node_dict['addr'])[-7:])
            node_dict['pid'] = Process().children()[index].pid
            node_dict['if_ns_name'] = if_base_name + str(2 * index + 1)

        # Querier should be the router with the lowest link local address
        if cls.router_list[0]['addr'] > cls.router_list[1]['addr']:
            cls.router_list.reverse()

    @classmethod
    def tearDownClass(cls):
        for node in reversed(cls.node_list):
            node.destroy()

    def setUp(self):
        self.mld_socket = socket.socket(
            socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_IPV6))
        self.mld_socket.setsockopt(socket.SOL_SOCKET, SO_ATTACH_FILTER, MLD_BPF_PROG)
        self.mld_socket.bind((self.switch_name, ETH_P_IPV6))

    def __disable_mld(self, router_dict):
        """Disable mld for the given router."""
        with Namespace(router_dict['pid'], 'net'):
            router_dict.pop('mld_if').remove()

    def tearDown(self):
        self.mld_socket.close()
        for router_dict in self.router_list:
            if 'mld_if' in router_dict:
                self.__disable_mld(router_dict)
        for host_dict in self.host_list:
            if 'socket' in host_dict:
                host_dict['socket'].close()

    def __sniff_mld_msg(self, count, mld_type_tuple):
        """Sniff MLD packages of the given types on the switch (except the exclusion list)."""
        msg_list = []
        while len(msg_list) < count:
            data, _, _, _ = self.mld_socket.recvmsg(256 * 1024, 500)
            time = datetime.now()
            (next_header,) = struct.unpack('B', data[54:55])
            if next_header == 58:
                dst = socket.inet_ntop(socket.AF_INET6, data[38:54])
                (mld_type,) = struct.unpack('B', data[62:63])
                if (mld_type in mld_type_tuple and
                    dst not in self.dst_exclusion_list):
                    msg_list.append({
                        'time': time,
                        'src': socket.inet_ntop(socket.AF_INET6, data[22:38]),
                        'dst': dst,
                        'type': mld_type,
                        'max_response_delay_ms': struct.unpack('!H', data[66:68])[0],
                        'm_addr': socket.inet_ntop(socket.AF_INET6, data[-16:]),
                    })
        return msg_list

    def __sniff_mld_query_msg(self, count):
        """Sniff MLD queries on the switch."""
        return self.__sniff_mld_msg(count, (PacketMLDHeader.MULTICAST_LISTENER_QUERY_TYPE,))

    def __sniff_all_mld_type_msg(self, count):
        """Sniff all types of MLD packets on the switch."""
        return self.__sniff_mld_msg(count, (PacketMLDHeader.MULTICAST_LISTENER_QUERY_TYPE,
                                            PacketMLDHeader.MULTICAST_LISTENER_REPORT_TYPE,
                                            PacketMLDHeader.MULTICAST_LISTENER_DONE_TYPE))

    def __enable_mld(self, router_dict):
        """Enable MLD on the given router."""
        with Namespace(router_dict['pid'], 'net'):
            router_dict['mld_if'] = NsInterface(
                interface_name=router_dict['if_ns_name'],
                ns_pid=router_dict['pid'],
            )
        router_dict['mld_if'].enable()


    def test_max_response_delay_in_query(self):
        """Check if max response delay is correctly set in queries."""
        self.__enable_mld(self.router_list[0])
        self.assertEqual(
            self.__sniff_mld_query_msg(1)[0]['max_response_delay_ms'],
            mld_globals.QUERY_RESPONSE_INTERVAL * 1000,
        )

    def __check_mld_msg(self, msg, expected_msg):
        """Check if the MLD packet contains the expected atrributs."""
        if (msg['type'] != expected_msg['type'] or msg['src'] != expected_msg['src'] or
            msg['dst'] != expected_msg['dst']):
            return False
        if 'm_addr' in expected_msg and msg['m_addr'] != expected_msg['m_addr']:
            return False
        return True

    def __is_query(self, msg, src_addr, dst_addr):
        """Check if the packet is a MLD query from the expected source to the expected destination.
        """
        return self.__check_mld_msg(
            msg,
            {
                'type': PacketMLDHeader.MULTICAST_LISTENER_QUERY_TYPE,
                'src': str(src_addr),
                'dst': dst_addr,
            },
        )

    def __is_all_nodes_query(self, msg, addr):
        """Check if packet is a MLD query to all nodes from the expected source."""
        return self.__is_query(msg, addr, str(InterfaceMLD.IPv6_LINK_SCOPE_ALL_NODES))

    def __start_router_list_and_wait_for_election(self, router_list):
        """Enable MLD on a router and check it is elected Querier."""
        for router_dict in router_list:
            self.__enable_mld(router_dict)
        msg_list = self.__sniff_mld_query_msg(len(router_list) + 2)
        for index, router_dict in enumerate(router_list):
            self.assertTrue(self.__is_all_nodes_query(msg_list[index], router_dict['addr']))
        for msg in msg_list[-2:]:
            self.assertTrue(self.__is_all_nodes_query(msg, router_list[0]['addr']))
        return msg_list

    def __is_query_interval_respected(self, msg_list, ipv6):
        """Check if the interval between mld queries from a single source is QUERY_INTERVAL."""
        previous_msg = {}
        for msg in msg_list:
            if self.__is_all_nodes_query(msg, ipv6):
                if 'time' in previous_msg:
                    interval = round((msg['time'] - previous_msg['time']).total_seconds(), 1)
                    if interval != mld_globals.QUERY_INTERVAL:
                        return False
                previous_msg = msg
        return True

    def test_querier_election(self):
        """Check if the router with the lowest local link address is elected Querier."""
        msg_list = self.__start_router_list_and_wait_for_election(self.router_list)
        self.assertTrue(self.__is_query_interval_respected(msg_list, self.router_list[0]['addr']))

    def test_querier_reelection(self):
        """Check if the second router is elected Querier once the first stopped MLD."""
        self.__start_router_list_and_wait_for_election(self.router_list[-1:])
        router0_msg_list = self.__start_router_list_and_wait_for_election(self.router_list[0:1])

        self.__disable_mld(self.router_list[0])
        router1_msg = self.__sniff_mld_query_msg(1)[0]
        self.assertTrue(self.__is_all_nodes_query(router1_msg, self.router_list[1]['addr']))
        time_diff = (router1_msg['time'] - router0_msg_list[-1]['time']).total_seconds()
        self.assertEqual(round(time_diff, 1), mld_globals.OTHER_QUERIER_PRESENT_INTERVAL)

    def test_failure_of_non_querier(self):
        """Check there is no reelection if a non-Querier router stops MLD."""
        self.__start_router_list_and_wait_for_election(self.router_list[-1:])
        msg_list = self.__start_router_list_and_wait_for_election(self.router_list[0:1])

        self.__disable_mld(self.router_list[1])
        msg_list.extend(self.__sniff_mld_query_msg(1))
        self.assertTrue(self.__is_query_interval_respected(msg_list, self.router_list[0]['addr']))

    def __check_group_state_list(self, expected_group_list=[]):
        """Assert there is no unexpected group state listened."""
        for ip in self.router_list[0]['mld_if'].interface_state.group_state.keys():
            self.assertIn(ip, self.dst_exclusion_list + expected_group_list)
        for router_dict in self.router_list[1:]:
            self.assertFalse(hasattr(router_dict['mld_if'].interface_state, 'groupe_state'))

    def test_no_members_present_state(self):
        """Check there is no interest in any multicast group by default."""
        for router_dict in self.router_list:
            self.__enable_mld(router_dict)
        for msg in self.__sniff_all_mld_type_msg(4):
            self.assertEqual(msg['type'], PacketMLDHeader.MULTICAST_LISTENER_QUERY_TYPE)
        self.__check_group_state_list()

    def __run_multicast_client(self, host_dict, group_address):
        """Join the given multicast group from the given host."""
        with Namespace(host_dict['pid'], 'net'):
            sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            sock.setsockopt(
                socket.IPPROTO_IPV6,
                socket.IPV6_JOIN_GROUP,
                socket.inet_pton(socket.AF_INET6, group_address) +
                    struct.pack('@I', socket.if_nametoindex(host_dict['if_ns_name'])),
            )
        host_dict['socket'] = sock

    def __is_report(self, msg, src_addr, multicast_grp):
        """Check if the packet is a MLD report from the expected source for the expected multicast
        group."""
        return self.__check_mld_msg(
            msg,
            {
                'type': PacketMLDHeader.MULTICAST_LISTENER_REPORT_TYPE,
                'src': str(src_addr),
                'dst': multicast_grp,
            },
        )

    def __join_multicast_group_and_check_group_state(self, host_dict, multicast_addr):
        self.__run_multicast_client(host_dict, multicast_addr)
        msg_list = self.__sniff_all_mld_type_msg(2)
        self.assertTrue(self.__is_report(msg_list[0], host_dict['addr'], multicast_addr))
        self.assertTrue(self.__is_all_nodes_query(msg_list[1], self.router_list[0]['addr']))
        self.__check_group_state_list([multicast_addr])
        self.assertEqual(
            self.router_list[0]['mld_if'].interface_state.group_state[multicast_addr].state.print_state(),
            'ListenersPresent',
        )


    def test_membership_detection(self):
        """Check if interest for a multicast group is detected."""
        self.__start_router_list_and_wait_for_election(self.router_list)
        self.__join_multicast_group_and_check_group_state(self.host_list[0], 'ff02::12:12:12')

    def test_membership_detection_to_existing_group(self):
        """Check behaviour when host interested in a multicast group with already another host
        interested."""
        self.__start_router_list_and_wait_for_election(self.router_list)
        self.__join_multicast_group_and_check_group_state(self.host_list[0], 'ff02::12:12:12')
        self.__join_multicast_group_and_check_group_state(self.host_list[1], 'ff02::12:12:12')
