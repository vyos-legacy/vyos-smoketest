#!/usr/bin/env python3
#
# Copyright (C) 2020 VyOS maintainers and contributors
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 or later as
# published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import os
import jmespath
import json
import unittest

from vyos.configsession import ConfigSession, ConfigSessionError
from vyos.util import cmd

base_path = ['nat66']
snat_pattern = 'nftables[?rule].rule[?chain].{chain: chain, comment: comment, prefix: { network: expr[].match.right.prefix.addr | [0], prefix: expr[].match.right.prefix.len | [0]},saddr: {network: expr[].snat.addr.prefix.addr | [0], prefix: expr[].snat.addr.prefix.len | [0]}}'

class TestNAT(unittest.TestCase):
    def setUp(self):
        # ensure we can also run this test on a live system - so lets clean
        # out the current configuration :)
        self.session = ConfigSession(os.getpid())
        self.session.delete(base_path)

    def tearDown(self):
        self.session.delete(base_path)
        self.session.commit()

    def test_source_nat(self):
        """ Configure and validate source NAT66 rule(s) """

        path = base_path + ['source']
        prefix = '2001::/64'
        source_prefix = 'fc00::/64'
        self.session.set(path + ['rule', '1', 'translation', 'prefix', prefix])
        self.session.set(path + ['rule', '1', 'source', 'prefix', source_prefix])

        # check validate() - outbound-interface must be defined
        with self.assertRaises(ConfigSessionError):
            self.session.commit()

        self.session.set(path + ['rule', '1', 'outbound-interface', 'any'])
        self.session.commit()

        tmp = cmd('sudo nft -j list table ip6 nat')
        nftable_json = json.loads(tmp)
        condensed_json = jmespath.search(snat_pattern, nftable_json)[0]

        self.assertEqual(condensed_json['comment'], 'NPT-NAT-1')
        self.assertEqual(condensed_json['prefix']['network'], source_prefix.split('/')[0])
        self.assertEqual(str(condensed_json['prefix']['prefix']), source_prefix.split('/')[1])
        self.assertEqual(condensed_json['saddr']['network'], prefix.split('/')[0])
        self.assertEqual(str(condensed_json['saddr']['prefix']), prefix.split('/')[1])

if __name__ == '__main__':
    unittest.main()
