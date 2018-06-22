# written by allen.stevens
import re
from block_class import Block
import config_class
import ipaddress


class Acl(object):
    def __init__(self, name: str, body_of_acl: str, parent: object = None):
        self.name = name
        self.parent = parent
        if isinstance(self.parent, config_class.Cisco_Config):
            self.interfaces = self.parent._find_ace_interfaces(self.name)
            self.addresses = []
            for intface in self.interfaces:
                self.addresses += self.parent._get_subnets(intface)
        if self.interfaces and self.addresses:
            self.calculated_addressess = []
            for address in self.addresses:
                self.calculated_addressess.append(self._static_overlap(address))

        self.blocks = []
        raw_blocks = self._break_into_blocks(body_of_acl)
        for block in raw_blocks:
            self.blocks.append(Block(block, parent=self))

    def _break_into_blocks(self, text_acl: str):
        aces = text_acl.strip().split('\n')
        line = 0
        blocks = []
        while line < len(aces):
            block = ''
            while line < len(aces) and aces[line].strip().startswith('remark'):
                block += aces[line] + '\n'
                line += 1
            while line < len(aces) and aces[line].strip().startswith('permit'):
                block += aces[line] + '\n'
                line += 1
            while line < len(aces) and aces[line].strip().startswith('deny'):
                block += aces[line] + '\n'
                line += 1
            blocks.append(block)
        return blocks

    def _static_overlap(self, address):
        ip_intface = ipaddress.ip_interface('/'.join(address.split()))
        return ' '.join([str(ip_intface.network.network_address), str(ip_intface.network.hostmask)])

    def dump(self, dir='in', est=False, os='catos'):
        result = ''
        for block in self.blocks:
            result += block.dump(dir, est, os)
        return result


if __name__ == '__main__':
    pass
#     dumb_acl = ''' permit icmp host 10.10.10.1 host 10.20.30.40 packet-too-big
# permit tcp 10.20.30.40 0.3.0.0 eq 80 host 20.30.40.50 established
# remark this is my 2nd block
# remark this is also still in the 2nd block
# deny ip any any'''

#     my_acl = Acl('stupid_acl', dumb_acl)
#     print(my_acl.name)
#     print(my_acl.blocks)
#     for i, block in enumerate(my_acl.blocks):
#         print('block ', i)
#         print(block.dump())
