# written by allen.stevens
import re
import ipaddress
from block_class import Block
try:
    import config_class
    CONFIG_CLASS = True
except ImportError:
    CONFIG_CLASS = False


class Acl(object):
    __slots__ = ['name', 'parent', 'interfaces', 'calculated_networks', 'calculated_statics', 'blocks', 'ip_interfaces']

    def __init__(self, name: str, body_of_acl: str, parent: object = None):
        self.name = name
        self.parent = parent
        self.interfaces = set()
        self.ip_interfaces = set()
        self.calculated_networks = set()
        self.calculated_statics = set()
        if CONFIG_CLASS and isinstance(self.parent, config_class.Cisco_Config):
            self.interfaces = set(self.parent._find_ace_interfaces(self.name))
            for intface in self.interfaces:
                self.ip_interfaces.update(self.parent._get_subnets(intface))
            if self.interfaces and self.ip_interfaces:
                for address in self.ip_interfaces:
                    self.calculated_networks.add(self._calculate_address(address))
                for address in self.ip_interfaces:
                    static_route = self._calculated_statics(address)
                    if static_route:
                        self.calculated_statics.add(static_route)

        self.blocks = []
        raw_blocks = self._break_into_blocks(body_of_acl)
        for block in raw_blocks:
            self.blocks.append(Block(block, parent=self))

    def _break_into_blocks(self, text_acl: str):
        aces = text_acl.strip().split('\n')
        line = 0
        blocks = []
        block = ''
        while line < len(aces):
            while line < len(aces) and aces[line].strip().startswith('remark'):
                block += aces[line] + '\n'
                line += 1
            while line < len(aces) and (aces[line].strip().startswith('permit')
                                        or aces[line].strip().startswith('deny')):
                block += aces[line] + '\n'
                line += 1
            blocks.append(block)
            block = ''
        return blocks

    def _calculate_address(self, address):
        ip_intface = ipaddress.ip_interface('/'.join(address.split()))
        return ' '.join((str(ip_intface.network.network_address), str(ip_intface.network.hostmask)))

    def _calculated_statics(self, address):
        ip_intface = ipaddress.ip_interface('/'.join(address.split()))
        for address in self._truncated_static_routes():
            # TODO: total hack, need to push this up into config or something.
            if CONFIG_CLASS and isinstance(self.parent, config_class.Cisco_Config):
                if address[2] in self.parent.interfaces:
                    raw_address = self.parent._get_subnets(address[2])[0]
                    raw_address = raw_address.split(' ')[0]
                else:
                    raw_address = address[2]
            ip_route = ipaddress.ip_address(raw_address)
            if ip_route in ip_intface.network:
                new_network = ipaddress.ip_network('/'.join(address[:2]))
                return ' '.join((str(new_network.network_address), str(new_network.hostmask)))

    def _truncated_static_routes(self):
        for route in self.parent.static_routes:
            yield route.split()[:3]

    def __str__(self):
        return self.name

    def dump(self, dir='in', est=False, os='catos'):
        result = ''
        for block in self.blocks:
            result += block.dump(dir, est, os)
        return result


if __name__ == '__main__':
    pass
    # dumb_acl = ''
    # with open('test_ace.txt') as f:
    #     for line in f:
    #         if (line.strip().startswith('permit')
    #             or line.strip().startswith('deny')
    #             or line.strip().startswith('remark')):
    #             dumb_acl += f'{line.strip()}\n'
    # dumb_acl = re.sub('^( )*!.*\\r?\\n', '', dumb_acl, flags=re.M)
    # dumb_acl = re.sub('^( )*\\r?\\n', '', dumb_acl, flags=re.M)

    # my_acl = Acl('stupid_acl', dumb_acl)
    # for i, block in enumerate(my_acl.blocks):
    #     print('block ', i)
    #     print('-'*90)
    #     print(block.dump(dir='out'))
