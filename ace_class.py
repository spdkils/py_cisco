# written by allen.stevens
import parse_ace


def ace_factory(string: str):
    processed_ace = parse_ace.ace_to_dict(string)
    checks = ['action', 'protocol',
              'source_ip', 'source_mask',
              'destination_ip', 'destination_mask']
    if processed_ace['action'] != 'remark' and not all([processed_ace[check] for check in checks]):
        raise ValueError(f'Bad ACE: {string}')
    if processed_ace['action'] == 'remark':
        return Remark(processed_ace)
    elif processed_ace['protocol'] in ['icmp', 'ip', 'igmp', 'pim', 'esp', 'eigrp'] or isinstance(processed_ace['protocol'], int):
        return ACE_IP_ICMP(processed_ace)
    else:
        return ACE_TCP_UDP(processed_ace)


class ACE(object):
    __slots__ = ['action', 'protocol', 'source_ip', 'source_mask', 'source_masked_ip',
                 'destination_ip', 'destination_mask', 'destination_masked_ip', 'options']

    def __init__(self, ace_dict):
        self.action = ace_dict['action']
        self.protocol = ace_dict['protocol']
        self.source_ip = self._ip_to_dec(ace_dict['source_ip'])
        self.source_mask = self._ip_to_dec(ace_dict['source_mask'])
        self.destination_ip = self._ip_to_dec(ace_dict['destination_ip'])
        self.destination_mask = self._ip_to_dec(ace_dict['destination_mask'])
        self.source_masked_ip = self.source_ip | self.source_mask
        self.destination_masked_ip = self.destination_ip | self.destination_mask
        self.options = []
        for x in range(6):
            self.options.append(ace_dict.get(f'option{x}'))

    def _ip_to_dec(self, ip):
        '''convert the string ip into a decimal number'''
        ip_dec = 0
        for idx, quad in enumerate(ip.split('.')):
            quad = int(quad)
            if 0 > quad or quad > 255:
                raise ValueError(f'IP address invalid. {ip}')
            ip_dec += quad << (8 * (3 - idx))
        if 0 > ip_dec or ip_dec > 4294967295:
            raise ValueError(f'IP address invalid. {ip}')
        return ip_dec

    def _dec_to_ip(self, dec: int) -> str:
        '''convert the decimal rep of an ip back to a string'''
        if 0 > dec or dec > 4294967295:
            raise ValueError('Decimal out of range for IPv4 Address')
        quad1 = 0b11111111000000000000000000000000
        quad2 = 0b00000000111111110000000000000000
        quad3 = 0b00000000000000001111111100000000
        quad4 = 0b00000000000000000000000011111111
        quads = [quad1, quad2, quad3, quad4]
        ip = []
        for idx, quad in enumerate(quads):
            ip.append(str((quad & dec) >> 8 * (3 - idx)))
        return '.'.join(ip)

    def dump(self, dir='in', est=False, os='catos'):
        '''Returns a string representation of the ace,
        strips off established and makes checks to see if it
        should be added or not.'''
        src_ip = self._dec_to_ip(self.source_ip)
        src_mask = self._dec_to_ip(self.source_mask)
        dst_ip = self._dec_to_ip(self.destination_ip)
        dst_mask = self._dec_to_ip(self.destination_mask)

        if src_mask == '0.0.0.0':
            src_ip, src_mask = 'host', src_ip
        elif src_mask == '255.255.255.255':
            src_ip, src_mask = 'any', None
        if dst_mask == '0.0.0.0':
            dst_ip, dst_mask = 'host', dst_ip
        elif dst_mask == '255.255.255.255':
            dst_ip, dst_mask = 'any', None

        if dir == 'out':
            src_ip, src_mask, dst_ip, dst_mask = dst_ip, dst_mask, src_ip, src_mask

        line = [f'{self.action:<6}', self.protocol,
                src_ip, src_mask,
                dst_ip, dst_mask,
                *self.options]
        return ' '.join([str(part) for part in line if part is not None]) + '\n'

    def __str__(self):
        return self.dump()


class ACE_IP_ICMP(ACE):
    def __init__(self, ace_dict):
        super().__init__(ace_dict)


class ACE_TCP_UDP(ACE):
    __slots__ = ['source_port', 'destination_port']

    def __init__(self, ace_dict):
        super().__init__(ace_dict)
        self.source_port = ACE_Port(ace_dict['source_port_op'], self.__handle_ports('src', ace_dict))
        self.destination_port = ACE_Port(ace_dict['destination_port_op'], self.__handle_ports('dst', ace_dict))

    def __handle_ports(self, direction, ace_dict):
        ports = []
        for key in ace_dict:
            if direction in key and ace_dict[key]:
                ports.append(ace_dict[key])
        return ports

    def dump(self, dir='in', est=False, os='catos'):
        '''Return a string representation of the ace,
        this is overridden from the default dump.
        This takes into account ports, and should return
        one line per port if it's nxos'''

        if 'established' in self.options:
            self.options.remove('established')

        src_op, src_ports = self.source_port.op, str(self.source_port)
        if not src_ports:
            src_ports = None
        dst_op, dst_ports = self.destination_port.op, str(self.destination_port)
        if not dst_ports:
            dst_ports = None
        src_ip = self._dec_to_ip(self.source_ip)
        src_mask = self._dec_to_ip(self.source_mask)
        dst_ip = self._dec_to_ip(self.destination_ip)
        dst_mask = self._dec_to_ip(self.destination_mask)

        if src_mask == '0.0.0.0':
            src_ip, src_mask = 'host', src_ip
        elif src_mask == '255.255.255.255':
            src_ip, src_mask = 'any', None
        if dst_mask == '0.0.0.0':
            dst_ip, dst_mask = 'host', dst_ip
        elif dst_mask == '255.255.255.255':
            dst_ip, dst_mask = 'any', None

        if dir == 'out':
            src_op, src_ports, dst_op, dst_ports = dst_op, dst_ports, src_op, src_ports
            src_ip, src_mask, dst_ip, dst_mask = dst_ip, dst_mask, src_ip, src_mask

        ftp_data = self.source_port.ports.issuperset({20}) or self.destination_port.ports.issuperset({20})
        active_ftp = self.protocol == 'tcp' and not src_op and dst_op == 'eq' and dst_ports == [20]

        if est and self.protocol == 'tcp' and not ftp_data and src_op and not dst_op:
            self.options.insert(0, 'established')
        elif est and active_ftp:
            self.options.insert(0, 'established')

        line = [f'{self.action:<6}', self.protocol,
                src_ip, src_mask, src_ports,
                dst_ip, dst_mask, dst_ports,
                *self.options]
        return ' '.join([str(part) for part in line if part is not None]) + '\n'


class ACE_Port(object):
    '''Simple set like representation of a port range,
    allows in compares, ispart of etc...'''
    __slots__ = ['op', 'ports']
    # TODO: Needs rewrite to prevent all the needless looping
    __gt1023 = {i for i in range(1023, 65536)}

    def __init__(self, op, ports):
        self.op = op
        self.ports = set()
        if op == 'range':
            self.ports = {i for i in range(ports[0], ports[1] + 1)}
        elif op == 'gt' and ports[0] == 1023:
            self.ports = ACE_Port.__gt1023.copy()
        elif op == 'gt':
            self.ports = {i for i in range(ports[0], 65536)}
        elif op == 'lt':
            self.ports = {i for i in range(0, ports[0])}
        elif op == 'eq':
            self.ports = set(ports)

    def __str__(self):
        if self.op is None:
            return ''
        elif self.op == 'gt':
            return '{} {}'.format(self.op, list(self.ports)[0])
        elif self.op == 'lt':
            return '{} {}'.format(self.op, list(self.ports)[-1])
        elif self.op == 'range':
            return '{} {} {}'.format(self.op, sorted(list(self.ports))[0], sorted(list(self.ports))[-1])
        elif self.op == 'eq':
            return '{} {}'.format(self.op, ' '.join([str(i) for i in sorted(self.ports)]))


class Remark(object):
    def __init__(self, ace_dict):
        self.action = ace_dict['action']
        self.text = ace_dict['text']

    def dump(self, dir='in', est=False, os='catos'):
        return ' '.join([self.action, self.text]) + '\n'

    def __str__(self):
        return self.dump()


if __name__ == '__main__':
    pass
    # example = ' permit tcp 10.13.13.1 0.0.0.7 eq 22 any'
    # example = ' permit icmp host 10.10.10.10 10.0.0.0 0.255.255.255 packet-too-big log'
    # example = ' permit udp host 0.0.0.0 host 255.255.255.255 eq 123 67'
    # example = ' permit ip any any log'
    # example = ' permit 112 any any'
    # example = ' permit zzz any any'
    # example = ' remark I just thought I would put in a remark ***'
    # split the line

    # loop tokens and use a basic if structure to load up the data structure.

    # my_ace = ace_factory(example)
    # print(type(my_ace))
    # print(my_ace.action)
    # print(my_ace.protocol)
    # print(my_ace.source_ip)
    # print(my_ace._dec_to_ip(my_ace.source_ip))
    # print(my_ace.source_mask)
    # print(my_ace.source_port.op)
    # print(my_ace.source_port.ports)
    # print(my_ace.source_port)

    # print(my_ace.destination_ip)
    # print(my_ace._dec_to_ip(my_ace.destination_ip))
    # print(my_ace.destination_mask)
    # print(my_ace.destination_port.op)
    # print(my_ace.destination_port.ports)
    # print(my_ace.destination_port)

    # print(my_ace.source_masked_ip)
    # print(my_ace.destination_masked_ip)

    # print(my_ace.options)

    # print(my_ace.dump(est=True, dir='in'))
