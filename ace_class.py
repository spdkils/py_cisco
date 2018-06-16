# written by allen.stevens
import parse_ace


def ace_factory(string: str):
    processed_ace = parse_ace.ace_to_dict(string)
    if processed_ace['action'] == 'remark':
        return Remark(processed_ace)
    elif processed_ace['protocol'] in ['icmp', 'ip', 'igmp', 'pim'] or isinstance(processed_ace['protocol'], int):
        return ACE_IP_ICMP(processed_ace)
    else:
        return ACE_TCP_UDP(processed_ace)


class ACE(object):
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
        for key in ace_dict:
            if 'option' in key and ace_dict[key]:
                self.options.append(ace_dict[key])

    def _ip_to_dec(self, ip):
        '''convert the string ip into a decimal number'''
        ip_dec = 0
        for idx, quad in enumerate(ip.split('.')):
            ip_dec += int(quad) << (8 * (3 - idx))
        return ip_dec

    def _dec_to_ip(self, dec: int) -> str:
        '''convert the decimal rep of an ip back to a string'''
        quad1 = 0b11111111000000000000000000000000
        quad2 = 0b00000000111111110000000000000000
        quad3 = 0b00000000000000001111111100000000
        quad4 = 0b00000000000000000000000011111111
        quads = [quad1, quad2, quad3, quad4]
        ip = []
        for idx, quad in enumerate(quads):
            ip.append(str((quad & dec) >> 8 * (3 - idx)))
        return '.'.join(ip)

    def overlap(self, other):
        return True

    def dump(self, dir='in', est=False, os='catos'):
        to_dec = self._dec_to_ip
        results = ''
        block = [self.action, self.protocol]
        if dir == 'in':
            block.extend([to_dec(self.source_ip), to_dec(self.source_mask),
                          to_dec(self.destination_ip), to_dec(self.destination_mask),
                          *self.options])
        if dir == 'out':
            block.extend([to_dec(self.destination_ip), to_dec(self.destination_mask),
                          to_dec(self.source_ip), to_dec(self.source_mask),
                          *self.options])
        results += ' '.join([str(x) for x in block if x]) + '\n'
        return results

    def __str__(self):
        output = str(self.source_ip) + ' ' + self.destination_ip
        return output


class Remark(object):
    def __init__(self, ace_dict):
        self.action = ace_dict['action']
        self.text = ace_dict['text']

    def dump(self, dir='in', est=False, os='catos'):
        return ' '.join([self.action, self.text]) + '\n'


class ACE_IP_ICMP(ACE):
    def __init__(self, ace_dict):
        super().__init__(ace_dict)


class ACE_TCP_UDP(ACE):
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
        to_dec = self._dec_to_ip
        results = ''

        def _port_dump(dump_port: ACE_Port):
            if dump_port and dump_port.op == 'range':
                dump = sorted(dump_port.ports)
                dump = [dump[0], dump[-1]]
                dump_op = dump_port.op
            elif dump_port.op == 'gt':
                dump = sorted(dump_port.ports)
                dump = [dump[0]]
                dump_op = dump_port.op
            elif dump_port.op == 'lt':
                dump = sorted(dump_port.ports)
                dump = [dump[-1]]
                dump_op = dump_port.op
            elif dump_port.op:
                dump = sorted(dump_port.ports)
                dump_op = dump_port.op
            else:
                dump_op = None
                dump = [None]
            return dump_op, dump

        src_op, src_ports = _port_dump(self.source_port)
        dst_op, dst_ports = _port_dump(self.destination_port)
        block = [self.action, self.protocol]
        if 'established' in self.options:
            self.options.remove('established')
        if dir == 'in':
            if est and self.protocol == 'tcp' and self.source_port.op and not self.destination_port.op:
                self.options.insert(0, 'established')
            block.extend([to_dec(self.source_ip), to_dec(self.source_mask), src_op, *src_ports,
                          to_dec(self.destination_ip), to_dec(self.destination_mask), dst_op, *dst_ports,
                          *self.options])
        if dir == 'out':
            if est and self.protocol == 'tcp' and self.destination_port.op and not self.source_port.op:
                self.options.insert(0, 'established')
            block.extend([to_dec(self.destination_ip), to_dec(self.destination_mask), dst_op, *dst_ports,
                          to_dec(self.source_ip), to_dec(self.source_mask), src_op, *src_ports,
                          *self.options])
        results += ' '.join([str(x) for x in block if x]) + '\n'
        return results


class ACE_Port(object):
    def __init__(self, op, ports):
        self.op = op
        if op == 'range':
            self.ports = {i for i in range(ports[0], ports[1] + 1)}
        elif op == 'gt':
            self.ports = {i for i in range(ports[0], 65536)}
        elif op == 'lt':
            self.ports = {i for i in range(0, ports[0])}
        elif op == 'eq':
            self.ports = set(ports)

    def __str__(self):
        if self.op in ['gt', 'lt']:
            return '{} {}'.format(self.op, list(self.ports)[0])
        elif self.op == 'range':
            return '{} {} {}'.format(self.op, sorted(list(self.ports))[0], sorted(list(self.ports))[-1])
        elif self.op == 'eq':
            return '{} {}'.format(self.op, ' '.join(sorted([str(i) for i in self.ports])))


if __name__ == '__main__':
    pass
    # example = ' permit tcp 10.184.13.1 0.0.0.7 range 80 555 any established'
    # example = ' permit icmp host 10.10.10.10 10.0.0.0 0.255.255.255 packet-too-big log'
    # example = ' permit ip any any log'
    # example = ' permit 112 any any'
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

    # print(my_ace.destination_mask)
    # print(my_ace.destination_port.op)
    # print(my_ace.destination_port.ports)
    # print(my_ace.destination_port)

    # print(my_ace.source_masked_ip)
    # print(my_ace.destination_masked_ip)

    # print(my_ace.options)

    # print(my_ace.dump())
