# written by allen.stevens
import re
import port_names

types = {'action': '^(?:permit|deny|remark)$',
         'protocol': '^(?:ip|tcp|udp|icmp|pim|igmp)$',
         'ip_or_mask': '^((?:\\d{1,3}\\.){3}\\d{1,3})$',
         'port_op': '^(?:eq|lt|gt|range)$',
         'integer': '^\\d+$',
         'word': '\\w+'}

ip_v4_fields = ['action', 'protocol',
                'source_ip', 'source_mask',
                'destination_ip', 'destination_mask',
                'option0', 'option1', 'option2', 'option3', 'option4', 'option5']
ip_v4_data_types = ['action', 'protocol',
                    'ip_or_mask', 'ip_or_mask',
                    'ip_or_mask', 'ip_or_mask',
                    'any', 'any', 'any', 'any', 'any', 'any']

tcp_udp_fields = ['action', 'protocol',
                  'source_ip', 'source_mask',
                  'source_port_op', 'src_port0', 'src_port1', 'src_port2', 'src_port3', 'src_port4', 'src_port5', 'src_port6', 'src_port7', 'src_port8', 'src_port9',
                  'destination_ip', 'destination_mask',
                  'destination_port_op', 'dst_port0', 'dst_port1', 'dst_port2', 'dst_port3', 'dst_port4', 'dst_port5', 'dst_port6', 'dst_port7', 'dst_port8', 'dst_port9',
                  'option0', 'option1', 'option2', 'option3', 'option4', 'option5']
tcp_udp_data_types = ['action', 'protocol',
                      'ip_or_mask', 'ip_or_mask',
                      'port_op', 'integer', 'integer', 'integer', 'integer', 'integer', 'integer', 'integer', 'integer', 'integer', 'integer',
                      'ip_or_mask', 'ip_or_mask',
                      'port_op', 'integer', 'integer', 'integer', 'integer', 'integer', 'integer', 'integer', 'integer', 'integer', 'integer',
                      'any', 'any', 'any', 'any', 'any', 'any']

tcp_udp = (tcp_udp_fields, tcp_udp_data_types)
ipv4 = (ip_v4_fields, ip_v4_data_types)


def split_ace(ace) -> list:
    return ace.strip().split()


def host_replace(ace: list) -> None:
    '''Edits the ace in place, replacing the any and
    host keywords with the IP addresses they represent'''
    for idx, item in enumerate(ace):
        if item.lower() == 'any':
            ace[idx] = '0.0.0.0'
            ace.insert(idx + 1, '255.255.255.255')
        elif item.lower() == 'host':
            ace[idx], ace[idx + 1] = ace[idx + 1], '0.0.0.0'


def port_names_replace(ace: list) -> None:
    '''Edits the ace in place, replacing port-names with
    the actual protocol numbers'''
    protocol = port_names.ALL_PORTS.get(ace[1])
    if protocol is not None:
        for idx, item in enumerate(ace):
            if item in protocol:
                ace[idx] = protocol[item]


def tokenize(ace: list) -> tuple:
    for token in ace:
        for op in types:
            if re.search(types[op], token, flags=re.M):
                yield op, token
                break


def create_ace_entry(ace, ace_type, keys):
    field_names, slot_types = keys
    fields = [None] * len(field_names)
    slot_location = 0
    for token, value in tokenize(ace):
        empty_slot = True
        while empty_slot and slot_location < len(field_names):
            slot_type = slot_types[slot_location]
            if ace_type == 'ip':
                numbered_protocol = slot_type == 'protocol' and token == 'integer'
            else:
                numbered_protocol = False
            if token == slot_type or slot_type == 'any' or numbered_protocol:
                if token == 'integer':
                    fields[slot_location] = int(value)
                else:
                    fields[slot_location] = value
                slot_location += 1
                empty_slot = False
            else:
                slot_location += 1
    return dict(zip(field_names, fields))


def ace_to_dict(ace):
    working_ace = split_ace(ace)
    if working_ace[0] == 'remark':
        return {'action': 'remark', 'text': ace[ace.find('remark') + 7:]}
    elif working_ace[1] in ['icmp', 'ip'] or working_ace[1].isdigit():
        host_replace(working_ace)
        port_names_replace(working_ace)
        return create_ace_entry(working_ace, 'ip', ipv4)
    else:
        host_replace(working_ace)
        port_names_replace(working_ace)
        return create_ace_entry(working_ace, 'tcp', tcp_udp)


if __name__ == '__main__':
    pass
    # example = ' permit tcp 10.184.13.1 0.0.0.7 range www 555 any eq 50 60 70 80 established'
    # example = ' permit icmp host 10.10.10.10 10.0.0.0 0.255.255.255 packet-too-big log'
    # example = ' permit ip any any log'
    # example = ' permit 112 any any'
    # example = ' permit 10.10.10.0 0.0.0.255'
    # example = ' permit 10.10.10.1'
    # example = ' remark I just thought I would put in a remark ***'
    # a = ace_to_dict(example)
    # print(a)
