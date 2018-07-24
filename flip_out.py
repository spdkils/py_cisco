import os
import re
import acl_class
import argparse

parser = argparse.ArgumentParser(description='Flip inbound ACLs.')
parser.add_argument('filename', help='File to search for inbound acl...', type=argparse.FileType(mode='r', encoding='UTF-8'))
parser.add_argument('-e', '--established', help='Do not add established statements...', action="store_false")
args = parser.parse_args()


def strip_acl(acl_to_strip):
    stripped_contents = ''
    for line in acl_to_strip.split('\n'):
        if (line.strip().startswith('permit') or
            line.strip().startswith('deny') or
                line.strip().startswith('remark')):
            stripped_contents += f'{line.strip()}\n'
    return stripped_contents


file_contents = args.filename.read()
folder = os.path.dirname(args.filename.name)
filename = 'IN_OUT_' + os.path.basename(args.filename.name)
new_filename = os.path.join(folder, filename)
args.filename.close()

inbound_data = re.search('^(?: +)?ip access-list extended (.*)\\r?\\n((?: .*\\r?\\n)+)', file_contents, flags=re.M)

try:
    name = inbound_data.group(1)
    contents = inbound_data.group(2)
except AttributeError:
    print("I could not find an ACL in that file...\nMake sure you use indentation for you lines, and that it is an inbound ACL or this won't go well.")
else:
    stripped_acl = strip_acl(contents)
    acl_to_flip = acl_class.Acl(name, stripped_acl)
    print(f'!!FLIPPED ACL {acl_to_flip.name}')
    new_name = re.sub('-IN$', '-OUT', acl_to_flip.name.upper(), flags=re.M)
    header_in = f'no ip access-list extended {acl_to_flip.name}\n'
    header_in += f'ip access-list extended {acl_to_flip.name}'
    acl_input = ''
    acl_output = ''
    for idx, block in enumerate(acl_to_flip.blocks):
        acl_input += f'! BLOCK {idx} -----------------------------\n'
        acl_output += f'! BLOCK {idx} -----------------------------\n'

        acl_input += block.dump(dir='in', est=args.established)
        acl_input += '\n'
        acl_output += block.dump(dir='out', est=args.established)
        acl_output += '\n'
    acl_input = re.sub('^', ' ', acl_input, flags=re.M)
    acl_output = re.sub('^', ' ', acl_output, flags=re.M)

    header_out = f'no ip access-list extended {new_name}\n'
    header_out += f'ip access-list extended {new_name}'

    print(header_in)
    print(header_out)

    with open(new_filename, 'w') as w:
        w.write('\n!************FLIPPER START*************\n')
        w.write(header_in + '\n')
        w.write(acl_input)
        w.write('\n!************FLIPPER END*************\n\n\n\n')
        w.write('\n!************FLIPPER START*************\n')
        w.write(header_out + '\n')
        w.write(acl_output)
        w.write('\n!************FLIPPER END*************\n')
        w.close()
