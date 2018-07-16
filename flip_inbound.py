import re
import acl_class
import argparse

parser = argparse.ArgumentParser(description='Flip inbound ACLs.')
parser.add_argument('filename', help='File to search for inbound acl...', type=argparse.FileType(mode='r+', encoding='UTF-8'))
# parser.add_argument('output', help='File to write flipped acl...', type=argparse.FileType(mode='w', encoding='UTF-8'))
parser.add_argument('-e', '--established', help='Smart addition of established statements...', action="store_true")
args = parser.parse_args()

file_contents = args.filename.read()

inbound_data = re.search('^(?: +)?ip access-list extended (.*)\\r?\\n((?: .*\\r?\\n)+)', file_contents, flags=re.M)

try:
    acl_to_flip = acl_class.Acl(inbound_data.group(1), inbound_data.group(2))
except AttributeError:
    print("I could not find an ACL in that file...\nMake sure you use indentation for you lines, and that it is an inbound ACL or this won't go well.")
else:
    print(f'!!FLIPPED ACL {acl_to_flip.name}')
    new_name = re.sub('-IN$', '-OUT', acl_to_flip.name.upper(), flags=re.M)
    header = f'no ip access-list extended {new_name}\n'
    header += f'ip access-list extended {new_name}'
    acl_output = acl_to_flip.dump(dir='out', est=args.established)
    acl_output = re.sub('^', ' ', acl_output, flags=re.M)
    print(header)
    print(acl_output)
    args.filename.write('\n!************FLIPPER START*************\n')
    args.filename.write(header + '\n')
    args.filename.write(acl_output)
    args.filename.write('\n!************FLIPPER END*************\n')
    args.filename.close()
