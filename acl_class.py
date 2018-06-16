# written by allen.stevens
import re
from block_class import Block


class Acl(object):
    def __init__(self, name: str, body_of_acl: str, parent: object=None):
        self.name = name
        self.parent = parent
        self.blocks = []
        blocks = self._break_into_blocks(body_of_acl)
        for block in blocks:
            self.blocks.append(Block(block, parent=self))

    def _break_into_blocks(self, text_acl: str):
        blocks = re.findall('(?:\\s*remark .*\\n)+(?:(?:permit|deny) .*\\n?)+', text_acl, flags=re.M)
        return blocks

    def dump(self, dir='in', est=False, os='catos'):
        result = ''
        for block in self.blocks:
            result += block.dump(dir, est, os)
        return result


if __name__ == '__main__':
    pass
    #     dumb_acl = ''' remark this is my dumb acl example
    # remark it really has no use
    # permit icmp host 10.10.10.1 host 10.20.30.40 packet-too-big
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
