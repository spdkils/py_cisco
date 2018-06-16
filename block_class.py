# written by allen.stevens
from ace_class import ace_factory


class Block(object):
    def __init__(self, text_block: str, parent: object = None):
        self.acl = parent
        self.aces = []
        aces = text_block.strip().split('\n')
        for ace in aces:
            self.aces.append(ace_factory(ace))

    def dump(self, dir='in', est=False, os='catos'):
        results = ''
        for ace in self.aces:
            results += ace.dump(dir, est, os)
        return results


if __name__ == '__main__':
    pass
    # example = ' remark I like dogs and cats\n'
    # example += ' remark I like cars and bars\n'
    # example += ' permit tcp 10.184.13.1 0.0.0.7 range 80 555 any established\n'
    # example += ' permit icmp host 10.10.10.10 10.0.0.0 0.255.255.255 packet-too-big log\n'

    # my_block = Block(example)
    # print(my_block.dump())
