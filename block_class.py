# written by allen.stevens
from ace_class import ace_factory, ACE


class Block(object):
    def __init__(self, text_block: str, parent: object = None):
        self.acl = parent
        self._raw = text_block
        self.aces = []
        raw_aces = text_block.strip().split('\n')
        for ace in raw_aces:
            self.aces.append(ace_factory(ace))

    def insert_statement(self, statement):
        '''Inserts an ace after the last remark, before
        all other statements.
        statement = text of ace (assume inbound)
        returns nothing'''
        ace_statement = ace_factory(statement)
        for idx, ace in enumerate(self.aces):
            if isinstance(ace, ACE):
                break
        self.aces.insert(idx, ace_statement)

    def insert(self, index, text_ace):
        '''Similar to list insert function
        takes an index, and the text statement
        to create an ace object, and inserts at that
        location in the self.aces'''
        ace_statement = ace_factory(text_ace)
        self.aces.insert(index, ace_statement)

    def dump(self, dir='in', est=False, os='catos'):
        '''Loops over the aces, calling their dump method,
        assumes inbound syntax, can reverse dump by calling
        dir='out'. If you set the est flag to True, it will
        try and calculate if the established option should be
        used.'''
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
    # my_block.insert(0, 'permit ip any any')
    # print('my_block.insert_statement()')
    # print(my_block.dump())
