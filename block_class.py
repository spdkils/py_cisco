# written by allen.stevens
import ace_class


class Block(object):
    def __init__(self, aces: list, parent: object = None):
        self.acl = parent
        self.aces = []
        for ace in aces:
            self.aces.append(ace_class.ace_factory(ace))

    def dump(self, version='catos'):
        results = []
        os = self.acl.config.os
        for ace in self.aces:
            results.extend(list(ace.dump(os)))
