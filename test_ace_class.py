from ace_class import *
from unittest import TestCase, main


class Test_Remark(TestCase):
    def test_remarks(self):
        remark1 = Remark(parse_ace.ace_to_dict('remark I love -- pie, so much!'))
        self.assertEqual(remark1.text, 'I love -- pie, so much!')


class Test_ACE_TCP_UDP(TestCase):
    ace1 = ace_factory('permit tcp host 10.10.10.1 eq 21 host 20.20.20.1 established log-input')
    ace2 = ace_factory('permit tcp host 10.10.10.1 eq www host 20.20.20.1 established log')
    ace3 = ace_factory('permit tcp host 10.10.10.1 eq 443 host 20.20.20.1 established')

    def test_construction(self):
        ace4 = ace_factory('permit udp host 10.10.10.1 range netbios-ns 401 host 20.20.20.1 established log-input')

    def test_dump_in(self):
        self.assertEqual(Test_ACE_TCP_UDP.ace1.dump(dir='in', est=False), 'permit tcp 10.10.10.1 0.0.0.0 eq 21 20.20.20.1 0.0.0.0 log-input\n')


if __name__ == '__main__':
    main()
