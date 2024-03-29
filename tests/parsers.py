import unittest
from main import check_keys_parser_classes


class ParsersTest(unittest.TestCase):

    def test_all_parsers_are_included(self):
        check_keys_parser_classes()
