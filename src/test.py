#!/usr/bin/env python3
# coding=utf-8
# date 2024-01-30 03:47:12
# author calllivecn <calllivecn@outlook.com>


import unittest

import version


class MainTestCase(unittest.TestCase):

    def test_version(self):
        self.assertTrue(hasattr(version, "VERSION"), True)
    
    def test_pass(self):
        pass





if __name__ == "__main__":
    unittest.main()
