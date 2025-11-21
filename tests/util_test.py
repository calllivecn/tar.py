
import unittest


class Pipe_test(unittest.TestCase):
    def test_pipe(self):
        from util import Pipe

        p = Pipe()
        result = (
            "hello world"
            | p.str.upper()
            | p.str.replace("WORLD", "there")
            | p.str.split()
        )
        self.assertEqual(result, ["HELLO", "there"])