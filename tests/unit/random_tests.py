from unittest2 import TestCase
from onepassword import random_util


class RandomTestCase(TestCase):
    # just make sure that all of the functions return the right number
    # of bytes for now
    BYTES = 512

    def test_not_random(self):
        bytez = random_util.not_random_bytes(self.BYTES)
        self.assertEqual(len(bytez), self.BYTES)

    def test_barely_random(self):
        bytez = random_util.barely_random_bytes(self.BYTES)
        self.assertEqual(len(bytez), self.BYTES)

    def test_sort_of_random(self):
        bytez = random_util.sort_of_random_bytes(self.BYTES)
        self.assertEqual(len(bytez), self.BYTES)

    def test_really_random(self):
        bytez = random_util.really_random_bytes(self.BYTES)
        self.assertEqual(len(bytez), self.BYTES)
