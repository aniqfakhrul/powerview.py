#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          :
# Author             :  Podalirius (@podalirius_)

from dsinternals.system.Guid import Guid
import unittest


class TestCaseGuid(unittest.TestCase):

    def test_load_guid_from_format_N(self):
        g = Guid.fromFormatN("fedcba981234abcdffff87ff87acef87")
        self.assertEqual(g.a, 0xfedcba98)
        self.assertEqual(g.b, 0x1234)
        self.assertEqual(g.c, 0xabcd)
        self.assertEqual(g.d, 0xffff)
        self.assertEqual(g.e, 0x87ff87acef87)

    def test_load_guid_from_format_D(self):
        g = Guid.fromFormatD("fedcba98-1234-abcd-ffff-87ff87acef87")
        self.assertEqual(g.a, 0xfedcba98)
        self.assertEqual(g.b, 0x1234)
        self.assertEqual(g.c, 0xabcd)
        self.assertEqual(g.d, 0xffff)
        self.assertEqual(g.e, 0x87ff87acef87)

    def test_load_guid_from_format_P(self):
        g = Guid.fromFormatP("(fedcba98-1234-abcd-ffff-87ff87acef87)")
        self.assertEqual(g.a, 0xfedcba98)
        self.assertEqual(g.b, 0x1234)
        self.assertEqual(g.c, 0xabcd)
        self.assertEqual(g.d, 0xffff)
        self.assertEqual(g.e, 0x87ff87acef87)

    def test_load_guid_from_format_B(self):
        g = Guid.fromFormatB("{fedcba98-1234-abcd-ffff-87ff87acef87}")
        self.assertEqual(g.a, 0xfedcba98)
        self.assertEqual(g.b, 0x1234)
        self.assertEqual(g.c, 0xabcd)
        self.assertEqual(g.d, 0xffff)
        self.assertEqual(g.e, 0x87ff87acef87)

    def test_load_guid_from_format_X(self):
        g = Guid.fromFormatX("{0xfedcba98,0x1234,0xabcd,{0xff,0xff,0x87,0xff,0x87,0xac,0xef,0x87}}")
        self.assertEqual(g.a, 0xfedcba98)
        self.assertEqual(g.b, 0x1234)
        self.assertEqual(g.c, 0xabcd)
        self.assertEqual(g.d, 0xffff)
        self.assertEqual(g.e, 0x87ff87acef87)

    def test_export_guid_to_format_N(self):
        guid_expected = Guid(0xfedcba98, 0x1234, 0xabcd, 0xffff, 0x87ff87acef87)
        self.assertEqual(guid_expected.toFormatN(), "fedcba981234abcdffff87ff87acef87")

    def test_export_guid_to_format_D(self):
        guid_expected = Guid(0xfedcba98, 0x1234, 0xabcd, 0xffff, 0x87ff87acef87)
        self.assertEqual(guid_expected.toFormatD(), "fedcba98-1234-abcd-ffff-87ff87acef87")

    def test_export_guid_to_format_P(self):
        guid_expected = Guid(0xfedcba98, 0x1234, 0xabcd, 0xffff, 0x87ff87acef87)
        self.assertEqual(guid_expected.toFormatP(), "(fedcba98-1234-abcd-ffff-87ff87acef87)")

    def test_export_guid_to_format_B(self):
        guid_expected = Guid(0xfedcba98, 0x1234, 0xabcd, 0xffff, 0x87ff87acef87)
        self.assertEqual(guid_expected.toFormatB(), "{fedcba98-1234-abcd-ffff-87ff87acef87}")

    def test_export_guid_to_format_X(self):
        guid_expected = Guid(0xfedcba98, 0x1234, 0xabcd, 0xffff, 0x87ff87acef87)
        self.assertEqual(guid_expected.toFormatX(), "{0xfedcba98,0x1234,0xabcd,{0xff,0xff,0x87,0xff,0x87,0xac,0xef,0x87}}")

    def test_import_export_involution_format_N(self):
        guid_expected = Guid(0xfedcba98, 0x1234, 0xabcd, 0xffff, 0x87ff87acef87)
        guid_generated = Guid.fromFormatN(guid_expected.toFormatN())
        self.assertEqual(guid_generated.a, guid_expected.a)
        self.assertEqual(guid_generated.b, guid_expected.b)
        self.assertEqual(guid_generated.c, guid_expected.c)
        self.assertEqual(guid_generated.d, guid_expected.d)
        self.assertEqual(guid_generated.e, guid_expected.e)

    def test_import_export_involution_format_D(self):
        guid_expected = Guid(0xfedcba98, 0x1234, 0xabcd, 0xffff, 0x87ff87acef87)
        guid_generated = Guid.fromFormatD(guid_expected.toFormatD())
        self.assertEqual(guid_generated.a, guid_expected.a)
        self.assertEqual(guid_generated.b, guid_expected.b)
        self.assertEqual(guid_generated.c, guid_expected.c)
        self.assertEqual(guid_generated.d, guid_expected.d)
        self.assertEqual(guid_generated.e, guid_expected.e)

    def test_import_export_involution_format_P(self):
        guid_expected = Guid(0xfedcba98, 0x1234, 0xabcd, 0xffff, 0x87ff87acef87)
        guid_generated = Guid.fromFormatP(guid_expected.toFormatP())
        self.assertEqual(guid_generated.a, guid_expected.a)
        self.assertEqual(guid_generated.b, guid_expected.b)
        self.assertEqual(guid_generated.c, guid_expected.c)
        self.assertEqual(guid_generated.d, guid_expected.d)
        self.assertEqual(guid_generated.e, guid_expected.e)

    def test_import_export_involution_format_B(self):
        guid_expected = Guid(0xfedcba98, 0x1234, 0xabcd, 0xffff, 0x87ff87acef87)
        guid_generated = Guid.fromFormatB(guid_expected.toFormatB())
        self.assertEqual(guid_generated.a, guid_expected.a)
        self.assertEqual(guid_generated.b, guid_expected.b)
        self.assertEqual(guid_generated.c, guid_expected.c)
        self.assertEqual(guid_generated.d, guid_expected.d)
        self.assertEqual(guid_generated.e, guid_expected.e)

    def test_import_export_involution_format_X(self):
        guid_expected = Guid(0xfedcba98, 0x1234, 0xabcd, 0xffff, 0x87ff87acef87)
        guid_generated = Guid.fromFormatX(guid_expected.toFormatX())
        self.assertEqual(guid_generated.a, guid_expected.a)
        self.assertEqual(guid_generated.b, guid_expected.b)
        self.assertEqual(guid_generated.c, guid_expected.c)
        self.assertEqual(guid_generated.d, guid_expected.d)
        self.assertEqual(guid_generated.e, guid_expected.e)

    def test_import_export_involution_rawbytes(self):
        guid_expected = Guid(0xfedcba98, 0x1234, 0xabcd, 0xffff, 0x87ff87acef87)
        guid_generated = Guid.fromRawBytes(guid_expected.toRawBytes())
        self.assertEqual(guid_generated.a, guid_expected.a)
        self.assertEqual(guid_generated.b, guid_expected.b)
        self.assertEqual(guid_generated.c, guid_expected.c)
        self.assertEqual(guid_generated.d, guid_expected.d)
        self.assertEqual(guid_generated.e, guid_expected.e)

    def test_random_guid_range_of_values(self):
        g = Guid()

        self.assertGreaterEqual(g.a, 0)
        self.assertLessEqual(g.a, 0x100000000)

        self.assertGreaterEqual(g.b, 0)
        self.assertLessEqual(g.b, 0x10000)

        self.assertGreaterEqual(g.c, 0)
        self.assertLessEqual(g.c, 0x10000)

        self.assertGreaterEqual(g.d, 0)
        self.assertLessEqual(g.d, 0x10000)

        self.assertGreaterEqual(g.e, 0)
        self.assertLessEqual(g.e, 0x1000000000000)

    def test_endianess(self):
        files = [
            "37fb078b-b420-4794-b8d7-c1f707921ecd.raw", "67771cd3-2472-406c-bd20-cc0fff4b65b1.raw", "f5bb4278-5865-42de-92b9-755cad29ad86.raw",
            "5dd44969-fb10-422a-be43-8dddb68afa0e.raw", "9977796b-79a9-45c4-bc04-d856d1051f78.raw", "f6fcf1cf-ceb9-4c7c-8730-0fc1051781ff.raw"
        ]


if __name__ == '__main__':
    unittest.main()
