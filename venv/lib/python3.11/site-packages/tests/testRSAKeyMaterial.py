#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          :
# Author             :  Podalirius (@podalirius_)

import unittest
from dsinternals.common.cryptography.RSAKeyMaterial import RSAKeyMaterial


class TestCaseGuid(unittest.TestCase):

    def test_key01(self):
        key = b"""RSA1\x00\x08\x00\x00\x03\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x01\xe3\xda\x8b\xe4\xe4\x8cJ\xce\xfeG\xfe\xcc8\x10z\xa4\x93\xa0:\xcd\'P.\x15h\x85\x06\x11\xf9] \t\x98\xf5\xef" \x95Db\x1b\x95\x1f\x1c\xa4\xd1h\x99}\xd0H\xc9\xc9\xfd\xe4\n\xe3\nk\x84>U\x12\xce\xe3{/\xbe\x16\xf2\x98\x9f\xe74\xc27\xf3\xe54_\x9d\xd8\x04?\xc1\x14\xda\xe0\xfc\x8c\xba\xc7\x89\xe6\xb9\x7f\xbc\x1e\xd27\xe3\x15\xb60\xe2t\xd2\xe0\xf8\xa1\x02\xcc\xfc\xf1\xfeL\xd1\xc7\x15\x9a\xda\xcc\xbf\xae\xf7\xbc\xc5\x1d\xe6\xbd\xd3\xa6\x04\xff\xa9V\x01u\x8bZ\xe8\x19=;\xa3jB\x80\xff}]\xcd\xf5\x85Gt5\xd9?T\xf6\xfd\xe6#\x0e\x8e\xe7\x8d\x9a/\x8a\x16 \rT\xc5\xd8\xf8%\xd5F+\x96\xfa\x80\xef\x92\xccEZ\xb9\xae%\x8d\xd3\xee$\xe5=\xb1\xc0\xdc7\xc0\x02\\\xf6z\xbc\xeeg\xb1m\x10\x00G\x1b\xd5\xd4v\xe9\xfakz\xe3\x1bgz\x89}\xb8\xe8\xf8\x9a{e:\xdd\xfc\xc6\x1a+\xe6\x82.\x196\x93\xe1A*\xd2q\xfc\xb7\x85"""
        rsa = RSAKeyMaterial.fromRawBytes(key)
        self.assertEqual(rsa.exponent, 0x10001)
        self.assertEqual(rsa.modulus, 0xe3da8be4e48c4acefe47fecc38107aa493a03acd27502e1568850611f95d200998f5ef22209544621b951f1ca4d168997dd048c9c9fde40ae30a6b843e5512cee37b2fbe16f2989fe734c237f3e5345f9dd8043fc114dae0fc8cbac789e6b97fbc1ed237e315b630e274d2e0f8a102ccfcf1fe4cd1c7159adaccbfaef7bcc51de6bdd3a604ffa95601758b5ae8193d3ba36a4280ff7d5dcdf585477435d93f54f6fde6230e8ee78d9a2f8a16200d54c5d8f825d5462b96fa80ef92cc455ab9ae258dd3ee24e53db1c0dc37c0025cf67abcee67b16d1000471bd5d476e9fa6b7ae31b677a897db8e8f89a7b653addfcc61a2be6822e193693e1412ad271fcb785)
        self.assertEqual(rsa.prime1, 0)
        self.assertEqual(rsa.prime2, 0)

    def test_key02(self):
        key = b"""RSA1\x00\x08\x00\x00\x03\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x01\x9b\xa9\x0e\x96\xd0\xd5\xd5\xa11H\xdb\xb2\x1a(\x15\x10X\x15V\xb9\x86\xc1\xb0\xeb@Vvh\x1a\x17&0G1\x8a&\x03\r\xf2?9\xaa\xe65\xfe\xa5p{\xd3\x9e\xd1\x94U\x8c\n\xa75\xdf\xef\x14\x00\xdal=R\xab\xb9\x85\xd6a+~D\x1b\x861\xcd\x83\xe0\xefVE`\xbd\xd1\xdd!8%\xee\xa0\xc1H\x98\xb4\x8f\xae\xdc\t\x16<\x1b\xf9\xffnz!SX+\x82\xe1\xd7\xa8+\xb1\xf9;\x1a\x1b?\x9c\xbc\x12\x96\x14\x18\xab0\rX\xf8\x8f\xd0q\xa1T\x06n\x93\x15\xc6]\x14\xb1\xf0p\xb7\xf3\xdc\xac>\x87 \xee\xfe\xeaK\x187fR\xa1\x8e\x8d\x0f{\xe5PW\xe9\xf8H\x8e\xf8K\x1ahj\x9b\xfd5\xa0\x9eQL\xff\xc4\xcd\xc8\\\xb0\xcb\xcdV\xa1<\xdd\xc8V\x8dNd\x1a8\xc2\x99\x96\xfc\xa0\xc1U\xb9&\xba\xd8\xcfy\xa6\xd6;V\xfc\xe6\xc8L\xf3nr\x92\xa5\xed\x97\xc3\x15m\xcc\x1e\xb3\xd5nV\xbb\xc8\xb65Y\xffv\xea\x16wNE\x00\x91"""
        rsa = RSAKeyMaterial.fromRawBytes(key)
        self.assertEqual(rsa.exponent, 0x10001)
        self.assertEqual(rsa.modulus, 0x9ba90e96d0d5d5a13148dbb21a281510581556b986c1b0eb405676681a17263047318a26030df23f39aae635fea5707bd39ed194558c0aa735dfef1400da6c3d52abb985d6612b7e441b8631cd83e0ef564560bdd1dd213825eea0c14898b48faedc09163c1bf9ff6e7a2153582b82e1d7a82bb1f93b1a1b3f9cbc12961418ab300d58f88fd071a154066e9315c65d14b1f070b7f3dcac3e8720eefeea4b18376652a18e8d0f7be55057e9f8488ef84b1a686a9bfd35a09e514cffc4cdc85cb0cbcd56a13cddc8568d4e641a38c29996fca0c155b926bad8cf79a6d63b56fce6c84cf36e7292a5ed97c3156dcc1eb3d56e56bbc8b63559ff76ea16774e450091)
        self.assertEqual(rsa.prime1, 0)
        self.assertEqual(rsa.prime2, 0)

    def test_key03(self):
        key = b"""RSA1\x00\x08\x00\x00\x03\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x01\xc9\xc9\xd8\x83\x98z\x0e\xbd\x0f\x9fc\rl\'\xa3\xa4Li\xb1\xf8{\xd3gyg\xc9\xb6\xd5\n7\xe2\x07^\xa1\xc3E\xaav\xb5\xa8\xb6K\x995\xa4\x90\xcd\xa5\x04\x8b\xc8oU\xa2\x18\xa6P*l\x00 \xd5\xf8\xc67\x02!\xc7\xc0Dt\xddj%\xab\xcft\xe8\xadJ?\xbe\xc9\xfd\xa9\xfa\xad\xd8\xde\xbf\xd3\x91s%\xfc\xc8o`C\x8d\xe6\x99\xd9\xfe\'\xcd#S\xf7\x1b\xca\x1b1\xc2R`\x0ez\xabEE\xef\xc0H\xc7\x98\xff\xb1\x03.@\x91\xf8\x07\xd9\x96\xa9c\xa4$\x02\xa2V\xd0\x86\x1cY\xa0b\t\xfb\xe3\xa2y\xba\n\xa2p52\x90\x7f\x90\x1a\x0e\\\x16\x94\xea.)\xc9yW\xf7\x05J\xf6\x9cB\x1e\xce;\xaf\x07\xc9\x86A\xab\xcf\x91d|7\xc6\xedgl\xcf\xb7\xae:\xd6\xf3\xc7X;\x83\xb6\xb9}\xcf\x13\xba{\xf2\xd4"S-\xf33N\xfa!\xd67J\x86&\xb9\x1d\x85\xda\x91*\x06\xb8%\x06\xaf\xa8\xc9\x12\x1c\xe0\xa1\xd5\x9cP\xfb\xad(\x8cP\xb5"""
        rsa = RSAKeyMaterial.fromRawBytes(key)
        self.assertEqual(rsa.exponent, 0x10001)
        self.assertEqual(rsa.modulus, 0xc9c9d883987a0ebd0f9f630d6c27a3a44c69b1f87bd3677967c9b6d50a37e2075ea1c345aa76b5a8b64b9935a490cda5048bc86f55a218a6502a6c0020d5f8c6370221c7c04474dd6a25abcf74e8ad4a3fbec9fda9faadd8debfd3917325fcc86f60438de699d9fe27cd2353f71bca1b31c252600e7aab4545efc048c798ffb1032e4091f807d996a963a42402a256d0861c59a06209fbe3a279ba0aa2703532907f901a0e5c1694ea2e29c97957f7054af69c421ece3baf07c98641abcf91647c37c6ed676ccfb7ae3ad6f3c7583b83b6b97dcf13ba7bf2d422532df3334efa21d6374a8626b91d85da912a06b82506afa8c9121ce0a1d59c50fbad288c50b5)
        self.assertEqual(rsa.prime1, 0)
        self.assertEqual(rsa.prime2, 0)

    def test_key04(self):
        key = b"""RSA1\x00\x08\x00\x00\x03\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x01\xc9\x93gZ\xcc\x10\x0cdw\x00\x13\xd9v\xde\x1513j\xb5xW\xe5j\x8f\x02$\x82:Kb\x01X\x8au\xc748\x0c\'\x13#\x99j\x8be1\xaf\xbe\x8e\xf7\xfe5|\xcdq\x1f\xda\xbdI~\x87\xd4|\xe8JF\xf2\xed\\\xe3\xd0t<\xd3T\x92F\xe9\x15r\x83\x85\xa4\xa0\xca\xd0%\t\xd1\xfe\xa4N\x06\xfc\xc5\xe9\xe0C1;\x1bj\xc5\x10\x11#\x9f\x18\xa5[Kk\xcd\x7fm\xb3\x06\x12a(\xf2\xd0\x01~h\xf1Q\xce\x15\xb6\x13\x9f\xb82m?\x92pl\xcfv\x10\xd9\x08a\x18\x08\x1a\xd7fK\xd6(\xda\xa3<\xdd\xe1k\xb21\x80\x92({\xb0\xebHA5\xc4K\xac2\x9d\xbcM\xa47Tw\x02\xf8\xeb\xf2n3\x8a\x92r\x8f\x00\xa9i\xaaF\xb8\x90\xfb\xcbBm\x91\x18X,\x1a6W\xf6_\x9a\xb4\xf2,x\x1bdC\x18\xfe\x97\x98`\xfa\xc1\x1b\x08Z\xe6\xba;\xa0\xff\x07\x04*\xa0p\x87\x0ft\xad\xa2\xd1\xf9\xbd\xca"\x8a\xe7\xe5\xaa\xf7\xbeI"""
        rsa = RSAKeyMaterial.fromRawBytes(key)
        self.assertEqual(rsa.exponent, 0x10001)
        self.assertEqual(rsa.modulus, 0xc993675acc100c64770013d976de1531336ab57857e56a8f0224823a4b6201588a75c734380c271323996a8b6531afbe8ef7fe357ccd711fdabd497e87d47ce84a46f2ed5ce3d0743cd3549246e915728385a4a0cad02509d1fea44e06fcc5e9e043313b1b6ac51011239f18a55b4b6bcd7f6db306126128f2d0017e68f151ce15b6139fb8326d3f92706ccf7610d9086118081ad7664bd628daa33cdde16bb2318092287bb0eb484135c44bac329dbc4da437547702f8ebf26e338a92728f00a969aa46b890fbcb426d9118582c1a3657f65f9ab4f22c781b644318fe979860fac11b085ae6ba3ba0ff07042aa070870f74ada2d1f9bdca228ae7e5aaf7be49)
        self.assertEqual(rsa.prime1, 0)
        self.assertEqual(rsa.prime2, 0)

    def test_key05(self):
        key = b"""RSA1\x00\x08\x00\x00\x03\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x01\xb0\x94\xa2\x83.\xa0>\xa7\xfa\x17\xef\xad\xca\x95\xe9D\xf2P\t87\xfdV2\x05M%\xe1\'{\xfaf\xffB\x13\xc6\x87\x84\x82\x10\xd7D\xed\xfc6\xc1\xfak\x9eV\x1f\xf8\xe9&x\xc6\x04/1@\\\xc1\xc5\xba\xbe\x00\x11\x04\x9c\xbd\x91\x91\xe4\x19o\xd1n\xbbE*\xfa\x90\xb2\xc4\x1ctTCe-\xca%\xdd\xe3;\xfeQ5\\\x11>\xba=\xbc\x01\x1a\x97;&b \x05\x11\xa50L\xfd\xec\xbe\xb7\xac\xb0I\xee\r\x9e\xca\xf3\xbf\xaa\x7f\x08\xd4}8\x17\xd7Gm\xec\xb4\'\xe3\x04\xe3(b)6\'\x91&8=\xfcT\xb6o\xd0\xd9d\x86\xf8y\\\x11\xc2\x8a\xc1\xc9\xd5\xdee\xcf\x87wzq&~\xbb\xcf\xc76\xbc\x95\xdf\x18mPl\xd6\x9d9\xe4\xff\xf0\xf7\xe4\xef\x11\x1d\xcdF_}TG\x06\x02G_he\xa4\\\xa9_\xfa\xee7Lr=%"\x94\xda\xc5`TL{\xa9\xeb\x9c\xfc\xb8\xb3=\xa7\x9549\x96\x95m)\x80&\x8d1\xae\xac\xbf\xb9"""
        rsa = RSAKeyMaterial.fromRawBytes(key)
        self.assertEqual(rsa.exponent, 0x10001)
        self.assertEqual(rsa.modulus, 0xb094a2832ea03ea7fa17efadca95e944f250093837fd5632054d25e1277bfa66ff4213c687848210d744edfc36c1fa6b9e561ff8e92678c6042f31405cc1c5babe0011049cbd9191e4196fd16ebb452afa90b2c41c745443652dca25dde33bfe51355c113eba3dbc011a973b2662200511a5304cfdecbeb7acb049ee0d9ecaf3bfaa7f08d47d3817d7476decb427e304e328622936279126383dfc54b66fd0d96486f8795c11c28ac1c9d5de65cf87777a71267ebbcfc736bc95df186d506cd69d39e4fff0f7e4ef111dcd465f7d54470602475f6865a45ca95ffaee374c723d252294dac560544c7ba9eb9cfcb8b33da795343996956d2980268d31aeacbfb9)
        self.assertEqual(rsa.prime1, 0)
        self.assertEqual(rsa.prime2, 0)

    def test_key06(self):
        key = b"""RSA1\x00\x08\x00\x00\x03\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x01\xab\x1d\xd0\x7fQ\xf7\\xss\x18\xa8@+n'\\\xe1\x12\xaa\xf3\x96L\xbc\xee\x16\x06\x08\x18;\xd3\x99\xca\xfe=\xce\x1c\xf3\xa2\xe6\r\x1b\x8c\xfb\xdbp\xff\xd3\xd2\x9c\x0fo\xfa\xa5C\xdbJZ\xf7Q\x82S2\x00\xf46\xe6Q\xb4\x7f\xc1\xfb\x00\xc9{\xa13u\x16\xd2\x14\xde\x97D\x11\xcdn\xc7\xa0\xf0O\x88Z\xd51\x80\xc3\xa4\x03\x9d\xd3Z\ro\xda\xbf\x03\xd2\x94\x03\x9dB\xf8\xb7\x88Fz\x1f\xe2\xd8\r\x85v\xa5\x99\xf1\xf2}\x1c,\xa1\xce\x1e,=(\n\xee?\xd4\x9d\xb9O\xf6\x82H\xb7\x14\x0b\x91\xa8g\xdf\x02\x933\x8ett|\xa1370\x9f\x0c\xa0\x19\xcf\xc4Q\xc2\x04\xd5]\x84\x84V\xa3\xc6\r\x815\x882\x1e\x0e[Z\xf2\x00\xb7\xe8\x8b\x9d\x8c\xf9\xfe3s\xa5\x9e\xd6\x04A\xc8\xb0l\xaa\r\xc3\x9b\x1d/\x8e.\xef \xa6\xf7\x9f\xd5\x16\x80!\xaaa\x1b\xea\x077\xfda\xd83\xdb\x92\xec\r\x037\xfa\xc0\xa6\x88S\x1cZX\x8d^K\xefK\xdf\xbd"""
        rsa = RSAKeyMaterial.fromRawBytes(key)
        self.assertEqual(rsa.exponent, 0x10001)
        self.assertEqual(rsa.modulus, 0xab1dd07f51f75c78737318a8402b6e275ce112aaf3964cbcee160608183bd399cafe3dce1cf3a2e60d1b8cfbdb70ffd3d29c0f6ffaa543db4a5af75182533200f436e651b47fc1fb00c97ba1337516d214de974411cd6ec7a0f04f885ad53180c3a4039dd35a0d6fdabf03d294039d42f8b788467a1fe2d80d8576a599f1f27d1c2ca1ce1e2c3d280aee3fd49db94ff68248b7140b91a867df0293338e74747ca13337309f0ca019cfc451c204d55d848456a3c60d813588321e0e5b5af200b7e88b9d8cf9fe3373a59ed60441c8b06caa0dc39b1d2f8e2eef20a6f79fd5168021aa611bea0737fd61d833db92ec0d0337fac0a688531c5a588d5e4bef4bdfbd)
        self.assertEqual(rsa.prime1, 0)
        self.assertEqual(rsa.prime2, 0)

    def test_key07(self):
        key = b"""RSA1\x00\x08\x00\x00\x03\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x01\xbc\x880\xba\xb8\xe0\x9b\xf8\x12en\x00\xfa~\xebM\x83\xcfq\x0e\xb0r\xc4\xf1\x9fT\x057\xcdQug S{\xfd\x15r8\xe9%g\xb6\x8dh\xadT\x87X2O\xba\x1f\xde\xe0\xaa\x08\xd3\xed\x99c\xd0>\xf9\xbbK\xb8\xcb\x91X\xd7\xaav\x7fk\xcfR\x91+\xdd\x7f\xa5\xc4\xd3\xed\xba\xb4\x81\x88]\xc9\xf0\xf4l\x1a\xf7\x95T\x12\x8c\x108i\xda\xfa\x08G"\x9fYT:/\x8a\xea\xf58\xf3\x0cV4\xc1\xb6\xc8\x7f\x9f\x8c\xcd.y$\x15\x03\xc7uM#\xe6m\xa6\xba\xf9|\xbd;\xd4\xb7\x96M_\xb7\xea\xfe\xa7\x0b\x8b\xb1\xaf\x9d\xb7s\x19\xf6\xf9\xcf\x0e\xeb\xe1j\xf8x\xa1\x03\x8b\xf7\\\xbcs\xb2\xe2\rJ\x9fH\xd6B6\x92\x1d\x99y$\xddY\xe8\x95\x1f\x9fk:\x81<\xefx\xd8\xd3\x86\xcd\x9f\xe1pN\nD\xf8\x8f^\x90&\\\x07\xf0s1C\xe1s\xcb\xd4\x16^\x89\x0f;\x8a\xc53\xbf\n\x8b\xeb\xe6e`\xbd\xb9\x96\xc4\x08G*3\xc9\xe2\xf8q"""
        rsa = RSAKeyMaterial.fromRawBytes(key)
        self.assertEqual(rsa.exponent, 0x10001)
        self.assertEqual(rsa.modulus, 0xbc8830bab8e09bf812656e00fa7eeb4d83cf710eb072c4f19f540537cd51756720537bfd157238e92567b68d68ad548758324fba1fdee0aa08d3ed9963d03ef9bb4bb8cb9158d7aa767f6bcf52912bdd7fa5c4d3edbab481885dc9f0f46c1af79554128c103869dafa0847229f59543a2f8aeaf538f30c5634c1b6c87f9f8ccd2e79241503c7754d23e66da6baf97cbd3bd4b7964d5fb7eafea70b8bb1af9db77319f6f9cf0eebe16af878a1038bf75cbc73b2e20d4a9f48d64236921d997924dd59e8951f9f6b3a813cef78d8d386cd9fe1704e0a44f88f5e90265c07f0733143e173cbd4165e890f3b8ac533bf0a8bebe66560bdb996c408472a33c9e2f871)
        self.assertEqual(rsa.prime1, 0)
        self.assertEqual(rsa.prime2, 0)

    def test_import_export_involution(self):
        rsa1 = RSAKeyMaterial(
            0xbc8830bab8e09bf812656e00fa7eeb4d83cf710eb072c4f19f540537cd51756720537bfd157238e92567b68d68ad548758324fba1fdee0aa08d3ed9963d03ef9bb4bb8cb9158d7aa767f6bcf52912bdd7fa5c4d3edbab481885dc9f0f46c1af79554128c103869dafa0847229f59543a2f8aeaf538f30c5634c1b6c87f9f8ccd2e79241503c7754d23e66da6baf97cbd3bd4b7964d5fb7eafea70b8bb1af9db77319f6f9cf0eebe16af878a1038bf75cbc73b2e20d4a9f48d64236921d997924dd59e8951f9f6b3a813cef78d8d386cd9fe1704e0a44f88f5e90265c07f0733143e173cbd4165e890f3b8ac533bf0a8bebe66560bdb996c408472a33c9e2f871,
            0x10001,
            0,
            0
        )
        rsa2 = RSAKeyMaterial.fromRawBytes(rsa1.toRawBytes())
        self.assertEqual(rsa2.exponent, 0x10001)
        self.assertEqual(rsa2.modulus, 0xbc8830bab8e09bf812656e00fa7eeb4d83cf710eb072c4f19f540537cd51756720537bfd157238e92567b68d68ad548758324fba1fdee0aa08d3ed9963d03ef9bb4bb8cb9158d7aa767f6bcf52912bdd7fa5c4d3edbab481885dc9f0f46c1af79554128c103869dafa0847229f59543a2f8aeaf538f30c5634c1b6c87f9f8ccd2e79241503c7754d23e66da6baf97cbd3bd4b7964d5fb7eafea70b8bb1af9db77319f6f9cf0eebe16af878a1038bf75cbc73b2e20d4a9f48d64236921d997924dd59e8951f9f6b3a813cef78d8d386cd9fe1704e0a44f88f5e90265c07f0733143e173cbd4165e890f3b8ac533bf0a8bebe66560bdb996c408472a33c9e2f871)
        self.assertEqual(rsa2.prime1, 0)
        self.assertEqual(rsa2.prime2, 0)


if __name__ == '__main__':
    unittest.main()
