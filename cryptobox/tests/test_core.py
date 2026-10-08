import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptobox.core import hashes
from cryptobox.core import md5 as md5_mod
from cryptobox.core import sha1 as sha1_mod
from cryptobox.core import sha256 as sha256_mod
from cryptobox.core import des as des_mod
from cryptobox.core import aes as aes_mod
from cryptobox.core import hill
from cryptobox.core.hmac_sha256 import hmac_sha256
from cryptobox.core.pbkdf2 import pbkdf2_hmac_sha256
from cryptobox.core import symmetric
from cryptobox.core import rsa
from cryptobox import crack


class TestHashes(unittest.TestCase):
    def test_md5(self):
        self.assertEqual(md5_mod.md5_hex(b""), "d41d8cd98f00b204e9800998ecf8427e")
        self.assertEqual(md5_mod.md5_hex(b"abc"), "900150983cd24fb0d6963f7d28e17f72")
        self.assertEqual(md5_mod.md5_hex(b"message digest"),
                         "f96b697d7cb7938d525a2f31aaf161d0")
        self.assertEqual(
            md5_mod.md5_hex(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"),
            "d174ab98d277d9f5a5611c2c9f419d9f")

    def test_sha1(self):
        self.assertEqual(sha1_mod.sha1_hex(b""), "da39a3ee5e6b4b0d3255bfef95601890afd80709")
        self.assertEqual(sha1_mod.sha1_hex(b"abc"),
                         "a9993e364706816aba3e25717850c26c9cd0d89d")
        self.assertEqual(SHA1_LONG,
                         sha1_mod.sha1_hex(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"))

    def test_sha256(self):
        self.assertEqual(sha256_mod.sha256_hex(b""),
                         "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        self.assertEqual(sha256_mod.sha256_hex(b"abc"),
                         "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        self.assertEqual(
            sha256_mod.sha256_hex(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1")

    def test_registry(self):
        self.assertEqual(hashes.digest_hex("MD5", b"abc"),
                         "900150983cd24fb0d6963f7d28e17f72")
        with self.assertRaises(ValueError):
            hashes.digest("NOPE", b"x")


SHA1_LONG = "84983e441c3bd26ebaae4aa1f95129e5e54670f1"


class TestDES(unittest.TestCase):
    def test_known_vector(self):
        key = bytes.fromhex("133457799BBCDFF1")
        plain = bytes.fromhex("0123456789ABCDEF")
        cipher = des_mod.des_encrypt_block(key, plain)
        self.assertEqual(cipher.hex().upper(), "85E813540F0AB405")
        self.assertEqual(des_mod.des_decrypt_block(key, cipher), plain)

    def test_cbc_roundtrip(self):
        key = b"8bytekey"
        iv = b"initvec!"
        data = b"the quick brown fox"
        blob = des_mod.des_encrypt(key, data, iv)
        self.assertEqual(des_mod.des_decrypt(key, blob, iv), data)

    def test_3des_roundtrip(self):
        key = bytes(range(24))
        iv = b"12345678"
        data = b"triple des secret"
        blob = des_mod.tdes_encrypt(key, data, iv)
        self.assertEqual(des_mod.tdes_decrypt(key, blob, iv), data)


class TestAES(unittest.TestCase):
    def test_known_vectors(self):
        plain = bytes.fromhex("00112233445566778899aabbccddeeff")
        key128 = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        self.assertEqual(aes_mod.aes_encrypt_block(key128, plain).hex(),
                         "69c4e0d86a7b0430d8cdb78070b4c55a")
        key192 = bytes.fromhex("000102030405060708090a0b0c0d0e0f1011121314151617")
        self.assertEqual(aes_mod.aes_encrypt_block(key192, plain).hex(),
                         "dda97ca4864cdfe06eaf70a0ec0d7191")
        key256 = bytes.fromhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
        self.assertEqual(aes_mod.aes_encrypt_block(key256, plain).hex(),
                         "8ea2b7ca516745bfeafc49904b496089")

    def test_block_inverse(self):
        key = bytes(range(16))
        block = bytes(range(16))
        self.assertEqual(aes_mod.aes_decrypt_block(key, aes_mod.aes_encrypt_block(key, block)), block)

    def test_modes_roundtrip(self):
        key = bytes(range(32))
        data = b"hello aes mode test " * 4
        iv = bytes(16)
        self.assertEqual(aes_mod.aes_cbc_decrypt(key, aes_mod.aes_cbc_encrypt(key, data, iv), iv), data)
        nonce = bytes(16)
        ct = aes_mod.aes_ctr_crypt(key, data, nonce)
        self.assertEqual(aes_mod.aes_ctr_crypt(key, ct, nonce), data)


class TestHMACPBKDF2(unittest.TestCase):
    def test_hmac_rfc4231(self):
        key = b"\x0b" * 20
        self.assertEqual(hmac_sha256(key, b"Hi There").hex(),
                         "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")

    def test_pbkdf2(self):
        self.assertEqual(pbkdf2_hmac_sha256("password", b"salt", 1, 32).hex(),
                         "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b")
        self.assertEqual(pbkdf2_hmac_sha256("password", b"salt", 2, 32).hex(),
                         "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43")
        self.assertEqual(pbkdf2_hmac_sha256("password", b"salt", 4096, 32).hex(),
                         "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a")


class TestHill(unittest.TestCase):
    def test_known_vector(self):
        key = [[6, 24, 1], [13, 16, 10], [20, 17, 15]]
        self.assertEqual(hill.encrypt("ACT", key), "POH")
        self.assertEqual(hill.decrypt("POH", key), "ACT")

    def test_roundtrip(self):
        key = hill.random_key(2)
        message = "THEQUICKBROWNFO"
        self.assertEqual(hill.decrypt(hill.encrypt(message, key), key), message)

    def test_parse_invalid(self):
        with self.assertRaises(ValueError):
            hill.parse_key("2 4 2 4")


class TestSymmetric(unittest.TestCase):
    def test_aes_roundtrip(self):
        data = "机密数据 secret data".encode("utf-8")
        for mode in ("CTR", "CBC"):
            blob = symmetric.encrypt_aes("passphrase", data, mode=mode)
            self.assertEqual(symmetric.decrypt_aes("passphrase", blob, mode=mode), data)

    def test_aes_wrong_password(self):
        blob = symmetric.encrypt_aes("right", b"data")
        with self.assertRaises(ValueError):
            symmetric.decrypt_aes("wrong", blob)

    def test_des_roundtrip(self):
        data = b"legacy des data"
        self.assertEqual(symmetric.decrypt_des("pw", symmetric.encrypt_des("pw", data)), data)
        self.assertEqual(symmetric.decrypt_3des("pw", symmetric.encrypt_3des("pw", data)), data)


class TestRSA(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = rsa.generate_keypair(1024)
        cls.public = (cls.key.n, cls.key.e)

    def test_oaep(self):
        msg = b"hello rsa"
        ct = rsa.oaep_encrypt(self.public, msg)
        self.assertEqual(rsa.oaep_decrypt(self.key, ct), msg)

    def test_pkcs1v15(self):
        msg = b"hello rsa v1.5"
        ct = rsa.pkcs1v15_encrypt(self.public, msg)
        self.assertEqual(rsa.pkcs1v15_decrypt(self.key, ct), msg)

    def test_sign_verify(self):
        msg = b"sign me"
        sig = rsa.sign(self.key, msg)
        self.assertTrue(rsa.verify(self.public, msg, sig))
        self.assertFalse(rsa.verify(self.public, b"other", sig))

    def test_serialization(self):
        pub_text = rsa.format_public(self.public)
        self.assertEqual(rsa.parse_public(pub_text), self.public)
        priv_text = rsa.format_private(self.key)
        self.assertEqual(rsa.parse_private(priv_text).d, self.key.d)


class TestCrack(unittest.TestCase):
    def test_dictionary(self):
        target = hashes.digest_hex("MD5", b"password")
        result = crack.crack_dictionary("MD5", target, crack.default_wordlist())
        self.assertTrue(result["found"])
        self.assertEqual(result["plaintext"], "password")

    def test_brute_force(self):
        target = hashes.digest_hex("SHA1", b"abc")
        result = crack.crack_brute_force("SHA1", target, "abc", 1, 3)
        self.assertTrue(result["found"])
        self.assertEqual(result["plaintext"], "abc")

    def test_salt(self):
        target = hashes.digest_hex("MD5", b"secret#salt")
        result = crack.crack_dictionary("MD5", target, ["nope", "secret"], salt="#salt")
        self.assertTrue(result["found"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
