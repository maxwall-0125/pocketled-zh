# -*- coding: utf-8 -*-
"""纯 Python 的 RSA PKCS#1 v1.5 / SHA-256 签名与校验（2048 位）。"""
import hashlib

SHA256_DIGESTINFO = bytes.fromhex('3031300d060960864801650304020105000420')


def load_key(path=r'C:\Users\maxwall\Desktop\DSH空间\pocketled\key\key.txt'):
    kv = {}
    for line in open(path, encoding='utf-8'):
        line = line.strip()
        if not line:
            continue
        k, v = line.split('=', 1)
        kv[k] = int(v, 16)
    return kv


def _emsa_pkcs1_v15(digest, k):
    t = SHA256_DIGESTINFO + digest
    if k < len(t) + 11:
        raise ValueError('key too small')
    ps = b'\xff' * (k - len(t) - 3)
    return b'\x00\x01' + ps + b'\x00' + t


def sign_sha256(data, key):
    n, d = key['modulus'], key['privateExponent']
    k = (n.bit_length() + 7) // 8
    em = _emsa_pkcs1_v15(hashlib.sha256(data).digest(), k)
    s = pow(int.from_bytes(em, 'big'), d, n)
    return s.to_bytes(k, 'big')


def verify_sha256(data, sig, n, e):
    k = (n.bit_length() + 7) // 8
    if len(sig) != k:
        return False
    m = pow(int.from_bytes(sig, 'big'), e, n)
    em = m.to_bytes(k, 'big')
    return em == _emsa_pkcs1_v15(hashlib.sha256(data).digest(), k)


def selftest():
    key = load_key()
    d = r'C:\Users\maxwall\Desktop\DSH空间\pocketled\key\\'
    msg = open(d + 'test.msg', 'rb').read()
    jsig = open(d + 'test.sig', 'rb').read()
    n, e = key['modulus'], key['publicExponent']
    print('JDK signature verifies:', verify_sha256(msg, jsig, n, e))
    mine = sign_sha256(msg, key)
    print('deterministic match:', mine == jsig)
    print('my signature verifies:', verify_sha256(msg, mine, n, e))


if __name__ == '__main__':
    selftest()
