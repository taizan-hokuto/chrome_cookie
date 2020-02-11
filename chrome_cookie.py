#reference: https://github.com/regen100/browsercookiejar

import os
import sys
import sqlite3
import http.cookiejar as cookiejar
from urllib.parse import urlencode
import json, base64
import aesgcm

'''
To filter by host-name, add below sentence to SQL.

WHERE
    host_key LIKE '%foo-bar-buz.com%'

'''

sql = """
SELECT
    host_key, name, path, is_secure,
    expires_utc,
    encrypted_value as value
FROM
    cookies
"""

def dpapi_decrypt(encrypted):
    import ctypes
    import ctypes.wintypes

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [('cbData', ctypes.wintypes.DWORD),
                    ('pbData', ctypes.POINTER(ctypes.c_char))]
	
    p = ctypes.create_string_buffer(encrypted, len(encrypted))
    blobin = DATA_BLOB(ctypes.sizeof(p), p)
    blobout = DATA_BLOB()
    retval = ctypes.windll.crypt32.CryptUnprotectData(
        ctypes.byref(blobin), None, None, None, None, 0, ctypes.byref(blobout))
    if not retval:
        raise ctypes.WinError()
    result = ctypes.string_at(blobout.pbData, blobout.cbData)
    ctypes.windll.kernel32.LocalFree(blobout.pbData)
    return result


def unix_decrypt(encrypted):
    if sys.platform.startswith('linux'):
        password = 'peanuts'
        iterations = 1
    else:
        raise NotImplementedError

    from Crypto.Cipher import AES
    from Crypto.Protocol.KDF import PBKDF2

    salt = 'saltysalt'
    iv = ' ' * 16
    length = 16
    key = PBKDF2(password, salt, length, iterations)
    cipher = AES.new(key, AES.MODE_CBC, IV=iv)
    decrypted = cipher.decrypt(encrypted[3:])
    return decrypted[:-ord(decrypted[-1])]

def get_key_from_local_state():
    jsn = None
    with open(os.path.join(os.environ['LOCALAPPDATA'],
        r"Google\Chrome\User Data\Local State"),encoding='utf-8',mode ="r") as f:
        jsn = json.loads(str(f.readline()))
    return jsn["os_crypt"]["encrypted_key"]

def aes_decrypt(encrypted):
    encoded_key = (get_key_from_local_state())
    encrypted_key = base64.b64decode(encoded_key.encode())
    #remove prefix 'DPAPI'
    encrypted_key = encrypted_key[5:]
    key = dpapi_decrypt(encrypted_key)
    #get nonce. ignore prefix 'v10', length is 12 bytes.
    nonce = encrypted[3:15]
    cipher = aesgcm.get_cipher(key)
    return aesgcm.decrypt(cipher,encrypted[15:],nonce)

def chrome_decrypt(encrypted):
    if sys.platform == 'win32':
        try:
            if encrypted[:4] == b'\x01\x00\x00\x00':
                return dpapi_decrypt(encrypted).decode()
            elif encrypted[:3] == b'v10':
                return aes_decrypt(encrypted)[:-16].decode()
        except WindowsError:
            return None
    else:
        try:
            return unix_decrypt(encrypted)
        except NotImplementedError:
            return None


def to_epoch(chrome_ts):
    if chrome_ts:
        return chrome_ts - 11644473600 * 000 * 1000
    else:
        return None

class ChromeCookieJar(cookiejar.FileCookieJar):
    def __init__(self, filename=None, delayload=False, policy=None):
        if filename is None:
            if sys.platform == 'win32':
                filename = os.path.join(
                    os.environ['USERPROFILE'],
                    r'AppData\Local\Google\Chrome\User Data\default\Cookies')
                '''
                If you use another account or moved profile folder,
                change above path.
                
                Or your valid userprofile might be saved at: 
                AppData\\Local\\Google\\Chrome\\User Data\\Profile [n]\\Cookies
                '''
            elif sys.platform.startswith('linux'):
                filename = os.path.expanduser(
                    '~/.config/google-chrome/Default/Cookies')
                if not os.path.exists(filename):
                    filename = os.path.expanduser(
                        '~/.config/chromium/Default/Cookies')
            if not os.path.exists(filename):
                filename = None
        cookiejar.FileCookieJar.__init__(self, filename, delayload, policy)

    def _really_load(self, f, filename, ignore_discard, ignore_expires):
        con = sqlite3.connect(filename)
        con.row_factory = sqlite3.Row
        con.create_function('decrypt', 1, chrome_decrypt)
        con.create_function('to_epoch', 1, to_epoch)
        cur = con.cursor()
        cur.execute(sql)
        for row in cur:
            if row['value'] is not None:
                name = row['name']
                value = chrome_decrypt(row['value'])
                host = row['host_key']
                path = row['path']
                is_secure = bool(row['is_secure'])
                expires = to_epoch(row['expires_utc'])
                c = cookiejar.Cookie(
                    0, name, value,
                    None, False,
                    host, bool(host), host.startswith('.'),
                    path, bool(path),
                    is_secure,
                    expires,
                    False,
                    None,
                    None,
                    {})
                self.set_cookie(c)
        cur.close()

