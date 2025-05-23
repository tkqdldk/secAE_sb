import sys

_pythonMajorVersion = sys.version_info[0]

ECB = 0
CBC = 1

PAD_NORMAL = 1
PAD_PKCS5 = 2

class _baseDes(object):
    def __init__(self, mode=ECB, IV=None, pad=None, padmode=PAD_NORMAL):
        if IV:
            IV = self._guardAgainstUnicode(IV)
        if pad:
            pad = self._guardAgainstUnicode(pad)
        self.block_size = 8
        if pad and padmode == PAD_PKCS5:
            raise ValueError("Cannot use a pad character with PAD_PKCS5")
        if IV and len(IV) != self.block_size:
            raise ValueError("Invalid Initial Value (IV), must be a multiple of " + str(self.block_size) + " bytes")
        self._mode = mode
        self._iv = IV
        self._padding = pad
        self._padmode = padmode

    def getKey(self):
        return self.__key

    def setKey(self, key):
        key = self._guardAgainstUnicode(key)
        self.__key = key

    def getMode(self):
        return self._mode

    def setMode(self, mode):
        self._mode = mode

    def getPadding(self):
        return self._padding

    def setPadding(self, pad):
        if pad is not None:
            pad = self._guardAgainstUnicode(pad)
        self._padding = pad

    def getPadMode(self):
        return self._padmode
        
    def setPadMode(self, mode):
        self._padmode = mode

    def getIV(self):
        return self._iv

    def setIV(self, IV):
        if not IV or len(IV) != self.block_size:
            raise ValueError("Invalid Initial Value (IV), must be a multiple of " + str(self.block_size) + " bytes")
        IV = self._guardAgainstUnicode(IV)
        self._iv = IV

    def _padData(self, data, pad, padmode):
        if padmode is None:
            padmode = self.getPadMode()
        if pad and padmode == PAD_PKCS5:
            raise ValueError("Cannot use a pad character with PAD_PKCS5")

        if padmode == PAD_NORMAL:
            if len(data) % self.block_size == 0:
                return data
            if not pad:
                pad = self.getPadding()
            if not pad:
                raise ValueError("Data must be a multiple of " + str(self.block_size) + " bytes in length. Use padmode=PAD_PKCS5 or set the pad character.")
            data += (self.block_size - (len(data) % self.block_size)) * pad
        
        elif padmode == PAD_PKCS5:
            pad_len = 8 - (len(data) % self.block_size)
            if _pythonMajorVersion < 3:
                data += pad_len * chr(pad_len)
            else:
                data += bytes([pad_len] * pad_len)

        return data

    def _unpadData(self, data, pad, padmode):
        if not data:
            return data
        if pad and padmode == PAD_PKCS5:
            raise ValueError("Cannot use a pad character with PAD_PKCS5")
        if padmode is None:
            padmode = self.getPadMode()

        if padmode == PAD_NORMAL:
            if not pad:
                pad = self.getPadding()
            if pad:
                data = data[:-self.block_size] + data[-self.block_size:].rstrip(pad)

        elif padmode == PAD_PKCS5:
            if _pythonMajorVersion < 3:
                pad_len = ord(data[-1])
            else:
                pad_len = data[-1]
            data = data[:-pad_len]

        return data

    def _guardAgainstUnicode(self, data):
        if _pythonMajorVersion < 3:
            if isinstance(data, unicode):
                raise ValueError("pyDes can only work with bytes, not Unicode strings.")
        else:
            if isinstance(data, str):
                try:
                    return data.encode('ascii')
                except UnicodeEncodeError:
                    pass
                raise ValueError("pyDes can only work with encoded strings, not Unicode.")
        return data

class des(_baseDes):
    __pc1 = [56, 48, 40, 32, 24, 16,  8, 0, 57, 49, 41, 33, 25, 17, 9,  1, 58, 50, 42, 34, 26, 18, 10,  2, 59, 51, 43, 35, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21, 13,  5, 60, 52, 44, 36, 28, 20, 12,  4, 27, 19, 11,  3]
    __left_rotations = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]
    __pc2 = [13, 16, 10, 23,  0,  4, 2, 27, 14,  5, 20,  9, 22, 18, 11,  3, 25,  7, 15,  6, 26, 19, 12,  1, 40, 51, 30, 36, 46, 54, 29, 39, 50, 44, 32, 47, 43, 48, 38, 55, 33, 52, 45, 41, 49, 35, 28, 31]
    __ip = [57, 49, 41, 33, 25, 17, 9,  1, 59, 51, 43, 35, 27, 19, 11, 3, 61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7, 56, 48, 40, 32, 24, 16, 8,  0, 58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6]
    __expansion_table = [31,  0,  1,  2,  3,  4, 3,  4,  5,  6,  7,  8, 7,  8,  9, 10, 11, 12, 11, 12, 13, 14, 15, 16, 15, 16, 17, 18, 19, 20, 19, 20, 21, 22, 23, 24, 23, 24, 25, 26, 27, 28, 27, 28, 29, 30, 31,  0]
    __sbox = [
        [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7, 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8, 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0, 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],
        [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10, 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5, 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15, 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],
        [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8, 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1, 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7, 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],
        [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15, 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9, 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4, 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],
        [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9, 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6, 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14, 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],
        [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11, 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8, 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6, 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],
        [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1, 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6, 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2, 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],
        [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7, 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2, 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8, 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
    ]
    __p = [15, 6, 19, 20, 28, 11, 27, 16, 0, 14, 22, 25, 4, 17, 30, 9, 1, 7, 23,13, 31, 26, 2, 8, 18, 12, 29, 5, 21, 10, 3, 24]
    __fp = [39,  7, 47, 15, 55, 23, 63, 31, 38,  6, 46, 14, 54, 22, 62, 30, 37,  5, 45, 13, 53, 21, 61, 29, 36,  4, 44, 12, 52, 20, 60, 28, 35,  3, 43, 11, 51, 19, 59, 27, 34,  2, 42, 10, 50, 18, 58, 26, 33,  1, 41,  9, 49, 17, 57, 25, 32,  0, 40,  8, 48, 16, 56, 24]

    ENCRYPT = 0x00
    DECRYPT = 0x01

    def __init__(self, key, mode=ECB, IV=None, pad=None, padmode=PAD_NORMAL):
        if len(key) != 8:
            raise ValueError("Invalid DES key size. Key must be exactly 8 bytes long.")
        _baseDes.__init__(self, mode, IV, pad, padmode)
        self.key_size = 8
        self.L = []
        self.R = []
        self.Kn = [ [0] * 48 ] * 16
        self.final = []
        self.setKey(key)

    def setKey(self, key):
        _baseDes.setKey(self, key)
        self.__create_sub_keys()

    def __String_to_BitList(self, data):
        if _pythonMajorVersion < 3:
            data = [ord(c) for c in data]
        l = len(data) * 8
        result = [0] * l
        pos = 0
        for ch in data:
            i = 7
            while i >= 0:
                if ch & (1 << i) != 0:
                    result[pos] = 1
                else:
                    result[pos] = 0
                pos += 1
                i -= 1
        return result

    def __BitList_to_String(self, data):
        result = []
        pos = 0
        c = 0
        while pos < len(data):
            c += data[pos] << (7 - (pos % 8))
            if (pos % 8) == 7:
                result.append(c)
                c = 0
            pos += 1
        if _pythonMajorVersion < 3:
            return ''.join([ chr(c) for c in result ])
        else:
            return bytes(result)

    def __permutate(self, table, block):
        return list(map(lambda x: block[x], table))
    
    def __create_sub_keys(self):
        key = self.__permutate(des.__pc1, self.__String_to_BitList(self.getKey()))
        i = 0
        self.L = key[:28]
        self.R = key[28:]
        while i < 16:
            j = 0
            while j < des.__left_rotations[i]:
                self.L.append(self.L[0])
                del self.L[0]
                self.R.append(self.R[0])
                del self.R[0]
                j += 1
            self.Kn[i] = self.__permutate(des.__pc2, self.L + self.R)
            i += 1

    def __des_crypt(self, block, crypt_type):
        block = self.__permutate(des.__ip, block)
        self.L = block[:32]
        self.R = block[32:]

        if crypt_type == des.ENCRYPT:
            iteration = 0
            iteration_adjustment = 1
        else:
            iteration = 15
            iteration_adjustment = -1

        i = 0
        while i < 16:
            tempR = self.R[:]
            self.R = self.__permutate(des.__expansion_table, self.R)
            self.R = list(map(lambda x, y: x ^ y, self.R, self.Kn[iteration]))
            B = [self.R[:6], self.R[6:12], self.R[12:18], self.R[18:24], self.R[24:30], self.R[30:36], self.R[36:42], self.R[42:]]
            j = 0
            Bn = [0] * 32
            pos = 0
            while j < 8:
                m = (B[j][0] << 1) + B[j][5]
                n = (B[j][1] << 3) + (B[j][2] << 2) + (B[j][3] << 1) + B[j][4]
                v = des.__sbox[j][(m << 4) + n]
                Bn[pos] = (v & 8) >> 3
                Bn[pos + 1] = (v & 4) >> 2
                Bn[pos + 2] = (v & 2) >> 1
                Bn[pos + 3] = v & 1
                pos += 4
                j += 1
            self.R = self.__permutate(des.__p, Bn)
            self.R = list(map(lambda x, y: x ^ y, self.R, self.L))
            self.L = tempR
            i += 1
            iteration += iteration_adjustment
        
        self.final = self.__permutate(des.__fp, self.R + self.L)
        return self.final

    def crypt(self, data, crypt_type):
        if not data:
            return ''
        if len(data) % self.block_size != 0:
            if crypt_type == des.DECRYPT:
                raise ValueError("Invalid data length, data must be a multiple of " + str(self.block_size) + " bytes\n.")
            if not self.getPadding():
                raise ValueError("Invalid data length, data must be a multiple of " + str(self.block_size) + " bytes\n. Try setting the optional padding character")
            else:
                data += (self.block_size - (len(data) % self.block_size)) * self.getPadding()

        if self.getMode() == CBC:
            if self.getIV():
                iv = self.__String_to_BitList(self.getIV())
            else:
                raise ValueError("For CBC mode, you must supply the Initial Value (IV) for ciphering")

        i = 0
        dict = {}
        result = []
        while i < len(data):
            block = self.__String_to_BitList(data[i:i+8])
            if self.getMode() == CBC:
                if crypt_type == des.ENCRYPT:
                    block = list(map(lambda x, y: x ^ y, block, iv))
                processed_block = self.__des_crypt(block, crypt_type)
                if crypt_type == des.DECRYPT:
                    processed_block = list(map(lambda x, y: x ^ y, processed_block, iv))
                    iv = block
                else:
                    iv = processed_block
            else:
                processed_block = self.__des_crypt(block, crypt_type)
            result.append(self.__BitList_to_String(processed_block))
            i += 8

        if _pythonMajorVersion < 3:
            return ''.join(result)
        else:
            return bytes.fromhex('').join(result)

    def encrypt(self, data, pad=None, padmode=None):
        data = self._guardAgainstUnicode(data)
        if pad is not None:
            pad = self._guardAgainstUnicode(pad)
        data = self._padData(data, pad, padmode)
        return self.crypt(data, des.ENCRYPT)

    def decrypt(self, data, pad=None, padmode=None):
        data = self._guardAgainstUnicode(data)
        if pad is not None:
            pad = self._guardAgainstUnicode(pad)
        data = self.crypt(data, des.DECRYPT)
        return self._unpadData(data, pad, padmode)

class triple_des(_baseDes):
    def __init__(self, key, mode=ECB, IV=None, pad=None, padmode=PAD_NORMAL):
        _baseDes.__init__(self, mode, IV, pad, padmode)
        self.setKey(key)

    def setKey(self, key):
        self.key_size = 24
        if len(key) != self.key_size:
            if len(key) == 16:
                self.key_size = 16
            else:
                raise ValueError("Invalid triple DES key size. Key must be either 16 or 24 bytes long")
        if self.getMode() == CBC:
            if not self.getIV():
                self._iv = key[:self.block_size]
            if len(self.getIV()) != self.block_size:
                raise ValueError("Invalid IV, must be 8 bytes in length")
        self.__key1 = des(key[:8], self._mode, self._iv, self._padding, self._padmode)
        self.__key2 = des(key[8:16], self._mode, self._iv, self._padding, self._padmode)
        if self.key_size == 16:
            self.__key3 = self.__key1
        else:
            self.__key3 = des(key[16:], self._mode, self._iv, self._padding, self._padmode)
        _baseDes.setKey(self, key)

    def setMode(self, mode):
        _baseDes.setMode(self, mode)
        for key in (self.__key1, self.__key2, self.__key3):
            key.setMode(mode)

    def setPadding(self, pad):
        _baseDes.setPadding(self, pad)
        for key in (self.__key1, self.__key2, self.__key3):
            key.setPadding(pad)

    def setPadMode(self, mode):
        _baseDes.setPadMode(self, mode)
        for key in (self.__key1, self.__key2, self.__key3):
            key.setPadMode(mode)

    def setIV(self, IV):
        _baseDes.setIV(self, IV)
        for key in (self.__key1, self.__key2, self.__key3):
            key.setIV(IV)

    def encrypt(self, data, pad=None, padmode=None):
        ENCRYPT = des.ENCRYPT
        DECRYPT = des.DECRYPT
        data = self._guardAgainstUnicode(data)
        if pad is not None:
            pad = self._guardAgainstUnicode(pad)
        data = self._padData(data, pad, padmode)
        if self.getMode() == CBC:
            self.__key1.setIV(self.getIV())
            self.__key2.setIV(self.getIV())
            self.__key3.setIV(self.getIV())
            i = 0
            result = []
            while i < len(data):
                block = self.__key1.crypt(data[i:i+8], ENCRYPT)
                block = self.__key2.crypt(block, DECRYPT)
                block = self.__key3.crypt(block, ENCRYPT)
                self.__key1.setIV(block)
                self.__key2.setIV(block)
                self.__key3.setIV(block)
                result.append(block)
                i += 8
            if _pythonMajorVersion < 3:
                return ''.join(result)
            else:
                return bytes.fromhex('').join(result)
        else:
            data = self.__key1.crypt(data, ENCRYPT)
            data = self.__key2.crypt(data, DECRYPT)
            return self.__key3.crypt(data, ENCRYPT)

    def decrypt(self, data, pad=None, padmode=None):
        ENCRYPT = des.ENCRYPT
        DECRYPT = des.DECRYPT
        data = self._guardAgainstUnicode(data)
        if pad is not None:
            pad = self._guardAgainstUnicode(pad)
        if self.getMode() == CBC:
            self.__key1.setIV(self.getIV())
            self.__key2.setIV(self.getIV())
            self.__key3.setIV(self.getIV())
            i = 0
            result = []
            while i < len(data):
                iv = data[i:i+8]
                block = self.__key3.crypt(iv, DECRYPT)
                block = self.__key2.crypt(block, ENCRYPT)
                block = self.__key1.crypt(block, DECRYPT)
                self.__key1.setIV(iv)
                self.__key2.setIV(iv)
                self.__key3.setIV(iv)
                result.append(block)
                i += 8
            if _pythonMajorVersion < 3:
                data = ''.join(result)
            else:
                data = bytes.fromhex('').join(result)
        else:
            data = self.__key3.crypt(data, DECRYPT)
            data = self.__key2.crypt(data, ENCRYPT)
            data = self.__key1.crypt(data, DECRYPT)
        return self._unpadData(data, pad, padmode)