import base64

class RC4Cipher:

#الدالة الداخلية لتطبيق خوارزمية RC4 على البيانات
    def _rc4_transform(self, data: bytes, key: bytes) -> bytes:
        # خوارزمية جدولة المفتاح (KSA)
        S = list(range(256))
        j = 0
        out = bytearray()
        for i in range(256):
            j = (j + S[i] + key[i % len(key)]) % 256
            S[i], S[j] = S[j], S[i]
        
        # خوارزمية توليد الأرقام شبه العشوائية (PRGA) وبوابة XOR
        i = 0
        j = 0
        for byte in data:
            i = (i + 1) % 256
            j = (j + S[i]) % 256
            S[i], S[j] = S[j], S[i]
            K = S[(S[i] + S[j]) % 256]
            out.append(byte ^ K)
        return bytes(out)
#الخوارزمية التشفير وفك التشفير باستخدام RC4
    def encrypt_text(self, text: str, key: str) -> str:
        try:
            encrypted_bytes = self._rc4_transform(text.encode('utf-8'), key.encode('utf-8'))
            return base64.b64encode(encrypted_bytes).decode('utf-8')
        except Exception as e:
            raise ValueError(f"خطأ في تشفير RC4: {str(e)}")
#
    def decrypt_text(self, enc_b64: str, key: str) -> str:
        try:
            enc_bytes = base64.b64decode(enc_b64.encode('utf-8'))
            decrypted_bytes = self._rc4_transform(enc_bytes, key.encode('utf-8'))
            return decrypted_bytes.decode('utf-8')
        except Exception as e:
            raise ValueError(f"خطأ في فك تشفير RC4: {str(e)}")

    def encrypt_bytes(self, file_bytes: bytes, key: str) -> bytes:
        try:
            return self._rc4_transform(file_bytes, key.encode('utf-8'))
        except Exception as e:
            raise ValueError(f"خطأ في تشفير الملف بـ RC4: {str(e)}")

    def decrypt_bytes(self, file_bytes: bytes, key: str) -> bytes:
        try:
            return self._rc4_transform(file_bytes, key.encode('utf-8'))
        except Exception as e:
            raise ValueError(f"خطأ في فك تشفير الملف بـ RC4: {str(e)}")