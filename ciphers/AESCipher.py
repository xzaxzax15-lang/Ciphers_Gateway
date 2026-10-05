import base64
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import scrypt

class AESCipher:
    def __init__(self):
        # نستخدم scrypt كدالة اشتقاق مفتاح (KDF) قوية جداً
        self.salt = b'crypto_matrix_secure_salt_2026'

    def _derive_key(self, key_string: str) -> bytes:
        """يشتق مفتاح 256-بت من كلمة مرور المستخدم"""
        return scrypt(key_string, self.salt, key_len=32, N=2**14, r=8, p=1)

    def encrypt_text(self, text: str, password: str) -> str:
        try:
            key = self._derive_key(password)
            cipher = AES.new(key, AES.MODE_GCM)
            ciphertext, tag = cipher.encrypt_and_digest(text.encode('utf-8'))
            
            # ندمج nonce (متغير عشوائي لكل تشفير) مع الـ tag والـ ciphertext
            encrypted_data = cipher.nonce + tag + ciphertext
            return base64.b64encode(encrypted_data).decode('utf-8')
        except Exception as e:
            raise ValueError(f"خطأ في تشفير AES: {str(e)}")

    def decrypt_text(self, enc_b64: str, password: str) -> str:
        try:
            enc_data = base64.b64decode(enc_b64.encode('utf-8'))
            nonce = enc_data[:16]
            tag = enc_data[16:32]
            ciphertext = enc_data[32:]

            key = self._derive_key(password)
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            
            decrypted_bytes = cipher.decrypt_and_verify(ciphertext, tag)
            return decrypted_bytes.decode('utf-8')
        except ValueError:
             raise ValueError("❌ فشل فك التشفير: المفتاح غير صحيح أو تم التلاعب بالنص المشفر.")
        except Exception as e:
            raise ValueError(f"خطأ في فك تشفير AES: {str(e)}")

    def encrypt_bytes(self, file_bytes: bytes, password: str) -> bytes:
        try:
            key = self._derive_key(password)
            cipher = AES.new(key, AES.MODE_GCM)
            ciphertext, tag = cipher.encrypt_and_digest(file_bytes)
            return cipher.nonce + tag + ciphertext
        except Exception as e:
            raise ValueError(f"خطأ في تشفير الملف بـ AES: {str(e)}")

    def decrypt_bytes(self, file_bytes: bytes, password: str) -> bytes:
        try:
            nonce = file_bytes[:16]
            tag = file_bytes[16:32]
            ciphertext = file_bytes[32:]

            key = self._derive_key(password)
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            
            return cipher.decrypt_and_verify(ciphertext, tag)
        except ValueError:
             raise ValueError("❌ فشل فك تشفير الملف: المفتاح غير صحيح أو الملف معطوب.")
        except Exception as e:
            raise ValueError(f"خطأ في فك تشفير الملف بـ AES: {str(e)}")