import rsa
import base64

class RSACipher:
    def __init__(self):
        self.public_key = None
        self.private_key = None

    def generate_keys(self, bit_size=1024):
        self.public_key, self.private_key = rsa.newkeys(bit_size)
        return self.public_key, self.private_key

    def encrypt_text(self, text: str, pub_key_pem: str) -> str:
        try:
            pub_key = rsa.PublicKey.load_pkcs1(pub_key_pem.encode('utf-8'))
            data_bytes = text.encode('utf-8')
            max_length = 100
            encrypted_chunks = []
            for i in range(0, len(data_bytes), max_length):
                chunk = data_bytes[i:i + max_length]
                encrypted_chunks.append(rsa.encrypt(chunk, pub_key))
            
            total_encrypted = b"".join(encrypted_chunks)
            return base64.b64encode(total_encrypted).decode('utf-8')
        except Exception as e:
            raise ValueError(f"خطأ في تشفير RSA: {str(e)}")

    def decrypt_text(self, enc_b64: str, priv_key_pem: str) -> str:
        try:
            priv_key = rsa.PrivateKey.load_pkcs1(priv_key_pem.encode('utf-8'))
            enc_data = base64.b64decode(enc_b64.encode('utf-8'))
            
            chunk_size = 128
            decrypted_chunks = []
            for i in range(0, len(enc_data), chunk_size):
                chunk = enc_data[i:i + chunk_size]
                decrypted_chunks.append(rsa.decrypt(chunk, priv_key))
                
            return b"".join(decrypted_chunks).decode('utf-8')
        except Exception as e:
            raise ValueError(f"خطأ في فك تشفير RSA: {str(e)}")

    def encrypt_bytes(self, file_bytes: bytes, pub_key_pem: str) -> bytes:
        try:
            pub_key = rsa.PublicKey.load_pkcs1(pub_key_pem.encode('utf-8'))
            max_length = 100
            encrypted_chunks = []
            for i in range(0, len(file_bytes), max_length):
                chunk = file_bytes[i:i + max_length]
                encrypted_chunks.append(rsa.encrypt(chunk, pub_key))
            return b"".join(encrypted_chunks)
        except Exception as e:
            raise ValueError(f"خطأ في تشفير الملف: {str(e)}")

    def decrypt_bytes(self, file_bytes: bytes, priv_key_pem: str) -> bytes:
        try:
            priv_key = rsa.PrivateKey.load_pkcs1(priv_key_pem.encode('utf-8'))
            chunk_size = 128
            decrypted_chunks = []
            for i in range(0, len(file_bytes), chunk_size):
                chunk = file_bytes[i:i + chunk_size]
                decrypted_chunks.append(rsa.decrypt(chunk, priv_key))
            return b"".join(decrypted_chunks)
        except Exception as e:
            raise ValueError(f"خطأ في فك تشفير الملف: {str(e)}")