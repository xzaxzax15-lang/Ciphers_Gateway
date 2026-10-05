from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad

def des_encrypt(plain_text, key):
    """
    تشفير النص باستخدام DES
    ملاحظة: مفتاح DES يجب أن يكون بطول 8 بايت (أحرف) بالضبط.
    """
    key_bytes = key.encode('utf-8')
    if len(key_bytes) != 8:
        raise ValueError("مفتاح DES يجب أن يكون مكوناً من 8 أحرف بالضبط.")
    
    cipher = DES.new(key_bytes, DES.MODE_ECB)
    padded_text = pad(plain_text.encode('utf-8'), DES.block_size)
    encrypted_bytes = cipher.encrypt(padded_text)
    
    return encrypted_bytes.hex()
#الخوارزمية فك التشفير باستخدام DES
def des_decrypt(cipher_hex, key):
    """
    فك التشفير باستخدام DES
    """
    key_bytes = key.encode('utf-8')
    if len(key_bytes) != 8:
        raise ValueError("مفتاح DES يجب أن يكون مكوناً من 8 أحرف بالضبط.")
    
    cipher = DES.new(key_bytes, DES.MODE_ECB)
    try:
        encrypted_bytes = bytes.fromhex(cipher_hex)
        decrypted_padded = cipher.decrypt(encrypted_bytes)
        original_text = unpad(decrypted_padded, DES.block_size)
        return original_text.decode('utf-8')
    except Exception:
        raise ValueError("فشل فك التشفير! تأكد من صحة المفتاح أو النص المشفر (Hex).")