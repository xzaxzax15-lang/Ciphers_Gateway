from typing import Optional
from utils import is_coprime, mod_inverse

# الأبجدية العربية الأساسية (28 حرفاً)
ARABIC_ALPHABET: str = "ابتثجحخدذرزسشصضطظعغفقكلمنهوي"
#الأبجدية الإنجليزية (26 حرفاً)
def validate_input_and_language(text: str, lang: str) -> None:
    """
    التحقق الصارم من عدم خلط اللغات أو إدخال حروف غير مسموحة بناءً على اللغة المختارة.
    
    Args:
        text (str): النص المراد التحقق منه.
        lang (str): اللغة المحددة ('العربية' أو 'الإنجليزية').
        
    Raises:
        ValueError: في حال وجود نص فارغ أو تداخل بين الحروف العربية والإنجليزية.
    """
    text_clean = text.replace(" ", "").replace("\n", "").strip()
    if not text_clean:
        raise ValueError("النص المدخل فارغ. يرجى إدخال نص صحيح.")
        
    for char in text_clean:
        # فحص الحروف الإنجليزية
        is_english_char = char.isascii() and char.isalpha()
        # فحص الحروف العربية
        is_arabic_char = ('أ' <= char <= 'ي') or (char in ARABIC_ALPHABET) or ('ء' <= char <= 'ي')
        
        if lang == "العربية":
            if is_english_char:
                raise ValueError("خطأ: لقد اخترت اللغة 'العربية'، ولكن النص يحتوي على حروف إنجليزية! ممنوع خلط اللغات.")
                
        elif lang == "الإنجليزية":
            if is_arabic_char:
                raise ValueError("خطأ: لقد اخترت اللغة 'الإنجليزية'، ولكن النص يحتوي على حروف عربية! يرجى إدخال حروف إنجليزية فقط.")

# خوارزمية قيصر
def caesar_cipher(text: str, shift: int, lang: str, decrypt: bool = False) -> str:
    """
    تشفير أو فك تشفير النص باستخدام خوارزمية قيصر (Caesar Cipher).
    
    Args:
        text (str): النص المراد تشفيره أو فك تشفيره.
        shift (int): مفتاح الإزاحة.
        lang (str): اللغة ('العربية' أو 'الإنجليزية').
        decrypt (bool): إذا كانت True يتم فك التشفير، وإذا كانت False يتم التشفير.
        
    Returns:
        str: النص الناتح بعد التشفير أو فك التشفير.
    """
    validate_input_and_language(text, lang)
    
    max_shift = 27 if lang == "العربية" else 25
    if not (1 <= shift <= max_shift):
        raise ValueError(f"مفتاح الإزاحة غير صالح للغة {lang}! يجب أن يكون المفتاح رقماً بين 1 و {max_shift}.")
        
    if decrypt:
        shift = -shift
        
    result = []
    for char in text:
        if lang == "العربية" and (char in ARABIC_ALPHABET or 'أ' <= char <= 'ي'):
            n = len(ARABIC_ALPHABET)
            idx = ARABIC_ALPHABET.find(char)
            if idx != -1:
                new_idx = (idx + shift) % n
                result.append(ARABIC_ALPHABET[new_idx])
            else:
                result.append(char)
        elif lang == "الإنجليزية" and char.isalpha():
            ascii_offset = 65 if char.isupper() else 97
            shifted = (ord(char) - ascii_offset + shift) % 26
            result.append(chr(shifted + ascii_offset))
        else:
            result.append(char) # الرموز والمسافات والأرقام تبقى كما هي
            
    return "".join(result)

#الخوارزمية التشفير الضربي
def multiplicative_cipher(text: str, key: int, lang: str, decrypt: bool = False) -> str:
    """
    تشفير أو فك تشفير النص باستخدام خوارزمية التشفير الضربي (Multiplicative Cipher).
    
    Args:
        text (str): النص المراد معالجته.
        key (int): المفتاح الضربي.
        lang (str): اللغة ('العربية' أو 'الإنجليزية').
        decrypt (bool): حالة فك التشفير أم لا.
        
    Returns:
        str: النص الناتج.
    """
    validate_input_and_language(text, lang)
    
    n = 28 if lang == "العربية" else 26
    
    if not (1 <= key < n):
        raise ValueError(f"المفتاح غير صالح للغة {lang}! يجب أن يكون رقماً بين 1 و {n - 1}.")
        
    if not is_coprime(key, n):
        raise ValueError(f"المفتاح غير صالح! يجب أن يكون المفتاح أولياً نسبياً مع حجم الأبجدية ({n}).")
        
    active_key = key
    if decrypt:
        inv_key = mod_inverse(key, n)
        if inv_key is None:
            raise ValueError("لا يمكن العثور على معكوس نمطي لهذا المفتاح.")
        active_key = inv_key
        
    result = []
    for char in text:
        if lang == "العربية" and char in ARABIC_ALPHABET:
            idx = ARABIC_ALPHABET.find(char)
            new_idx = (idx * active_key) % n
            result.append(ARABIC_ALPHABET[new_idx])
        elif lang == "الإنجليزية" and char.isalpha():
            ascii_offset = 65 if char.isupper() else 97
            shifted = ((ord(char) - ascii_offset) * active_key) % 26
            result.append(chr(shifted + ascii_offset))
        else:
            result.append(char)
            
    return "".join(result)


# دالة التشفير الجمعي تعتمد 
# على قيصر، لذا يمكننا إعادة استخدام دالة caesar_cipher مباشرةً.

def additive_cipher(text: str, key: int, lang: str, decrypt: bool = False) -> str:
    """
    خوارزمية التشفير الجمعي (تعتمد كلياً على قيصر).
    """
    return caesar_cipher(text, key, lang, decrypt)