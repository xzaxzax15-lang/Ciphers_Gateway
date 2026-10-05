"""1. محتوى ملف utils.py (الدوال المشتركة والتعقيم)
"""

import math
import re

def sanitize_text(text, allow_spaces=True, english_only=False):
    """تنظيف النص من الرموز الخاصة والمسافات الزائدة"""
    if not text:
        return ""
    text = text.strip()
    if not allow_spaces:
        text = text.replace(" ", "")
    if english_only:
        text = re.sub(r'[^a-zA-Z]', '', text)
        text = text.upper()
    return text

def sanitize_binary(text):
    if not text:
        return ""
    text = text.strip()
    text = re.sub(r'[^01\s]', '', text)
    text = re.sub(r'\s+', ' ', text)
    return text

def is_coprime(a, b):
    return math.gcd(a, b) == 1

def mod_inverse(a, m):
    """حساب معكوس الضرب النمطي بناءً على حجم الأبجدية m (26 أو 28)"""
    a = a % m
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return None

def is_prime(n):
    if n < 2:
        return False
    for i in range(2, int(n**0.5) + 1):
        if n % i == 0:
            return False
    return True

