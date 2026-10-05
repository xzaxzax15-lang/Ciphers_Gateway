"""ج. ملف ciphers/transposition.py (التبديل العمودي و P-Box):
"""

import math
from utils import sanitize_text


def columnar_transposition_encrypt(text, key):
    text = sanitize_text(text, allow_spaces=False)
    cols = len(key)
    rows = math.ceil(len(text) / cols)
    text += '*' * (rows * cols - len(text))
    grid = [text[i:i+cols] for i in range(0, len(text), cols)]
    sorted_key = sorted(list(key))
    ciphertext = ""
    for k in sorted_key:
        col_idx = key.index(k)
        for row in grid:
            ciphertext += row[col_idx]
    return ciphertext

def columnar_transposition_decrypt(text, key):
    text = sanitize_text(text, allow_spaces=False)
    cols = len(key)
    rows = math.ceil(len(text) / cols)
    sorted_key = sorted(list(key))
    num_long_cols = len(text) % cols or cols
    col_lengths = [rows if i < num_long_cols else rows - 1 for i in range(cols)]
    grid = [[''] * cols for _ in range(rows)]
    idx = 0
    for k in sorted_key:
        col_idx = key.index(k)
        col_len = col_lengths[col_idx]
        for r in range(col_len):
            grid[r][col_idx] = text[idx]
            idx += 1
    plaintext = "".join("".join(row) for row in grid)
    return plaintext.replace('*', '')

def pbox_encrypt(text, key):
    key_list = [int(k.strip()) for k in key.split(',')]
    if len(key_list) != len(text):
        raise ValueError(f"طول المفتاح ({len(key_list)}) يجب أن يساوي طول النص ({len(text)}).")
    result = [''] * len(text)
    for i, k in enumerate(key_list):
        result[k] = text[i]
    return ''.join(result)

def pbox_decrypt(text, key):
    key_list = [int(k.strip()) for k in key.split(',')]
    if len(key_list) != len(text):
        raise ValueError(f"طول المفتاح ({len(key_list)}) يجب أن يساوي طول النص ({len(text)}).")
    result = [''] * len(text)
    for i, k in enumerate(key_list):
        result[i] = text[k]
    return ''.join(result)
