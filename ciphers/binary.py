import re
#الدالة لتحويل النص العادي إلى نص ثنائي
def text_to_binary(text): 
    return ' '.join(format(byte, '08b') for byte in text.encode('utf-8'))
#الدالة لتحويل النص الثنائي إلى نص عادي
def binary_to_text(binary_str):
    bits = binary_str.replace(" ", "").replace("\n", "").strip()
    if not all(c in '01' for c in bits):
        raise ValueError("الإدخال غير صالح: يجب أن يتكون التشفير الثنائي من الأصفار والآحاد (0 و 1) فقط.")
    if len(bits) % 8 != 0:
        raise ValueError(f"طول النص الثنائي غير صالح (عدد البتات الحالي: {len(bits)}). يجب أن يكون إجمالي عدد الخانات من مضاعفات الرقم 8.")
    try:
        byte_array = bytearray(int(bits[i:i+8], 2) for i in range(0, len(bits), 8))
        return byte_array.decode('utf-8')
    except Exception as e:
        raise ValueError("فشل فك التشفير: تأكد من صحة ولصق النص الثنائي كاملاً.")
#الدالة لتحويل ملف بايتات إلى نص ثنائي
def file_to_binary(file_bytes):
    return ' '.join(format(byte, '08b') for byte in file_bytes)
#الدالة لتحويل النص الثنائي إلى ملف بايتات
def binary_to_file(binary_str):
    bits = binary_str.replace(" ", "").replace("\n", "").strip()
    if not all(c in '01' for c in bits):
        raise ValueError("التشفير الثنائي للملف يجب أن يحتوي على أصفار وآحاد فقط.")
    if len(bits) % 8 != 0:
        raise ValueError("طول بتات الملف غير صالح (ليس من مضاعفات 8).")
    
    # تأكد أن هذا السطر يعيد bytes وليس bytearray
    return bytes(int(bits[i:i+8], 2) for i in range(0, len(bits), 8))