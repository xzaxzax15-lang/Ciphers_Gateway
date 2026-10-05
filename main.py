# ============================================================
#  CryptoMatrix — NeoGlass Edition (نسخة مصلّحة)
#  ✅ إصلاح ظهور أكواد CSS كنص على الصفحة
# ============================================================

import streamlit as st
import math
import rsa
import base64
from utils import sanitize_text, sanitize_binary, is_prime, mod_inverse
from ciphers.binary import text_to_binary, binary_to_text,binary_to_file, file_to_binary
from ciphers.classical import caesar_cipher, multiplicative_cipher, additive_cipher
from ciphers.transposition import columnar_transposition_encrypt, columnar_transposition_decrypt, pbox_encrypt, pbox_decrypt
from ciphers.DES import des_encrypt, des_decrypt
from ciphers.RSAComponent import RSACipher
from ciphers.RC4Cipher import RC4Cipher
from ciphers.AESCipher import AESCipher

class RC4Cipher:
    def _rc4_transform(self, data: bytes, key: bytes) -> bytes:
        S = list(range(256))
        j = 0
        out = bytearray()
        for i in range(256):
            j = (j + S[i] + key[i % len(key)]) % 256
            S[i], S[j] = S[j], S[i]
        i = 0
        j = 0
        for byte in data:
            i = (i + 1) % 256
            j = (j + S[i]) % 256
            S[i], S[j] = S[j], S[i]
            K = S[(S[i] + S[j]) % 256]
            out.append(byte ^ K)
        return bytes(out)

    def encrypt_text(self, text: str, key: str) -> str:
        try:
            encrypted_bytes = self._rc4_transform(text.encode('utf-8'), key.encode('utf-8'))
            return base64.b64encode(encrypted_bytes).decode('utf-8')
        except Exception as e:
            raise ValueError(f"خطأ في تشفير RC4: {str(e)}")

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


# 1. إعدادات الصفحة
st.set_page_config(page_title="CryptoMatrix · NeoGlass", page_icon="🔐", layout="wide", initial_sidebar_state="expanded")

# ============================================================
#  🔧 أدوات الحقن الآمن — هنا إصلاح مشكلة ظهور CSS كنص
# ============================================================

def html(markup: str, container=None):
    """حقن HTML بأمان — يفرض unsafe_allow_html=True دائمًا حتى لا يظهر الكود كنص."""
    target = container if container is not None else st
    target.markdown(markup.strip(), unsafe_allow_html=True)

def _rgba(hexc, a):
    h = hexc.lstrip('#')
    return "rgba(%d,%d,%d,%.2f)" % (int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16), a)

def _svg_uri(svg: str) -> str:
    """ترميز SVG إلى base64 — آمن 100% داخل url() في CSS (لا يحتوي أبدًا على " أو مسافات)."""
    return "data:image/svg+xml;base64," + base64.b64encode(svg.encode("utf-8")).decode("ascii")

# ============================================================
#  خلفيات SVG رمزية لكل خوارزمية
# ============================================================

PATTERNS = {
    "binary": "<svg width='150' height='75'><text x='8' y='22' font-family='monospace' font-size='16' fill='rgba(255,255,255,0.22)'>10110</text><text x='66' y='48' font-family='monospace' font-size='16' fill='rgba(255,255,255,0.15)'>01001</text><text x='20' y='70' font-family='monospace' font-size='16' fill='rgba(255,255,255,0.19)'>11010</text></svg>",
    "caesar": "<svg width='150' height='75'><text x='10' y='26' font-family='serif' font-size='21' fill='rgba(255,255,255,0.24)'>XII</text><text x='68' y='58' font-family='serif' font-size='21' fill='rgba(255,255,255,0.18)'>IX</text><text x='104' y='24' font-family='serif' font-size='21' fill='rgba(255,255,255,0.22)'>XLIV</text></svg>",
    "multiplicative": "<svg width='130' height='75'><text x='14' y='38' font-size='36' fill='rgba(255,255,255,0.22)'>×</text><text x='78' y='66' font-size='30' fill='rgba(255,255,255,0.17)'>×</text><text x='98' y='22' font-size='22' fill='rgba(255,255,255,0.15)'>×</text></svg>",
    "additive": "<svg width='130' height='75'><path d='M24 10 V44 M7 27 H41' stroke='rgba(255,255,255,0.22)' stroke-width='4.5' stroke-linecap='round'/><path d='M92 42 V70 M78 56 H106' stroke='rgba(255,255,255,0.17)' stroke-width='4' stroke-linecap='round'/><path d='M108 8 V28 M98 18 H118' stroke='rgba(255,255,255,0.15)' stroke-width='3' stroke-linecap='round'/></svg>",
    "columnar": "<svg width='160' height='75'><rect x='8' y='10' width='28' height='55' rx='5' fill='rgba(255,255,255,0.12)'/><rect x='46' y='10' width='28' height='55' rx='5' fill='none' stroke='rgba(255,255,255,0.28)' stroke-width='2.5'/><rect x='84' y='10' width='28' height='55' rx='5' fill='rgba(255,255,255,0.12)'/><rect x='122' y='10' width='28' height='55' rx='5' fill='none' stroke='rgba(255,255,255,0.22)' stroke-width='2.5'/></svg>",
    "pbox": "<svg width='130' height='75'><path d='M14 14 L116 61 M116 14 L14 61' stroke='rgba(255,255,255,0.22)' stroke-width='2.5' fill='none'/><circle cx='14' cy='14' r='4.5' fill='rgba(255,255,255,0.4)'/><circle cx='116' cy='14' r='4.5' fill='rgba(255,255,255,0.4)'/><circle cx='14' cy='61' r='4.5' fill='rgba(255,255,255,0.4)'/><circle cx='116' cy='61' r='4.5' fill='rgba(255,255,255,0.4)'/><circle cx='65' cy='37' r='6' fill='rgba(255,255,255,0.55)'/></svg>",
    "rsa": "<svg width='120' height='75'><g stroke='rgba(255,255,255,0.3)' stroke-width='3' fill='none'><rect x='22' y='32' width='32' height='26' rx='6' fill='rgba(255,255,255,0.12)'/><path d='M29 32 V21 a9 9 0 0 1 18 0 V32'/></g><g stroke='rgba(255,255,255,0.16)' stroke-width='2.5' fill='none'><rect x='72' y='48' width='22' height='17' rx='4'/><path d='M77 48 V40 a6 6 0 0 1 12 0 V48'/></g><circle cx='38' cy='45' r='3' fill='rgba(255,255,255,0.5)'/></svg>",
    "rc4": "<svg width='120' height='75'><path d='M54 4 L32 40 H47 L40 71 L80 26 H61 L72 4 Z' fill='rgba(255,255,255,0.22)'/><path d='M12 60 H26 M16 48 H28' stroke='rgba(255,255,255,0.32)' stroke-width='2.5' stroke-linecap='round'/><path d='M96 58 H108' stroke='rgba(255,255,255,0.25)' stroke-width='2.5' stroke-linecap='round'/></svg>",
    "des": "<svg width='150' height='75'><rect x='8' y='10' width='24' height='15' rx='3' fill='rgba(255,255,255,0.18)'/><rect x='8' y='48' width='24' height='15' rx='3' fill='rgba(255,255,255,0.18)'/><rect x='66' y='10' width='24' height='15' rx='3' fill='none' stroke='rgba(255,255,255,0.32)' stroke-width='2.5'/><rect x='66' y='48' width='24' height='15' rx='3' fill='none' stroke='rgba(255,255,255,0.26)' stroke-width='2.5'/><path d='M32 17 H66 M32 55 H66 M90 17 H116 V55 H90' stroke='rgba(255,255,255,0.24)' stroke-width='2' fill='none'/><circle cx='132' cy='36' r='5.5' fill='rgba(255,255,255,0.32)'/></svg>",
    "aes": "<svg width='140' height='75'><rect x='20' y='25' width='100' height='25' rx='4' fill='rgba(255,255,255,0.15)'/><path d='M30 25 V15 A 40 40 0 0 1 110 15 V25' stroke='rgba(255,255,255,0.3)' stroke-width='3' fill='none'/><circle cx='70' cy='37' r='4' fill='rgba(255,255,255,0.6)'/></svg>",
}

# ============================================================
#  بيانات الخوارزميات
# ============================================================

ALGOS = {
    "binary": dict(icon="🧬", name="التشفير الثنائي", en="Binary Encoding", badge="ترميز رقمي",
        desc="حوّل أي نص إلى لغة الآلة: تتابع من الأصفار والآحاد (ASCII) — القاعدة التي تُبنى عليها كل الشفرات الرقمية.",
        c1="#00c6ff", c2="#0072ff",
        meta=["🧩 ترميز (Encoding)", "🕰️ عصر الحوسبة", "⚡ تنفيذ فوري", "🎯 أساس الأنظمة الرقمية"],
        steps=["اكتب النص العادي", "اضغط «تشفير فوري»", "اقرأ الناتج 0/1"],
        story="الثنائي ليس تشفيرًا بحد ذاته بل تمثيل للبيانات كما تفهمها الحواسيب: كل حرف يُحوَّل إلى 8 بتات (0/1) وفق جدول ASCII، وهو الخطوة الأولى في معظم خوارزميات التشفير الحديثة.",
        tags=["⚡ فوري", "🎓 تعليمي"]),
    "caesar": dict(icon="🏛️", name="تشفير قيصر", en="Caesar Cipher", badge="كلاسيكي · إزاحة",
        desc="إزاحة كل حرف بمقدار ثابت داخل الأبجدية — الشفرة التي استخدمها يوليوس قيصر لمراسلاته السرية قبل أكثر من ألفي عام.",
        c1="#f7971e", c2="#ffd200",
        meta=["🧩 إزاحة (Shift)", "🕰️ روما ~58 ق.م", "🎓 تعليمي", "🌍 عربي / إنجليزي"],
        steps=["اختر لغة النص", "حدد مفتاح الإزاحة", "شغّل التشفير أو الفك"],
        story="أبسط شفرات الاستبدال وأشهرها: يُستبدل كل حرف بالحرف الواقع بعدّة إزاحة ثابتة. كسرها ممكن بتجربة جميع الاحتمالات فقط، لذا تُعد اليوم بوابة تعليمية ممتازة لفهم مفهوم المفتاح.",
        tags=["🏛️ تاريخية", "🧠 بسيطة"]),
    "multiplicative": dict(icon="✖️", name="التشفير الضربي", en="Multiplicative Cipher", badge="كلاسيكي · ضربي",
        desc="يضرب ترتيب كل حرف بمفتاح أوليّ نسبيًا مع حجم الأبجدية ثم يأخذ باقي القسمة — التوءم الرياضي لشفرة الجمع.",
        c1="#11998e", c2="#38ef7d",
        meta=["🧩 ضرب معياري (Mod)", "🕰️ الرياضيات الكلاسيكية", "🎓 تعليمي", "🌍 عربي / إنجليزي"],
        steps=["اختر اللغة (حجم الأبجدية)", "مفتاح Co-prime مع الحجم", "نفّذ التشفير أو الفك"],
        story="يعتمد على الحساب النمطي: C = (P × K) mod n. شرط قابلية الفك هو أن يكون المفتاح أوليًا نسبيًا مع حجم الأبجدية حتى يوجد معكوس ضربي يُرجع النص الأصلي.",
        tags=["✖️ حسابي", "🔑 معكوس ضربي"]),
    "additive": dict(icon="➕", name="التشفير بالجمع", en="Additive Cipher", badge="كلاسيكي · جمعي",
        desc="يضيف مفتاحًا ثابتًا إلى ترتيب كل حرف ضمن الأبجدية — أبسط صور الإزاحة وأساس شفرة قيصر.",
        c1="#ff512f", c2="#f09819",
        meta=["🧩 جمع معياري (Mod)", "🕰️ الشفرات القديمة", "🎓 تعليمي", "🌍 عربي / إنجليزي"],
        steps=["اختر لغة النص", "حدد المفتاح", "نفّذ العملية"],
        story="C = (P + K) mod n، والفك يتم بطرح المفتاح: P = (C − K) mod n. يُدعى أيضًا شفرة الإزاحة العامة، وقيصر حالة خاصة منه بمفتاح 3.",
        tags=["➕ جمعي", "🎓 تعليمي"]),
    "columnar": dict(icon="🗂️", name="التبديل العمودي", en="Columnar Transposition", badge="كلاسيكي · تبديل",
        desc="يُعيد ترتيب الحروف كتابةً على أعمدة كلمة مفتاحية ثم قراءتها بترتيبها الأبجدي — الحروف نفسها لكن مواقعها تُخفى.",
        c1="#ec008c", c2="#fc6767",
        meta=["🧩 تبديل (Transposition)", "🕰️ الحروب الكبرى", "🔒 قوة متوسطة", "🔤 كلمة مفتاحية"],
        steps=["أدخل النص", "أدخل الكلمة المفتاحية", "شغّل التشفير أو الفك"],
        story="لا يغيّر هوية الحروف بل مواقعها: يُكتب النص صفّيًا بعدد أعمدة يساوي طول المفتاح، وتُقرأ الأعمدة حسب الترتيب الأبجدي لحروف الكلمة المفتاحية.",
        tags=["🗂️ شبكة أعمدة", "🔀 تبديلي"]),
    "pbox": dict(icon="🔀", name="صناديق التبديل", en="P-Box", badge="حديث · تبديل بتات",
        desc="تبديل مواضع الرموز/البتات وفق خريطة مفتاح دقيقة — اللبّ الذي تُبنى عليه DES وAES والشفرات الكتلية الحديثة.",
        c1="#8E2DE2", c2="#4A00E0",
        meta=["🧩 تبديل مواقع", "🕰️ أساس DES / AES", "⚙️ خريطة بتات", "🧪 الطول = عدد الخانات"],
        steps=["أدخل النص (طوله = عدد الخانات)", "أدخل خريطة المفتاح بفواصل", "نفّذ التبديل"],
        story="P-Box تطبيق مباشر لمبدأ Claude Shannon في «الانتشار Diffusion»: كل بت يدخل في موضع محدد حسب المفتاح، وتُستخدم طبقاته داخل كل جولات الشفرات الكتلية الحديثة.",
        tags=["🔀 بتات", "🧬 نواة حديثة"]),
    "rsa": dict(icon="🔐", name="خوارزمية RSA", en="RSA · Asymmetric", badge="حديث · غير متماثل",
        desc="نجم التشفير الحديث: مفتاح عام للتشفير ومفتاح خاص للفك، يرتكزان على صعوبة تحليل الأعداد الكبيرة إلى عواملها الأولية.",
        c1="#6a11cb", c2="#2575fc",
        meta=["🧩 غير متماثل (مفتاحان)", "🕰️ 1977 · Rivest–Shamir–Adleman", "🛡️ قوي جدًا", "🌐 TLS · التواقيع"],
        steps=["وَلِّد زوج المفاتيح", "شفّر بالمفتاح العام", "فُك بالمفتاح الخاص"],
        story="حاز مبتكروها جائزة تورنغ 2002. تُولَّد المفاتيح من حاصل ضرب عددين أوليين ضخمين؛ فك الشفرة يتطلب معرفة هذين العددين — مهمة شبه مستحيلة حسابيًا بالأحجام الحالية.",
        tags=["🔑 عام/خاص", "🛡️ معيار عالمي"]),
    "rc4": dict(icon="⚡", name="تشفير RC4", en="RC4 · Stream", badge="حديث · سيلاني",
        desc="شفرة سيلانية فائقة السرعة تُولّد تيار مفاتيح لحظيًا وتدمجه مع البيانات بعملية XOR — كانت قلب SSL وWEP.",
        c1="#00b09b", c2="#96c93d",
        meta=["🧩 سيلاني (Stream)", "🕰️ 1987 · Ron Rivest", "⚡ سريع جدًا", "🧪 مهجور أمنيًا"],
        steps=["أدخل المفتاح السري", "اختر نصًا أو ملفًا", "نفّذ التشفير / الفك"],
        story="خوارزمية أنيقة من 256 خلية تُخلط وفق المفتاح ثم تُنتج بايتات تيار تُدمج مع البيانات. سرعتها جعلها منتشرة في SSL/WPA، لكن ثغرات التحليل أنهت استخدامها الرسمي.",
        tags=["🌊 تيار لحظي", "🚀 أداء عالٍ"]),
    "des": dict(icon="🗝️", name="خوارزمية DES", en="DES · Block", badge="حديث · كتلي",
        desc="الشفرة الكتلية التاريخية: 16 جولة فيستل على كتل 64-بت بمفتاح 56-بت — درسٌ كامل في هندسة الشفرات.",
        c1="#cb2d3e", c2="#ef473a",
        meta=["🧩 متماثل كتلي", "🕰️ 1977 · IBM / NIST", "🗝️ مفتاح 8 أحرف", "📚 تاريخي / تعليمي"],
        steps=["أدخل نصًا ومفتاحًا من 8 أحرف", "شغّل التشفير (Hex)", "فُك بالنص Hex والمفتاح نفسه"],
        story="طوّرته IBM باسم Lucifer واعتمدته NIST معيارًا فيدراليًا عام 1977. قِصَر مفتاحه (56-بت) جعله قابلًا للكسر بالحواسيب الحديثة فخلفه AES — لكنه يبقى من أهم دروس علم التشفير.",
        tags=["🧊 شبكة فيستل", "📖 معلم أساسي"]),
    "aes": dict(icon="🛡️", name="معيار التشفير المتقدم (AES)", en="AES-256-GCM", badge="حديث · الأقوى عالمياً",
        desc="خوارزمية التشفير المتماثل الأقوى والمعتمدة عالمياً (تشفير البنوك والحكومات)، تدعم التوثيق عبر (GCM) لمنع التلاعب بالبيانات.",
        c1="#ff0055", c2="#2b00ff",
        meta=["🧩 متماثل كتلي (Block)", "🕰️ 2001 · NIST", "🛡️ غير قابل للكسر", "🌐 HTTPS / VPN"],
        steps=["أدخل أي كلمة مرور قوية", "اختر نصًا أو ملفًا ضخماً", "نفّذ التشفير بأعلى حماية"],
        story="تم اختيار AES كبديل لخوارزمية DES بعد مسابقة عالمية. نستخدم هنا وضع GCM الذي يوفر سرية البيانات ويثبت مصداقيتها في نفس الوقت.",
        tags=["🛡️ درع سيبراني", "🚀 فائق القوة"]),
}

ORDER = ["binary", "caesar", "multiplicative", "additive", "columnar", "pbox", "rsa", "rc4", "des", "aes"]
ALGO_CAT = {"binary": "modern", "caesar": "classical", "multiplicative": "classical",
            "additive": "classical", "columnar": "classical", "pbox": "modern",
            "rsa": "modern", "rc4": "modern", "des": "modern", "aes": "modern"}

NAV = {
    "home": "🏠 الصفحة الرئيسية",
    "binary": "🧬 التشفير الثنائي · Binary",
    "caesar": "🏛️ تشفير قيصر · Caesar",
    "multiplicative": "✖️ التشفير الضربي · Multiplicative",
    "additive": "➕ التشفير بالجمع · Additive",
    "columnar": "🗂️ التبديل العمودي · Columnar",
    "pbox": "🔀 صناديق التبديل · P-Box",
    "rsa": "🔐 خوارزمية RSA",
    "rc4": "⚡ التشفير السريع · RC4",
    "des": "🗝️ خوارزمية DES",
    "aes": "🛡️ خوارزمية AES"
}
LABEL2KEY = {v: k for k, v in NAV.items()}

# ============================================================
#  🎨 CSS بأسلوب تقني نظيف — كتلة واحدة متصلة بدون أسطر فارغة
# ============================================================

_FONT = "@import url('https://fonts.googleapis.com/css2?family=Cairo:wght@300;400;600;700;800;900&display=swap');"

# ملاحظة مهمة: لا توجد أسطر فارغة داخل أي كتلة <style> — السطر الفارغ يكسر كتلة HTML في Markdown
_BASE_CSS = """
h1,h2,h3{color:#fff!important;font-weight:800!important;letter-spacing:.3px;}
footer{visibility:hidden;}
::-webkit-scrollbar{width:10px;height:10px;}
::-webkit-scrollbar-track{background:#06070d;}
::-webkit-scrollbar-thumb{background:linear-gradient(180deg,var(--ac1),var(--ac2));border-radius:8px;border:2px solid #06070d;}
.stButton>button,.stDownloadButton>button{background:linear-gradient(135deg,var(--ac1),var(--ac2))!important;color:#05070d!important;border:none!important;border-radius:12px;padding:11px 24px;font-weight:800;font-size:15px;letter-spacing:.2px;box-shadow:0 10px 26px -12px var(--ac1);transition:transform .25s cubic-bezier(.34,1.56,.64,1),box-shadow .25s,filter .25s;}
.stButton>button:hover,.stDownloadButton>button:hover{transform:translateY(-2px) scale(1.015);filter:brightness(1.09);box-shadow:0 16px 36px -12px var(--ac1);}
.stButton>button:active{transform:translateY(0) scale(.98);}
.stTextInput input,.stTextArea textarea,.stNumberInput input{background:rgba(4,6,12,.72)!important;border:1px solid rgba(255,255,255,.10)!important;border-radius:12px!important;color:#eaf2ff!important;transition:border-color .25s,box-shadow .25s;}
.stTextInput input:focus,.stTextArea textarea:focus,.stNumberInput input:focus{border-color:var(--ac1)!important;box-shadow:0 0 0 3px rgba(255,255,255,.05),0 0 18px -4px var(--ac1)!important;}
[data-testid="stWidgetLabel"] p{color:#c6d3e8!important;font-weight:700;font-size:.92rem;}
pre{background:rgba(2,4,9,.92)!important;border:1px solid rgba(255,255,255,.09)!important;border-radius:12px!important;}
pre code{color:#cffff0!important;}
[data-testid="stAlert"]{background:rgba(255,255,255,.05)!important;border:1px solid rgba(255,255,255,.12)!important;border-radius:14px!important;backdrop-filter:blur(8px);}
.stTabs [data-baseweb="tab-list"]{gap:10px;background:rgba(255,255,255,.035);padding:7px;border-radius:16px;border:1px solid rgba(255,255,255,.07);}
.stTabs [data-baseweb="tab"]{background:transparent;border-radius:11px;padding:11px 24px;color:#9db0c9;font-weight:700;transition:.25s;}
.stTabs [data-baseweb="tab"]:hover{color:#fff;background:rgba(255,255,255,.05);}
.stTabs [aria-selected="true"]{background:linear-gradient(135deg,var(--ac1),var(--ac2))!important;color:#05070d!important;box-shadow:0 8px 22px -10px var(--ac1);}
.stTabs [data-baseweb="tab-highlight"],.stTabs [data-baseweb="tab-border"]{display:none;}
[data-testid="stVerticalBlockBorderWrapper"]{background:rgba(13,16,28,.55)!important;border:1px solid rgba(255,255,255,.09)!important;border-radius:18px!important;backdrop-filter:blur(14px);box-shadow:0 14px 40px -18px rgba(0,0,0,.8),inset 0 0 34px -20px var(--ac1);padding:1.4rem 1.6rem!important;}
[data-testid="stExpander"]{background:rgba(255,255,255,.03);border:1px solid rgba(255,255,255,.08);border-radius:14px;}
[data-testid="stExpander"] details{border:none!important;background:transparent!important;}
[data-testid="stExpander"] summary{font-weight:800;color:#dfe8f8;}
[data-testid="stExpander"] summary:hover{color:#fff;}
[data-testid="stFileUploaderDropzone"]{background:rgba(255,255,255,.03)!important;border:1.6px dashed var(--ac1)!important;border-radius:14px!important;}
[data-testid="stRadio"] [role="radiogroup"]{gap:9px;flex-wrap:wrap;}
[data-testid="stRadio"] label{background:rgba(255,255,255,.045);border:1px solid rgba(255,255,255,.1);border-radius:999px;padding:8px 18px;cursor:pointer;transition:.25s;font-weight:700;}
[data-testid="stRadio"] label p{color:#c6d3e8;font-weight:700;}
[data-testid="stRadio"] label:hover{border-color:var(--ac1);}
[data-testid="stRadio"] label:hover p{color:#fff;}
[data-testid="stRadio"] label:has(input:checked){background:linear-gradient(135deg,var(--ac1),var(--ac2));border-color:transparent;box-shadow:0 8px 20px -10px var(--ac1);}
[data-testid="stRadio"] label:has(input:checked) p{color:#05070d!important;}
[data-testid="stRadio"] label>div:first-child{display:none;}
section[data-testid="stSidebar"]{background:linear-gradient(180deg,#0a0c16 0%,#07080f 100%)!important;border-left:1px solid rgba(0,255,204,.16);box-shadow:-14px 0 44px rgba(0,0,0,.6);}
section[data-testid="stSidebar"] [data-testid="stRadio"] label{background:rgba(255,255,255,.035);border:1px solid rgba(255,255,255,.06);border-radius:12px;padding:10px 13px;margin:4px 0;}
section[data-testid="stSidebar"] [data-testid="stRadio"] label:hover{border-color:rgba(0,255,204,.4);background:rgba(0,255,204,.05);}
section[data-testid="stSidebar"] [data-testid="stRadio"] label:hover p{color:#fff;}
section[data-testid="stSidebar"] [data-testid="stRadio"] label:has(input:checked){background:linear-gradient(135deg,rgba(0,255,204,.15),rgba(123,44,191,.28));border-color:rgba(0,255,204,.5);box-shadow:0 6px 20px -8px rgba(0,255,204,.4);}
section[data-testid="stSidebar"] [data-testid="stRadio"] label:has(input:checked) p{color:#fff!important;}
.cm-logo{display:flex;align-items:center;gap:12px;padding:4px 2px;}
.cm-logo-ico{width:52px;height:52px;min-width:52px;border-radius:16px;background:linear-gradient(135deg,#00ffcc,#7b2cbf);display:flex;align-items:center;justify-content:center;font-size:1.55rem;box-shadow:0 10px 26px -8px rgba(0,255,204,.55);}
.cm-logo-txt b{display:block;font-size:1.12rem;background:linear-gradient(90deg,#7ff7e3,#b78cff);-webkit-background-clip:text;background-clip:text;color:transparent;}
.cm-logo-txt span{font-size:.72rem;color:#8fa2bd;}
.cm-sb-cap{font-size:.76rem;font-weight:800;color:#7ff7e3;letter-spacing:1px;margin:2px 0 6px;}
.cm-sb-tip{background:rgba(0,255,204,.06);border:1px solid rgba(0,255,204,.18);border-radius:12px;padding:10px 12px;font-size:.78rem;color:#a9c7c2;line-height:1.9;}
.cm-sb-foot{margin-top:12px;font-size:.7rem;color:#5d6a84;text-align:center;line-height:2;}
.cm-hr{border:none;height:1px;background:linear-gradient(90deg,transparent,rgba(0,255,204,.35),transparent);margin:12px 0;}
.cm-hero{position:relative;overflow:hidden;border-radius:28px;padding:52px 46px 46px;border:1px solid rgba(0,255,204,.2);background:linear-gradient(120deg,rgba(0,255,204,.09),rgba(123,44,191,.16) 55%,rgba(37,117,252,.10));box-shadow:0 30px 80px -40px rgba(0,255,204,.4),inset 0 0 80px rgba(123,44,191,.07);direction:rtl;margin-bottom:8px;}
.cm-hero::before,.cm-hero::after{content:"";position:absolute;border-radius:50%;filter:blur(6px);pointer-events:none;}
.cm-hero::before{width:360px;height:360px;top:-160px;left:-110px;background:radial-gradient(circle,rgba(0,255,204,.22),transparent 65%);animation:cmFloat 8s ease-in-out infinite;}
.cm-hero::after{width:420px;height:420px;bottom:-220px;right:-140px;background:radial-gradient(circle,rgba(123,44,191,.25),transparent 65%);animation:cmFloat 9.5s ease-in-out infinite reverse;}
@keyframes cmFloat{0%,100%{transform:translate(0,0);}50%{transform:translate(16px,14px);}}
.cm-kicker-home{letter-spacing:5px;color:#7ff7e3;font-weight:800;font-size:.8rem;margin-bottom:4px;}
.cm-hero h1{font-size:3.6rem!important;margin:0 0 10px!important;padding:0!important;line-height:1.15;background:linear-gradient(90deg,#fff 5%,#7ff7e3 45%,#b78cff 90%);-webkit-background-clip:text;background-clip:text;color:transparent!important;text-shadow:none!important;}
.cm-hero .lead{color:#b9c7dd;font-size:1.1rem;line-height:2;max-width:780px;margin:0;}
.cm-badges{display:flex;gap:9px;flex-wrap:wrap;margin-top:20px;}
.cm-badges span{background:rgba(255,255,255,.055);border:1px solid rgba(255,255,255,.13);padding:7px 15px;border-radius:999px;font-size:.82rem;color:#dfe7f5;font-weight:600;backdrop-filter:blur(6px);}
.cm-stats{display:flex;gap:14px;margin:16px 0 4px;flex-wrap:wrap;direction:rtl;}
.cm-stat{flex:1;min-width:160px;background:rgba(255,255,255,.035);border:1px solid rgba(255,255,255,.08);border-radius:18px;padding:18px;text-align:center;transition:.3s;}
.cm-stat:hover{transform:translateY(-3px);border-color:rgba(0,255,204,.3);}
.cm-stat b{display:block;font-size:1.9rem;font-weight:900;background:linear-gradient(90deg,#00ffcc,#b78cff);-webkit-background-clip:text;background-clip:text;color:transparent;}
.cm-stat span{color:#93a5c0;font-size:.82rem;font-weight:600;}
.cm-section{margin:26px 0 4px;direction:rtl;}
.cm-section h2{margin:0!important;padding:0!important;font-size:1.45rem!important;}
.cm-section p{margin:4px 0 0;color:#93a5c0;font-size:.88rem;}
.cm-card{position:relative;overflow:hidden;border-radius:20px;padding:20px;min-height:250px;display:flex;flex-direction:column;border:1px solid rgba(255,255,255,.15);background-size:150px 75px,cover;direction:rtl;box-shadow:0 14px 34px -16px rgba(0,0,0,.75);transition:transform .3s cubic-bezier(.34,1.45,.64,1),box-shadow .3s,border-color .3s;}
.cm-card::before{content:"";position:absolute;inset:0;background:linear-gradient(180deg,rgba(3,6,12,.05) 20%,rgba(3,6,12,.55) 100%);}
.cm-card>*{position:relative;z-index:1;}
.cm-card:hover{transform:translateY(-7px);border-color:rgba(255,255,255,.4);box-shadow:0 30px 54px -20px var(--c1);}
.cm-head{display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:10px;}
.cm-ico{width:56px;height:56px;border-radius:17px;background:rgba(255,255,255,.17);backdrop-filter:blur(8px);display:flex;align-items:center;justify-content:center;font-size:1.8rem;border:1px solid rgba(255,255,255,.28);box-shadow:inset 0 0 18px rgba(255,255,255,.12);}
.cm-badge{background:rgba(2,5,10,.35);border:1px solid rgba(255,255,255,.3);color:#fff;padding:4px 12px;border-radius:999px;font-size:.72rem;font-weight:800;backdrop-filter:blur(4px);}
.cm-name{color:#fff!important;font-size:1.28rem;font-weight:900;margin:2px 0 0;text-shadow:0 2px 12px rgba(0,0,0,.4);}
.cm-en{color:rgba(255,255,255,.72);font-size:.7rem;letter-spacing:2px;font-weight:700;text-transform:uppercase;margin-top:2px;}
.cm-desc{color:rgba(255,255,255,.9);font-size:.85rem;line-height:1.85;margin:8px 0 10px;}
.cm-tags{display:flex;gap:6px;flex-wrap:wrap;margin-top:auto;}
.cm-tags span{background:rgba(2,5,10,.3);border:1px solid rgba(255,255,255,.22);padding:3px 11px;border-radius:999px;font-size:.7rem;color:#fff;font-weight:700;}
[data-testid="stColumn"]:has(.cm-card) .stButton>button,[data-testid="column"]:has(.cm-card) .stButton>button{background:linear-gradient(135deg,var(--c1,#00ffcc),var(--c2,#7b2cbf))!important;border-radius:13px!important;margin-top:4px;}
.cm-hero-algo{position:relative;overflow:hidden;border-radius:24px;padding:30px 36px;border:1px solid rgba(255,255,255,.16);direction:rtl;display:flex;gap:26px;align-items:center;margin-bottom:12px;background-size:170px 85px,cover;}
.cm-hero-algo::before{content:"";position:absolute;inset:0;background:linear-gradient(180deg,rgba(3,6,12,.12),rgba(3,6,12,.52));}
.cm-hero-algo>*{position:relative;z-index:1;}
.cm-hero-ico{width:96px;height:96px;min-width:96px;border-radius:26px;background:rgba(255,255,255,.15);border:1px solid rgba(255,255,255,.3);display:flex;align-items:center;justify-content:center;font-size:2.9rem;backdrop-filter:blur(8px);box-shadow:inset 0 0 26px rgba(255,255,255,.14);}
.cm-hero-txt{flex:1;}
.cm-kicker{color:rgba(255,255,255,.85);letter-spacing:4px;font-size:.74rem;font-weight:800;}
.cm-hero-algo h1{color:#fff!important;margin:.1em 0 .2em!important;padding:0!important;font-size:2.15rem!important;text-shadow:0 4px 22px rgba(0,0,0,.45)!important;}
.cm-hero-algo p{color:rgba(255,255,255,.93);margin:0;font-size:.98rem;line-height:1.9;max-width:840px;}
.cm-meta{display:flex;gap:8px;flex-wrap:wrap;margin-top:14px;}
.cm-meta span{background:rgba(2,5,10,.35);border:1px solid rgba(255,255,255,.3);padding:5px 13px;border-radius:999px;font-size:.77rem;color:#fff;font-weight:700;backdrop-filter:blur(4px);}
.cm-steps{display:flex;align-items:center;gap:9px;flex-wrap:wrap;margin:2px 0 14px;direction:rtl;}
.cm-step{background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.1);border-radius:999px;padding:7px 15px 7px 12px;color:#dbe5f5;font-size:.85rem;display:inline-flex;align-items:center;gap:9px;}
.cm-step b{width:23px;height:23px;min-width:23px;border-radius:50%;background:linear-gradient(135deg,var(--ac1),var(--ac2));color:#04060c;display:inline-flex;align-items:center;justify-content:center;font-size:.74rem;}
.cm-arrow{color:var(--ac1);font-weight:900;}
"""

def build_theme_css(k=None):
    """يبني كتلة <style> واحدة كاملة — بنداء واحد مضمون، بدون أسطر فارغة، بدون HTML مكشوف."""
    if k is None:
        ac1, ac2 = "#00ffcc", "#7b2cbf"
        # خلفية الرئيسية — سلسلة عادية (لا تمر على % formatting)
        bg = (".stApp{background:"
              "radial-gradient(1200px 620px at 82% -12%,rgba(0,255,204,.08),transparent 60%),"
              "radial-gradient(1000px 520px at 8% 112%,rgba(123,44,191,.11),transparent 60%),"
              "linear-gradient(160deg,#0b0c16 0%,#05060d 100%)!important;}"
              ".stApp::before{content:\"\";position:fixed;inset:0;z-index:0;pointer-events:none;"
              "background-image:linear-gradient(rgba(0,255,204,.03) 1px,transparent 1px),"
              "linear-gradient(90deg,rgba(0,255,204,.03) 1px,transparent 1px);background-size:42px 42px;}")
    else:
        a = ALGOS[k]
        ac1, ac2 = a["c1"], a["c2"]
        pat = _svg_uri(PATTERNS[k])   # ← base64: آمن داخل url() ولا يكسر CSS أبدًا
        bg = ('.stApp{background-image:url("%s"),'
              'radial-gradient(1100px 560px at 88%% -12%%,%s,transparent 60%%),'
              'radial-gradient(900px 540px at 4%% 108%%,%s,transparent 58%%),'
              'linear-gradient(160deg,#0a0c16 0%%,#05060c 100%%)!important;'
              'background-size:170px 85px,auto,auto,cover;background-attachment:fixed;}'
              % (pat, _rgba(ac1, .16), _rgba(ac2, .14)))

    root_css = ':root{--ac1:%s;--ac2:%s;}' % (ac1, ac2)
    note_css = ('.cm-note{direction:rtl;background:%s;border:1px solid %s;border-right:4px solid %s;'
                'border-radius:14px;padding:12px 16px;color:#dbe6fa;font-size:.93rem;line-height:1.8;margin:4px 0 12px;}'
                % (_rgba(ac1, .07), _rgba(ac1, .4), ac1))

    # تلوين كل بطاقة + زرها بألوان خوارزميتها (SVG بترميز base64)
    card_css = "".join(
        '.cm-card-%s{--c1:%s;--c2:%s;background-image:url("%s"),linear-gradient(150deg,%s 0%%,%s 100%%);}'
        % (key, a["c1"], a["c2"], _svg_uri(PATTERNS[key]), a["c1"], a["c2"])
        for key, a in ALGOS.items())
    colvar_css = "".join(
        '[data-testid="stColumn"]:has(.cm-card-%s),[data-testid="column"]:has(.cm-card-%s){--c1:%s;--c2:%s;}'
        % (key, key, a["c1"], a["c2"])
        for key, a in ALGOS.items())

    css = _FONT + root_css + bg + note_css + card_css + colvar_css + _BASE_CSS
    return "<style>" + css.replace("\n\n", "\n") + "</style>"   # ضمان: لا أسطر فارغة

def inject_theme(k=None):
    """النداء الوحيد والوحيد لحقن CSS في التطبيق كله."""
    st.markdown(build_theme_css(k), unsafe_allow_html=True)

# ============================================================
#  مكوّنات الواجهة
# ============================================================

def _go(label):
    st.session_state["nav"] = label

def note(txt):
    html("<div class='cm-note' dir='rtl'>💡 " + txt + "</div>")

def _card(k):
    a = ALGOS[k]
    chips = "".join("<span>" + t + "</span>" for t in a["tags"])
    return ("<div class='cm-card cm-card-" + k + "' dir='rtl'>"
            "<div class='cm-head'><div class='cm-ico'>" + a['icon'] + "</div><span class='cm-badge'>" + a['badge'] + "</span></div>"
            "<div class='cm-name'>" + a['name'] + "</div>"
            "<div class='cm-en'>" + a['en'] + "</div>"
            "<p class='cm-desc'>" + a['desc'] + "</p>"
            "<div class='cm-tags'>" + chips + "</div></div>")

def _hero(k):
    a = ALGOS[k]
    pat = _svg_uri(PATTERNS[k])
    chips = "".join("<span>" + m + "</span>" for m in a["meta"])
    steps = "".join(
        "<span class='cm-step'><b>" + str(i + 1) + "</b>" + s + "</span>" +
        ("<span class='cm-arrow'>←</span>" if i < len(a["steps"]) - 1 else "")
        for i, s in enumerate(a["steps"]))
    return ("<div class='cm-hero-algo' dir='rtl' style=\"background-image:url('" + pat +
            "'),linear-gradient(120deg," + a['c1'] + " 0%," + a['c2'] + " 100%);"
            "box-shadow:0 30px 64px -28px " + _rgba(a['c1'], .6) + ";\">"
            "<div class='cm-hero-ico'>" + a['icon'] + "</div>"
            "<div class='cm-hero-txt'>"
            "<div class='cm-kicker'>خوارزمية تشفير · " + a['en'] + "</div>"
            "<h1>" + a['name'] + "</h1>"
            "<p>" + a['desc'] + "</p>"
            "<div class='cm-meta'>" + chips + "</div></div></div>"
            "<div class='cm-steps' dir='rtl'>" + steps + "</div>")

def algo_header(k, note_text=None):
    inject_theme(k)   # ثيم الصفحة: نداء واحد مضمون
    html(_hero(k))
    with st.expander("📖 نبذة سريعة — كيف تعمل الخوارزمية؟"):
        html("<div dir='rtl' style='color:#c9d6ea;line-height:2.1;font-size:.95rem'>" + ALGOS[k]['story'] + "</div>")
    if note_text:
        note(note_text)

def back_home(k):
    html("<div style='height:8px'></div>")
    st.button("🏠 العودة إلى الصفحة الرئيسية", key="home_" + k, on_click=_go, args=(NAV["home"],), use_container_width=True)

# ============================================================
#  الصفحة الرئيسية
# ============================================================

def render_home():
    inject_theme(None)
    html("""
    <div class="cm-hero" dir="rtl">
      <div class="cm-kicker-home">★ منصّة تعليمية تفاعلية لعلم التشفير</div>
      <h1>CryptoMatrix</h1>
      <p class="lead">من شفرات روما القديمة إلى RSA الحديثة — تسع خوارزميات تشفير كاملة في واجهة واحدة أنيقة: شفّر النصوص والملفات، وافهم كيف تعمل كل خوارزمية من الداخل.</p>
      <div class="cm-badges">
        <span>🔒 تشفير النصوص</span><span>📁 تشفير الملفات</span><span>🌍 عربي / إنجليزي</span>
        <span>⚡ معالجة لحظية</span><span>🎓 شرح مبسّط</span>
      </div>
    </div>
    <div class="cm-stats">
      <div class="cm-stat"><b>9</b><span>خوارزميات تشفير متكاملة</span></div>
      <div class="cm-stat"><b>2</b><span>مدرستان: كلاسيكية وحديثة</span></div>
      <div class="cm-stat"><b>2</b><span>لغتان: العربية والإنجليزية</span></div>
      <div class="cm-stat"><b>100%</b><span>معالجة محلية آمنة</span></div>
    </div>
    """)
    html("<div class='cm-section'><h2>🧭 اختر خوارزميتك</h2><p>كل بطاقة تحمل هوية خوارزميتها — اضغط «استكشف» للدخول.</p></div>")

    filt_label = st.radio("فلترة", ["الكل ✨", "🏛️ كلاسيكية", "🚀 حديثة"], horizontal=True, key="filter", label_visibility="collapsed")
    fmap = {"الكل ✨": "all", "🏛️ كلاسيكية": "classical", "🚀 حديثة": "modern"}
    filt = fmap[filt_label]

    keys = [k for k in ORDER if filt == "all" or ALGO_CAT[k] == filt]
    for r in range(0, len(keys), 3):
        cols = st.columns(3, gap="medium")
        for col, k in zip(cols, keys[r:r+3]):
            with col:
                html(_card(k))
                st.button("🚀 استكشف الخوارزمية", key="go_" + k, on_click=_go, args=(NAV[k],), use_container_width=True)

# ============================================================
#  صفحات الخوارزميات (نفس منطق التشفير بدون أي تغيير)
# ============================================================

def page_binary():
    algo_header("binary", "يدعم اللغتين العربية والإنجليزية، وتحويل الملفات بالكامل إلى صيغة 8-بت.")
    tab1, tab2 = st.tabs(["🔒 التشفير (نصوص وملفات)", "🔓 فك التشفير (نصوص وملفات)"])
    
    with tab1:
        with st.container(border=True):
            mode = st.radio("اختر نوع التشفير:", ["نص عادي (عربي / إنجليزي)", "ملف (File)"], horizontal=True, key="bin_enc_mode")
            
            if mode == "نص عادي (عربي / إنجليزي)":
                text = st.text_area("أدخل النص (يدعم العربية والإنجليزية):", key="bin_enc_text")
                if st.button("⚡ تشفير النص فوري", key="b_enc_t", use_container_width=True):
                    if not text:
                        st.warning("الرجاء إدخال نص أولاً.")
                    else:
                        st.success("✨ تم تشفير النص بنجاح:")
                        st.code(text_to_binary(text), language="text")
            else:
                uploaded_file = st.file_uploader("اختر ملفاً لتشفيره:", key="bin_enc_file")
                if st.button("⚡ تشفير الملف", key="b_enc_f", use_container_width=True):
                    if uploaded_file is not None:
                        file_bytes = uploaded_file.read()
                        res = file_to_binary(file_bytes)
                        st.success("✨ تم تحويل وتشفير الملف إلى صيغة ثنائية بنجاح:")
                        st.text_area("النتيجة الثنائية للملف:", res, height=150)
                        st.download_button("📥 تحميل النتائج الثنائية", res, file_name="encrypted_file.txt", mime="text/plain")
                    else:
                        st.warning("الرجاء رفع ملف أولاً.")
                        
    with tab2:
        with st.container(border=True):
            mode_dec = st.radio("اختر نوع فك التشفير:", ["نص ثنائي", "ملف ثنائي"], horizontal=True, key="bin_dec_mode")
            
            if mode_dec == "نص ثنائي":
                text = st.text_area("أدخل النص الثنائي (أصفار وآحاد فقط):", key="bin_dec_text")
                if st.button("🔓 فك التشفير الفوري", key="b_dec_t", use_container_width=True):
                    if not text:
                        st.warning("الرجاء إدخال النص الثنائي أولاً.")
                    else:
                        cleaned_text = text.replace(" ", "").replace("\n", "")
                        if not all(c in '01' for c in cleaned_text):
                            st.error("❌ خطأ: النص الثنائي يجب أن يتكون من أصفار (0) وآحاد (1) فقط!")
                        else:
                            try:
                                st.success("✨ تم فك التشفير بنجاح:")
                                st.code(binary_to_text(text), language="text")
                            except Exception as e:
                                st.error(f"خطأ في الصيغة: {str(e)}")
            else:
                bin_input_file = st.text_area("ألصق الكود الثنائي الخاص بالملف هنا:", key="bin_dec_file_text")
                file_name_input = st.text_input("اسم الملف المسترجع مع اللاحقة (مثال: image.png أو doc.txt):", value="decoded_file.txt")
                if st.button("🔓 استرجاع وفك ملف", key="b_dec_f", use_container_width=True):
                    if not bin_input_file:
                        st.warning("الرجاء إدخال الكود الثنائي للملف.")
                    else:
                        cleaned_text = bin_input_file.replace(" ", "").replace("\n", "")
                        if not all(c in '01' for c in cleaned_text):
                            st.error("❌ خطأ: يجب أن يحتوي النص على أصفار وآحاد فقط استرجاعاً للملف!")
                        else:
                            try:
                                original_bytes = binary_to_file(bin_input_file)
                                st.success("✨ تم فك تشفير واسترجاع الملف بنجاح!")
                                st.download_button("📥 تحميل الملف المفكوك", original_bytes, file_name=file_name_input)
                            except Exception as e:
                                st.error(f"خطأ في فك ملف الثنائي: {str(e)}")

    back_home("binary")

#القسم التالي هو صفحة خوارزمية قيصر، حيث يمكن للمستخدم اختيار اللغة
#  وإدخال النص والمفتاح لتشفير أو فك تشفير النص باستخدام خوارزمية قيصر.
#
def page_caesar():
    algo_header("caesar")
    lang = st.radio("اختر لغة النص:", ["العربية", "الإنجليزية"], horizontal=True, key="caesar_lang")
    max_shift = 27 if lang == "العربية" else 25
    note("اللغة <b>" + lang + "</b> تستخدم مفتاح إزاحة من 1 إلى " + str(max_shift) + " — كل حرف يُزاح بمقدار المفتاح داخل الأبجدية.")
    
    tab1, tab2 = st.tabs(["🔒 التشفير (Encrypt)", "🔓 فك التشفير (Decrypt)"])
    
    with tab1:
        with st.container(border=True):
            mode_enc = st.radio("اختر نوع التشفير:", ["نص عادي", "ملف (File)"], horizontal=True, key="caesar_enc_mode")
            shift = st.number_input("مفتاح الإزاحة:", min_value=1, max_value=max_shift, value=3, key="c_enc_s")
            
            if mode_enc == "نص عادي":
                text = st.text_area(f"أدخل النص العادي ({lang} فقط):", key="c_enc_t")
                if st.button("🏛️ تشفير قيصر", key="c_enc_b", use_container_width=True):
                    if not text.strip():
                        st.warning("الرجاء إدخال النص أولاً.")
                    else:
                        try:
                            # تنفيذ التشفير أولاً للتأكد من عدم وجود أخطاء لغة
                            result = caesar_cipher(text, int(shift), lang, decrypt=False)
                            st.success("✨ تم التشفير بنجاح!")
                            st.code(result, language="text")
                            st.download_button("📥 تحميل النص المشفر كملف", result, file_name="caesar_encrypted.txt", mime="text/plain", key="down_c_enc_txt")
                        except ValueError as e:
                            st.error(str(e))
            else:
                uploaded_file = st.file_uploader("اختر ملفاً لتشفيره:", key="caesar_enc_file")
                if st.button("🏛️ تشفير الملف بقيصر", key="c_enc_file_b", use_container_width=True):
                    if uploaded_file is not None:
                        try:
                            file_bytes = uploaded_file.read()
                            file_text = file_bytes.decode('utf-8', errors='ignore')
                            result = caesar_cipher(file_text, int(shift), lang, decrypt=False)
                            st.success("✨ تم تشفير الملف بنجاح!")
                            st.text_area("نتيجة تشفير الملف:", result, height=150)
                            st.download_button("📥 تحميل الملف المشفر", result, file_name="caesar_encrypted_file.txt", mime="text/plain", key="down_c_enc_file")
                        except ValueError as e:
                            st.error(str(e))
                        except Exception as e:
                            st.error(f"خطأ في قراءة الملف: {str(e)}")
                    else:
                        st.warning("الرجاء رفع ملف أولاً.")

    with tab2:
        with st.container(border=True):
            mode_dec = st.radio("اختر نوع فك التشفير:", ["نص مشفر", "ملف مشفر"], horizontal=True, key="caesar_dec_mode")
            shift = st.number_input("مفتاح الإزاحة:", min_value=1, max_value=max_shift, value=3, key="c_dec_s")
            
            if mode_dec == "نص مشفر":
                text = st.text_area(f"أدخل النص المشفر ({lang} فقط):", key="c_dec_t")
                file_name_dec = st.text_input("اسم الملف المسترجع للنص:", value="caesar_decrypted.txt", key="c_dec_t_name")
                
                if st.button("🏛️ فك تشفير قيصر", key="c_dec_b", use_container_width=True):
                    if not text.strip():
                        st.warning("الرجاء إدخال النص المشفر أولاً.")
                    else:
                        try:
                            result = caesar_cipher(text, int(shift), lang, decrypt=True)
                            st.success("✨ تم فك التشفير بنجاح!")
                            st.code(result, language="text")
                            st.download_button("📥 تحميل النص المفكوك كملف", result, file_name=file_name_dec, mime="text/plain", key="down_c_dec_txt")
                        except ValueError as e:
                            st.error(str(e))
            else:
                bin_input_file = st.text_area("ألصق محتوى الملف المشفر هنا:", key="caesar_dec_file_text")
                file_name_input = st.text_input("اسم الملف المسترجع مع اللاحقة (مثال: doc.txt):", value="restored_file.txt", key="caesar_dec_filename_input")
                
                if st.button("🏛️ استرجاع وفك الملف", key="c_dec_file_b", use_container_width=True):
                    if not bin_input_file.strip():
                        st.warning("الرجاء إدخال النص المشفر للملف.")
                    else:
                        try:
                            result = caesar_cipher(bin_input_file, int(shift), lang, decrypt=True)
                            st.success("✨ تم فك تشفير واسترجاع الملف بنجاح!")
                            st.download_button("📥 تحميل الملف المفكوك", result, file_name=file_name_input, mime="text/plain", key="down_c_dec_file")
                        except ValueError as e:
                            st.error(str(e))

    back_home("caesar")

def page_multiplicative():
    algo_header("multiplicative")
    lang = st.radio("اختر لغة النص:", ["العربية", "الإنجليزية"], horizontal=True, key="mult_lang")
    n_size = 28 if lang == "العربية" else 26
    max_key = n_size - 1
    note("اللغة: <b>" + lang + "</b> (حجم الأبجدية " + str(n_size) + "). المفتاح يجب أن يكون أوليًا نسبيًا مع " + str(n_size) + " (من 1 إلى " + str(max_key) + ").")
    
    tab1, tab2 = st.tabs(["🔒 التشفير (Encrypt)", "🔓 فك التشفير (Decrypt)"])
    
    with tab1:
        with st.container(border=True):
            mode_enc = st.radio("اختر نوع التشفير:", ["نص عادي", "ملف (File)"], horizontal=True, key="mult_enc_mode")
            key = st.number_input(f"المفتاح (Co-prime مع {n_size}):", min_value=1, max_value=max_key, value=5, key="m_enc_k")
            
            if mode_enc == "نص عادي":
                text = st.text_area(f"النص العادي ({lang} فقط):", key="m_enc_t")
                if st.button("✖️ تشفير ضربي", key="m_enc_b", use_container_width=True):
                    if not text.strip():
                        st.warning("الرجاء إدخال النص أولاً.")
                    else:
                        try:
                            result = multiplicative_cipher(text, int(key), lang, decrypt=False)
                            st.success("✨ تم التشفير بنجاح!")
                            st.code(result, language="text")
                            st.download_button("📥 تحميل النص المشفر كملف", result, file_name="multiplicative_encrypted.txt", mime="text/plain", key="down_m_enc_txt")
                        except Exception as e:
                            st.error(str(e))
            else:
                uploaded_file = st.file_uploader("اختر ملفاً لتشفيره:", key="mult_enc_file")
                if st.button("✖️ تشفير الملف ضربياً", key="m_enc_file_b", use_container_width=True):
                    if uploaded_file is not None:
                        try:
                            file_bytes = uploaded_file.read()
                            file_text = file_bytes.decode('utf-8', errors='ignore')
                            result = multiplicative_cipher(file_text, int(key), lang, decrypt=False)
                            st.success("✨ تم تشفير الملف بنجاح!")
                            st.text_area("نتيجة تشفير الملف:", result, height=150)
                            st.download_button("📥 تحميل الملف المشفر", result, file_name="multiplicative_encrypted_file.txt", mime="text/plain", key="down_m_enc_file")
                        except Exception as e:
                            st.error(str(e))
                    else:
                        st.warning("الرجاء رفع ملف أولاً.")

    with tab2:
        with st.container(border=True):
            mode_dec = st.radio("اختر نوع فك التشفير:", ["نص مشفر", "ملف مشفر"], horizontal=True, key="mult_dec_mode")
            key = st.number_input(f"المفتاح (Co-prime مع {n_size}):", min_value=1, max_value=max_key, value=5, key="m_dec_k")
            
            if mode_dec == "نص مشفر":
                text = st.text_area(f"النص المشفر ({lang} فقط):", key="m_dec_t")
                file_name_dec = st.text_input("اسم الملف المسترجع للنص:", value="multiplicative_decrypted.txt", key="m_dec_t_name")
                
                if st.button("✖️ فك تشفير ضربي", key="m_dec_b", use_container_width=True):
                    if not text.strip():
                        st.warning("الرجاء إدخال النص المشفر أولاً.")
                    else:
                        try:
                            result = multiplicative_cipher(text, int(key), lang, decrypt=True)
                            st.success("✨ تم فك التشفير بنجاح!")
                            st.code(result, language="text")
                            st.download_button("📥 تحميل النص المفكوك كملف", result, file_name=file_name_dec, mime="text/plain", key="down_m_dec_txt")
                        except Exception as e:
                            st.error(str(e))
            else:
                bin_input_file = st.text_area("ألصق محتوى الملف المشفر هنا:", key="mult_dec_file_text")
                file_name_input = st.text_input("اسم الملف المسترجع مع اللاحقة (مثال: doc.txt):", value="restored_file.txt", key="mult_dec_filename_input")
                
                if st.button("✖️ استرجاع وفك الملف ضربياً", key="m_dec_file_b", use_container_width=True):
                    if not bin_input_file.strip():
                        st.warning("الرجاء إدخال النص المشفر للملف.")
                    else:
                        try:
                            result = multiplicative_cipher(bin_input_file, int(key), lang, decrypt=True)
                            st.success("✨ تم فك تشفير واسترجاع الملف بنجاح!")
                            st.download_button("📥 تحميل الملف المفكوك", result, file_name=file_name_input, mime="text/plain", key="down_m_dec_file")
                        except Exception as e:
                            st.error(str(e))

    back_home("multiplicative")
#الآن ننتقل إلى صفحة خوارزمية الجمع، حيث يمكن للمستخدم اختيار اللغة وإدخال النص والمفتاح لتشفير
#  أو فك تشفير النص باستخدام خوارزمية الجمع.
def page_additive():
    algo_header("additive")
    lang = st.radio("اختر لغة النص:", ["العربية", "الإنجليزية"], horizontal=True, key="add_lang")
    max_shift = 27 if lang == "العربية" else 25
    note("اللغة <b>" + lang + "</b> تستخدم مفتاح جمع من 1 إلى " + str(max_shift) + " — C = (P + K) mod n.")
    
    tab1, tab2 = st.tabs(["🔒 التشفير (Encrypt)", "🔓 فك التشفير (Decrypt)"])
    
    with tab1:
        with st.container(border=True):
            mode_enc = st.radio("اختر نوع التشفير:", ["نص عادي", "ملف (File)"], horizontal=True, key="add_enc_mode")
            key = st.number_input("المفتاح:", min_value=1, max_value=max_shift, value=4, key="a_enc_k")
            
            if mode_enc == "نص عادي":
                text = st.text_area(f"النص العادي ({lang} فقط):", key="a_enc_t")
                if st.button("➕ تشفير بالجمع", key="a_enc_b", use_container_width=True):
                    if not text.strip():
                        st.warning("الرجاء إدخال النص أولاً.")
                    else:
                        try:
                            result = additive_cipher(text, int(key), lang, decrypt=False)
                            st.success("✨ تم التشفير بنجاح!")
                            st.code(result, language="text")
                            st.download_button("📥 تحميل النص المشفر كملف", result, file_name="additive_encrypted.txt", mime="text/plain", key="down_a_enc_txt")
                        except Exception as e:
                            st.error(str(e))
            else:
                uploaded_file = st.file_uploader("اختر ملفاً لتشفيره:", key="add_enc_file")
                if st.button("➕ تشفير الملف بالجمع", key="a_enc_file_b", use_container_width=True):
                    if uploaded_file is not None:
                        try:
                            file_bytes = uploaded_file.read()
                            file_text = file_bytes.decode('utf-8', errors='ignore')
                            result = additive_cipher(file_text, int(key), lang, decrypt=False)
                            st.success("✨ تم تشفير الملف بنجاح!")
                            st.text_area("نتيجة تشفير الملف:", result, height=150)
                            st.download_button("📥 تحميل الملف المشفر", result, file_name="additive_encrypted_file.txt", mime="text/plain", key="down_a_enc_file")
                        except Exception as e:
                            st.error(str(e))
                    else:
                        st.warning("الرجاء رفع ملف أولاً.")

    with tab2:
        with st.container(border=True):
            mode_dec = st.radio("اختر نوع فك التشفير:", ["نص مشفر", "ملف مشفر"], horizontal=True, key="add_dec_mode")
            key = st.number_input("المفتاح:", min_value=1, max_value=max_shift, value=4, key="a_dec_k")
            
            if mode_dec == "نص مشفر":
                text = st.text_area(f"النص المشفر ({lang} فقط):", key="a_dec_t")
                file_name_dec = st.text_input("اسم الملف المسترجع للنص:", value="additive_decrypted.txt", key="a_dec_t_name")
                
                if st.button("➕ فك تشفير بالجمع", key="a_dec_b", use_container_width=True):
                    if not text.strip():
                        st.warning("الرجاء إدخال النص المشفر أولاً.")
                    else:
                        try:
                            result = additive_cipher(text, int(key), lang, decrypt=True)
                            st.success("✨ تم فك التشفير بنجاح!")
                            st.code(result, language="text")
                            st.download_button("📥 تحميل النص المفكوك كملف", result, file_name=file_name_dec, mime="text/plain", key="down_a_dec_txt")
                        except Exception as e:
                            st.error(str(e))
            else:
                bin_input_file = st.text_area("ألصق محتوى الملف المشفر هنا:", key="add_dec_file_text")
                file_name_input = st.text_input("اسم الملف المسترجع مع اللاحقة (مثال: doc.txt):", value="restored_file.txt", key="add_dec_filename_input")
                
                if st.button("➕ استرجاع وفك الملف بالجمع", key="a_dec_file_b", use_container_width=True):
                    if not bin_input_file.strip():
                        st.warning("الرجاء إدخال النص المشفر للملف.")
                    else:
                        try:
                            result = additive_cipher(bin_input_file, int(key), lang, decrypt=True)
                            st.success("✨ تم فك تشفير واسترجاع الملف بنجاح!")
                            st.download_button("📥 تحميل الملف المفكوك", result, file_name=file_name_input, mime="text/plain", key="down_a_dec_file")
                        except Exception as e:
                            st.error(str(e))

    back_home("additive")
    
def page_columnar():
    algo_header("columnar", "اكتب كلمة مفتاحية إنجليزية (مثل <b>ZEBRA</b>) — تُقرأ الأعمدة حسب الترتيب الأبجدي لحروفها.")
    tab1, tab2 = st.tabs(["🔒 التشفير (Encrypt)", "🔓 فك التشفير (Decrypt)"])
    with tab1:
        with st.container(border=True):
            text = st.text_area("النص العادي:", key="col_e_t")
            key = st.text_input("الكلمة المفتاحية (مثال ZEBRA):", key="col_e_k")
            if st.button("🗂️ تشفير تبديلي عمودي", key="col_e_b", use_container_width=True):
                st.success("✨ تم التشفير بنجاح!")
                st.code(columnar_transposition_encrypt(text, key.upper()), language="text")
    with tab2:
        with st.container(border=True):
            text = st.text_area("النص المشفر:", key="col_d_t")
            key = st.text_input("الكلمة المفتاحية:", key="col_d_k")
            if st.button("🗂️ فك تشفير تبديلي عمودي", key="col_d_b", use_container_width=True):
                st.success("✨ تم فك التشفير بنجاح!")
                st.code(columnar_transposition_decrypt(text, key.upper()), language="text")
    back_home("columnar")


def page_pbox():
    algo_header("pbox", "طول النص يجب أن يساوي عدد خانات المفتاح (مثال: النص <b>ABCD</b> والمفتاح <b>2,0,3,1</b>).")
    tab1, tab2 = st.tabs(["🔒 التشفير (Encrypt)", "🔓 فك التشفير (Decrypt)"])
    with tab1:
        with st.container(border=True):
            text = st.text_area("النص:", key="pb_e_t")
            key = st.text_input("المفتاح (مفصول بفواصل):", key="pb_e_k")
            if st.button("🔀 تشفير P-Box", key="pb_e_b", use_container_width=True):
                try:
                    st.success("✨ تم التشفير بنجاح!")
                    st.code(pbox_encrypt(sanitize_text(text, allow_spaces=False), key), language="text")
                except Exception as e:
                    st.error(str(e))
    with tab2:
        with st.container(border=True):
            text = st.text_area("النص المشفر:", key="pb_d_t")
            key = st.text_input("المفتاح (مفصول بفواصل):", key="pb_d_k")
            if st.button("🔀 فك تشفير P-Box", key="pb_d_b", use_container_width=True):
                try:
                    st.success("✨ تم فك التشفير بنجاح!")
                    st.code(pbox_decrypt(sanitize_text(text, allow_spaces=False), key), language="text")
                except Exception as e:
                    st.error(str(e))
    back_home("pbox")


def page_rsa():
    algo_header("rsa", "خوارزمية <b>غير متماثلة</b>: ولّد زوج المفاتيح ← شفّر بالمفتاح العام ← فُك بالمفتاح الخاص (صيغة PEM النظامية).")
    rsa_tool = RSACipher()
    if 'rsa_pub_enc' not in st.session_state:
        st.session_state['rsa_pub_enc'] = ""
    if 'rsa_priv_dec' not in st.session_state:
        st.session_state['rsa_priv_dec'] = ""
    tab1, tab2 = st.tabs(["🔒 التشفير (Public Key)", "🔓 فك التشفير (Private Key)"])
    with tab1:
        with st.container(border=True):
            st.subheader("تشفير RSA الآمن")
            if st.button("⚡ توليد زوج مفاتيح جديد مؤقت", key="rsa_gen_btn_e", use_container_width=True):
                pub_k, priv_k = rsa_tool.generate_keys(1024)
                st.session_state['rsa_pub_enc'] = pub_k.save_pkcs1().decode('utf-8')
                st.session_state['rsa_priv_dec'] = priv_k.save_pkcs1().decode('utf-8')
                st.success("✨ تم توليد المفاتيح بنجاح وتحديث الحقول تلقائياً!")
                st.rerun() if hasattr(st, 'rerun') else st.experimental_rerun()
            pub_key_input = st.text_area("أدخل المفتاح العام (Public Key):", key="rsa_pub_enc", height=150)
            rsa_input_type = st.radio("اختر نوع مدخلات التشفير:", ["نص عادي", "ملف (File)"], key="rsa_enc_type", horizontal=True)
            text_to_enc, file_to_enc = "", None
            if rsa_input_type == "نص عادي":
                text_to_enc = st.text_area("أدخل النص المراد تشفيره:", key="rsa_enc_text")
            else:
                file_to_enc = st.file_uploader("اختر ملفاً لتشفيره:", key="rsa_enc_file")
            if st.button("🔐 تنفيذ تشفير RSA", key="rsa_enc_b", use_container_width=True):
                try:
                    if not pub_key_input.strip():
                        st.warning("⚠️ تنبيه: المفتاح العام فارغ.")
                    elif rsa_input_type == "نص عادي":
                        if not text_to_enc.strip():
                            st.warning("⚠️ تنبيه: يرجى كتابة النص المراد تشفيره.")
                        else:
                            st.success("✨ تم التشفير بنجاح!")
                            st.code(rsa_tool.encrypt_text(text_to_enc, pub_key_input), language="text")
                    else:
                        if file_to_enc is None:
                            st.warning("⚠️ تنبيه: يرجى رفع ملف أولاً.")
                        else:
                            enc_bytes = rsa_tool.encrypt_bytes(file_to_enc.read(), pub_key_input)
                            st.success("✨ تم تشفير الملف بنجاح!")
                            st.download_button("تحميل الملف المشفر", data=enc_bytes, file_name="encrypted_file.enc", mime="application/octet-stream")
                except Exception as e:
                    st.error(f"❌ خطأ معالجة المدخلات: {str(e)}")
    with tab2:
        with st.container(border=True):
            st.subheader("فك تشفير RSA الآمن")
            priv_key_input = st.text_area("أدخل المفتاح الخاص (Private Key):", key="rsa_priv_dec", height=150)
            rsa_dec_type = st.radio("اختر نوع مدخلات فك التشفير:", ["نص مشفر (Base64)", "ملف مشفر (File)"], key="rsa_dec_type", horizontal=True)
            text_to_dec, file_to_dec = "", None
            if rsa_dec_type == "نص مشفر (Base64)":
                text_to_dec = st.text_area("أدخل النص المشفر:", key="rsa_dec_text")
            else:
                file_to_dec = st.file_uploader("اختر الملف المشفر:", key="rsa_dec_file")
            if st.button("🔓 تنفيذ فك تشفير RSA", key="rsa_dec_b", use_container_width=True):
                try:
                    if not priv_key_input.strip():
                        st.warning("⚠️ تنبيه: المفتاح الخاص فارغ.")
                    elif rsa_dec_type == "نص مشفر (Base64)":
                        if not text_to_dec.strip():
                            st.warning("⚠️ تنبيه: يرجى إدخال النص المشفر.")
                        else:
                            st.success("✨ تم فك التشفير بنجاح:")
                            st.code(rsa_tool.decrypt_text(text_to_dec.strip(), priv_key_input), language="text")
                    else:
                        if file_to_dec is None:
                            st.warning("⚠️ تنبيه: يرجى رفع الملف المشفر أولاً.")
                        else:
                            dec_bytes = rsa_tool.decrypt_bytes(file_to_dec.read(), priv_key_input)
                            st.success("✨ تم فك تشفير الملف بنجاح!")
                            st.download_button("تحميل الملف الأصلي", data=dec_bytes, file_name="decrypted_file.txt", mime="application/octet-stream")
                except Exception as e:
                    st.error(f"❌ خطأ في فك التشفير: {str(e)}")
    back_home("rsa")
def page_aes():
    algo_header("aes", "تشفير <b>عسكري</b>: يمكنك استخدام أي كلمة مرور (تشفير متماثل). النظام يشتق منها مفتاحاً قوياً جداً بـ 256-بت باستخدام دالة SCrypt لتوفير أقصى درجات الحماية ضد هجمات كسر كلمات المرور.")
    aes_tool = AESCipher()
    
    tab1, tab2 = st.tabs(["🔒 التشفير (Encrypt) - أعلى حماية", "🔓 فك التشفير (Decrypt)"])
    with tab1:
        with st.container(border=True):
            st.subheader("تشفير AES-GCM (التشفير والتوثيق)")
            aes_password = st.text_input("أدخل كلمة المرور للتشفير:", type="password", key="aes_enc_pass")
            aes_input_type = st.radio("ماذا تريد أن تشفر؟", ["نص (Text)", "ملف (File)"], key="aes_enc_type", horizontal=True)
            
            if aes_input_type == "نص (Text)":
                text_to_enc = st.text_area("أدخل النص (يدعم نصوصاً طويلة جداً):", key="aes_enc_text")
                if st.button("🛡️ تشفير النص فوراً", key="aes_enc_btn_txt", use_container_width=True):
                    if not aes_password.strip():
                        st.warning("⚠️ يجب إدخال كلمة مرور.")
                    elif not text_to_enc.strip():
                        st.warning("⚠️ يجب إدخال النص.")
                    else:
                        try:
                            result = aes_tool.encrypt_text(text_to_enc, aes_password)
                            st.success("✨ تمت حماية النص بنجاح!")
                            st.code(result, language="text")
                        except Exception as e:
                            st.error(str(e))
            else:
                file_to_enc = st.file_uploader("اختر ملفاً (صور، PDF، مستندات):", key="aes_enc_file")
                if st.button("🛡️ تشفير وحماية الملف", key="aes_enc_btn_file", use_container_width=True):
                    if not aes_password.strip():
                        st.warning("⚠️ يجب إدخال كلمة مرور.")
                    elif file_to_enc is None:
                        st.warning("⚠️ يرجى رفع ملف.")
                    else:
                        try:
                            enc_bytes = aes_tool.encrypt_bytes(file_to_enc.read(), aes_password)
                            st.success("✨ تم تشفير الملف. لا يمكن فتحه الآن إلا بكلمة المرور.")
                            st.download_button("📥 تحميل الملف المشفر", data=enc_bytes, file_name="secured_file.aes", mime="application/octet-stream")
                        except Exception as e:
                            st.error(str(e))

    with tab2:
        with st.container(border=True):
            st.subheader("فك التشفير (يحتاج كلمة المرور الأصلية)")
            aes_password_dec = st.text_input("أدخل كلمة المرور الأصلية:", type="password", key="aes_dec_pass")
            aes_dec_type = st.radio("ماذا تريد أن تفك تشفيره؟", ["نص مشفر", "ملف مشفر (.aes)"], key="aes_dec_type", horizontal=True)
            
            if aes_dec_type == "نص مشفر":
                text_to_dec = st.text_area("الصق النص المشفر هنا:", key="aes_dec_text")
                if st.button("🔓 فك التشفير", key="aes_dec_btn_txt", use_container_width=True):
                    if not aes_password_dec.strip():
                         st.warning("⚠️ يرجى إدخال كلمة المرور.")
                    elif not text_to_dec.strip():
                         st.warning("⚠️ يرجى إدخال النص المشفر.")
                    else:
                        try:
                            result = aes_tool.decrypt_text(text_to_dec.strip(), aes_password_dec)
                            st.success("✨ تم فك التشفير واستعادة النص بنجاح!")
                            st.code(result, language="text")
                        except Exception as e:
                            st.error(str(e))
            else:
                file_to_dec = st.file_uploader("ارفع الملف المشفر:", key="aes_dec_file")
                file_name_out = st.text_input("صيغة واسم الملف المسترجع (مثال: image.jpg):", value="decrypted_file.txt")
                if st.button("🔓 استرجاع الملف", key="aes_dec_btn_file", use_container_width=True):
                    if not aes_password_dec.strip():
                         st.warning("⚠️ يرجى إدخال كلمة المرور.")
                    elif file_to_dec is None:
                         st.warning("⚠️ يرجى رفع الملف المشفر.")
                    else:
                        try:
                            dec_bytes = aes_tool.decrypt_bytes(file_to_dec.read(), aes_password_dec)
                            st.success("✨ تم فك تشفير واسترجاع الملف بنجاح!")
                            st.download_button("📥 تحميل الملف المسترجع", data=dec_bytes, file_name=file_name_out, mime="application/octet-stream")
                        except Exception as e:
                            st.error(str(e))

    back_home("aes")

def page_rc4():
    algo_header("rc4", "شفرة <b>سيلانية</b>: المفتاح السري نفسه يُستخدم للتشفير والفك — الناتج النصي بصيغة Base64، والملفات تُشفّر بايت ببايت.")
    rc4_tool = RC4Cipher()
    tab1, tab2 = st.tabs(["🔒 التشفير (Encrypt)", "🔓 فك التشفير (Decrypt)"])
    with tab1:
        with st.container(border=True):
            st.subheader("تشفير RC4 الآمن")
            rc4_key_enc = st.text_input("أدخل المفتاح السري (Secret Key):", type="password", key="rc4_key_enc")
            rc4_input_type = st.radio("اختر نوع مدخلات التشفير:", ["نص عادي", "ملف (File)"], key="rc4_enc_type", horizontal=True)
            text_to_enc, file_to_enc = "", None
            if rc4_input_type == "نص عادي":
                text_to_enc = st.text_area("أدخل النص المراد تشفيره:", key="rc4_enc_text")
            else:
                file_to_enc = st.file_uploader("اختر ملفاً لتشفيره:", key="rc4_enc_file")
            if st.button("⚡ تنفيذ تشفير RC4", key="rc4_enc_b", use_container_width=True):
                try:
                    if not rc4_key_enc.strip():
                        st.warning("⚠️ تنبيه: المفتاح السري فارغ.")
                    elif rc4_input_type == "نص عادي":
                        if not text_to_enc.strip():
                            st.warning("⚠️ تنبيه: يرجى كتابة النص المراد تشفيره.")
                        else:
                            st.success("✨ تم التشفير بنجاح!")
                            st.code(rc4_tool.encrypt_text(text_to_enc, rc4_key_enc), language="text")
                    else:
                        if file_to_enc is None:
                            st.warning("⚠️ تنبيه: يرجى رفع ملف أولاً.")
                        else:
                            enc_bytes = rc4_tool.encrypt_bytes(file_to_enc.read(), rc4_key_enc)
                            st.success("✨ تم تشفير الملف بنجاح!")
                            st.download_button("تحميل الملف المشفر", data=enc_bytes, file_name="rc4_encrypted.enc", mime="application/octet-stream")
                except Exception as e:
                    st.error(f"❌ خطأ معالجة المدخلات: {str(e)}")
    with tab2:
        with st.container(border=True):
            st.subheader("فك تشفير RC4 الآمن")
            rc4_key_dec = st.text_input("أدخل المفتاح السري (Secret Key):", type="password", key="rc4_key_dec")
            rc4_dec_type = st.radio("اختر نوع مدخلات فك التشفير:", ["نص مشفر (Base64)", "ملف مشفر (File)"], key="rc4_dec_type", horizontal=True)
            text_to_dec, file_to_dec = "", None
            if rc4_dec_type == "نص مشفر (Base64)":
                text_to_dec = st.text_area("أدخل النص المشفر:", key="rc4_dec_text")
            else:
                file_to_dec = st.file_uploader("اختر الملف المشفر:", key="rc4_dec_file")
            if st.button("⚡ تنفيذ فك تشفير RC4", key="rc4_dec_b", use_container_width=True):
                try:
                    if not rc4_key_dec.strip():
                        st.warning("⚠️ تنبيه: المفتاح السري فارغ.")
                    elif rc4_dec_type == "نص مشفر (Base64)":
                        if not text_to_dec.strip():
                            st.warning("⚠️ تنبيه: يرجى إدخال النص المشفر.")
                        else:
                            st.success("✨ تم فك التشفير بنجاح:")
                            st.code(rc4_tool.decrypt_text(text_to_dec.strip(), rc4_key_dec), language="text")
                    else:
                        if file_to_dec is None:
                            st.warning("⚠️ تنبيه: يرجى رفع الملف المشفر أولاً.")
                        else:
                            dec_bytes = rc4_tool.decrypt_bytes(file_to_dec.read(), rc4_key_dec)
                            st.success("✨ تم فك تشفير الملف بنجاح!")
                            st.download_button("تحميل الملف الأصلي", data=dec_bytes, file_name="rc4_decrypted.txt", mime="application/octet-stream")
                except Exception as e:
                    st.error(f"❌ خطأ في فك التشفير: {str(e)}")
    back_home("rc4")


def page_des():
    algo_header("des", "في DES يجب أن يكون المفتاح السري مكونًا من <b>8 أحرف بالضبط</b> — يُشتق منه 16 مفتاحًا فرعيًا عبر شبكة فيستل.")
    tab1, tab2 = st.tabs(["🔒 التشفير (Encrypt)", "🔓 فك التشفير (Decrypt)"])
    with tab1:
        with st.container(border=True):
            text = st.text_area("أدخل النص العادي لتشفيره:", key="des_enc_text")
            key = st.text_input("أدخل المفتاح السري (8 أحرف):", max_chars=8, key="des_enc_key", type="password")
            if st.button("🗝️ تشفير DES", key="des_enc_btn", use_container_width=True):
                try:
                    if not text.strip() or not key:
                        st.warning("الرجاء إدخال النص والمفتاح.")
                    else:
                        st.success("✨ تم التشفير بنجاح!")
                        st.code(des_encrypt(text, key), language="text")
                except ValueError as ve:
                    st.error(f"خطأ: {ve}")
                except Exception as e:
                    st.error(f"حدث خطأ غير متوقع: {e}")
    with tab2:
        with st.container(border=True):
            text = st.text_area("أدخل النص المشفر (بصيغة Hex):", key="des_dec_text")
            key = st.text_input("أدخل المفتاح السري (8 أحرف):", max_chars=8, key="des_dec_key", type="password")
            if st.button("🗝️ فك تشفير DES", key="des_dec_btn", use_container_width=True):
                try:
                    if not text.strip() or not key:
                        st.warning("الرجاء إدخال النص المشفر والمفتاح.")
                    else:
                        st.success("✨ تم فك التشفير بنجاح!")
                        st.code(des_decrypt(text.strip(), key), language="text")
                except ValueError as ve:
                    st.error(f"خطأ: {ve}")
                except Exception as e:
                    st.error(f"حدث خطأ غير متوقع: {e}")
    back_home("des")


# ============================================================
#  الشريط الجانبي + التوجيه
# ============================================================

html("""
<div class="cm-logo" dir="rtl">
  <div class="cm-logo-ico">🔐</div>
  <div class="cm-logo-txt"><b>CryptoMatrix</b><span>مصفوفة التشفير المتكاملة</span></div>
</div>
""", st.sidebar)
html("<hr class='cm-hr'>", st.sidebar)
html("<div class='cm-sb-cap' dir='rtl'>🧭 التنقّل بين الخوارزميات</div>", st.sidebar)

if "nav" not in st.session_state:
    st.session_state["nav"] = NAV["home"]

choice = st.sidebar.radio("nav", list(NAV.values()), key="nav", label_visibility="collapsed")
html("<hr class='cm-hr'>", st.sidebar)
html("<div class='cm-sb-tip' dir='rtl'>💡 من الصفحة الرئيسية اضغط «استكشف» على أي بطاقة للانتقال السريع.</div>", st.sidebar)
html("<div class='cm-sb-foot'>CryptoMatrix · NeoGlass v2.1<br/>جميع العمليات تُنفّذ محليًا 🔒</div>", st.sidebar)

PAGES = {
    "binary": page_binary, "caesar": page_caesar, "multiplicative": page_multiplicative,
    "additive": page_additive, "columnar": page_columnar, "pbox": page_pbox,
    "aes": page_aes, # ← أضف هذا السطر هنا
    "rsa": page_rsa, "rc4": page_rc4, "des": page_des,
}

page = LABEL2KEY[choice]
if page == "home":
    render_home()
else:
    PAGES[page]()