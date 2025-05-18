DENCODER.py
A powerful and flexible command-line tool for encoding, decoding, and analyzing text and files across a wide range of codecs and formats.

✨ Features
🔡 Encode/decode text using:

Character encodings: UTF-8, UTF-16, UTF-32, Latin-1, Shift_JIS, EBCDIC, etc.

Base encodings: Base64, Base32, Base58, Base62, Base85, Base91, Z85, Base36, Base2

ASCII code point encoding (e.g., 72 101 108 108 111 for "Hello")

🕵️ Automatic encoding detection using chardet

🧠 Smart decoding:

Auto-detects Base encodings like Base64, Base58, Base62, Base85, Base2, etc.

Automatically decodes ASCII numeric code points if detected

📂 File support:

Encode/decode files or batch-process multiple files

Save outputs to specified output files

📦 Requirements
Some features require optional packages:




pip install chardet pyzmq base91
🚀 Usage



python DENCODER.py -codec <codec> <encode|decode> <text|-f files> [-output outputs]
📘 Options
Flag	Description
-help	Show usage instructions
-codec	Specify codec to encode/decode with
-f	Input file(s), comma-separated
-output	Output file(s), comma-separated
-identify	Identify encoding of input file(s)
-auto	Auto-detect and decode encoding from text or files
-minconf	Set minimum confidence for encoding detection (default: 0.85)

🧪 Examples
🔤 Encode & Decode Strings



-python DENCODER.py -codec ascii encode "Hello"
-python DENCODER.py -codec base64 decode "SGVsbG8="
📝 Encode/Decode Files



-python DENCODER.py -codec utf-16 encode -f input.txt -output out.txt
-python DENCODER.py -codec base58 decode -f encoded1.txt,encoded2.txt -output decoded1.txt,decoded2.txt
🔍 Identify File Encoding



-python DENCODER.py -identify -f unknown.txt
🧠 Auto Decode Text or Files



-python DENCODER.py -auto "SGVsbG8gd29ybGQh"
-python DENCODER.py -auto -f mysterious.txt
🧬 Supported Codecs



ascii, utf-8, utf-16, utf-32, latin-1, windows-1252, shift_jis, big5, ebcdic
base64, base32, base16, base58, base62, base85, ascii85, z85, base91, base36, base2
🧩 Optional Dependencies
Codec	Module Required	Install Command
Z85	pyzmq	pip install pyzmq
Base91	base91	pip install base91
Auto ID	chardet	pip install chardet

🛠 Developer Notes
This script is modular and easy to extend with new codecs. It also features color-coded CLI output for better visibility of errors and warnings.

