import sys
import base64
import binascii

def color(text, color_code):
    return f"\033[{color_code}m{text}\033[0m"

def encoder(text):
    # Encodes text to space-separated ASCII codes
    return ' '.join(str(ord(char)) for char in text)

def decoder(ascii_string):
    # Decodes space-separated ASCII codes to text
    try:
        return ''.join(chr(int(code)) for code in ascii_string.split())
    except ValueError:
        return color("Invalid ASCII input for decoding.", "1;31")

SUPPORTED_CODECS = {
    "ascii": "ascii",
    "utf-8": "utf-8",
    "utf-16": "utf-16",
    "utf-32": "utf-32",
    "latin-1": "latin-1",
    "iso-8859-1": "latin-1",
    "windows-1252": "cp1252",
    "shift_jis": "shift_jis",
    "big5": "big5",
    "ebcdic": "cp500",
    "base64": "base64",
    "base32": "base32",
    "base16": "base16",
    "base58": "base58",
    "base62": "base62",
    "base85": "base85",
    "ascii85": "base85",
    "z85": "z85",
    "base91": "base91",
    "base36": "base36",
    "base2": "base2"
}

# Base58 alphabet (Bitcoin)
BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

def base58_encode(data: bytes) -> str:
    num = int.from_bytes(data, 'big')
    encode = ''
    while num > 0:
        num, rem = divmod(num, 58)
        encode = BASE58_ALPHABET[rem] + encode
    # Add '1' for each leading 0 byte
    n_pad = len(data) - len(data.lstrip(b'\0'))
    return '1' * n_pad + encode

def base58_decode(s: str) -> bytes:
    num = 0
    for c in s:
        num = num * 58 + BASE58_ALPHABET.index(c)
    # Convert number back to bytes
    b = num.to_bytes((num.bit_length() + 7) // 8, 'big')
    # Add leading zero bytes
    n_pad = len(s) - len(s.lstrip('1'))
    return b'\0' * n_pad + b

# Base62 alphabet
BASE62_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

def base62_encode(data: bytes) -> str:
    num = int.from_bytes(data, 'big')
    encode = ''
    while num > 0:
        num, rem = divmod(num, 62)
        encode = BASE62_ALPHABET[rem] + encode
    n_pad = len(data) - len(data.lstrip(b'\0'))
    return BASE62_ALPHABET[0] * n_pad + encode

def base62_decode(s: str) -> bytes:
    num = 0
    for c in s:
        num = num * 62 + BASE62_ALPHABET.index(c)
    b = num.to_bytes((num.bit_length() + 7) // 8, 'big')
    n_pad = len(s) - len(s.lstrip(BASE62_ALPHABET[0]))
    return b'\0' * n_pad + b

# Z85 alphabet (ZeroMQ)
Z85_ALPHABET = (
    "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#"
)

def z85_encode(data: bytes) -> str:
    try:
        import zmq.utils.z85 as z85
        return z85.encode(data).decode()
    except ImportError:
        return color("Z85 encoding requires pyzmq (pip install pyzmq)", "1;31")

def z85_decode(s: str) -> bytes:
    try:
        import zmq.utils.z85 as z85
        return z85.decode(s.encode())
    except ImportError:
        return color("Z85 decoding requires pyzmq (pip install pyzmq)", "1;31")

# Base91 (requires external package)
def base91_encode(data: bytes) -> str:
    try:
        import base91
        return base91.encode(data)
    except ImportError:
        return color("Base91 encoding requires base91 (pip install base91)", "1;31")

def base91_decode(s: str) -> bytes:
    try:
        import base91
        return base91.decode(s)
    except ImportError:
        return color("Base91 decoding requires base91 (pip install base91)", "1;31")

def base36_encode(data: bytes) -> str:
    num = int.from_bytes(data, 'big')
    return format(num, 'x') if num else '0'

def base36_decode(s: str) -> bytes:
    num = int(s, 36)
    return num.to_bytes((num.bit_length() + 7) // 8, 'big')

def base2_encode(data: bytes) -> str:
    return ''.join(f"{byte:08b}" for byte in data)

def base2_decode(s: str) -> bytes:
    s = s.replace(" ", "")
    return int(s, 2).to_bytes((len(s) + 7) // 8, 'big')

def codec_encoder(text, codec):
    # ...existing code for ascii...
    if codec == "ascii":
        return encoder(text)
    data = text.encode("utf-8")
    try:
        if codec == "base64":
            return base64.b64encode(data).decode()
        elif codec == "base32":
            return base64.b32encode(data).decode()
        elif codec == "base16":
            return base64.b16encode(data).decode()
        elif codec == "base58":
            return base58_encode(data)
        elif codec == "base62":
            return base62_encode(data)
        elif codec in ("base85", "ascii85"):
            return base64.a85encode(data).decode()
        elif codec == "z85":
            return z85_encode(data)
        elif codec == "base91":
            return base91_encode(data)
        elif codec == "base36":
            return base36_encode(data)
        elif codec == "base2":
            return base2_encode(data)
        else:
            encoded = text.encode(codec)
            return ' '.join(f"{b:02x}" for b in encoded)
    except Exception as e:
        return color(f"Encoding error: {e}", "1;31")

def codec_decoder(input_string, codec):
    # ...existing code for ascii...
    if codec == "ascii":
        return decoder(input_string)
    try:
        if codec == "base64":
            return base64.b64decode(input_string).decode("utf-8")
        elif codec == "base32":
            return base64.b32decode(input_string).decode("utf-8")
        elif codec == "base16":
            return base64.b16decode(input_string).decode("utf-8")
        elif codec == "base58":
            return base58_decode(input_string).decode("utf-8")
        elif codec == "base62":
            return base62_decode(input_string).decode("utf-8")
        elif codec in ("base85", "ascii85"):
            return base64.a85decode(input_string).decode("utf-8")
        elif codec == "z85":
            decoded = z85_decode(input_string)
            if isinstance(decoded, str):
                return decoded  # error message
            return decoded.decode("utf-8")
        elif codec == "base91":
            decoded = base91_decode(input_string)
            if isinstance(decoded, str):
                return decoded  # error message
            return decoded.decode("utf-8")
        elif codec == "base36":
            return base36_decode(input_string).decode("utf-8")
        elif codec == "base2":
            return base2_decode(input_string).decode("utf-8")
        else:
            # hex string to bytes, then decode
            hex_string = input_string.replace(",", " ").replace("\n", " ")
            byte_values = bytes(int(b, 16) for b in hex_string.split())
            return byte_values.decode(codec)
    except Exception as e:
        return color(f"Decoding error: {e}", "1;31")

def identify_file(filename):
    try:
        import chardet
    except ImportError:
        return color("chardet module required for identification (pip install chardet)", "1;31")
    try:
        with open(filename, "rb") as f:
            raw = f.read()
        result = chardet.detect(raw)
        encoding = result.get("encoding", "unknown")
        confidence = result.get("confidence", 0)
        return f"{filename}: {encoding} (confidence: {confidence:.2f})"
    except Exception as e:
        return color(f"Error identifying {filename}: {e}", "1;31")

def identify_files(filenames):
    results = []
    for filename in filenames:
        results.append(identify_file(filename))
    return results

def auto_identify_and_decode_file(filename, min_confidence=0.85):
    try:
        import chardet
    except ImportError:
        return color("chardet module required for auto identification (pip install chardet)", "1;31")
    try:
        with open(filename, "rb") as f:
            raw = f.read()
        result = chardet.detect(raw)
        encoding = result.get("encoding", "unknown")
        confidence = result.get("confidence", 0)
        warn = ""
        if confidence < min_confidence:
            warn = color(f" [Warning: Low confidence ({confidence:.2f}) in detected encoding '{encoding}']", "1;33")
        decoded = None
        detected_codec = None
        # Try to decode using the detected encoding
        if encoding and encoding.lower() != "unknown":
            try:
                decoded = raw.decode(encoding, errors="replace")
                # If ascii and looks like numbers, try ascii decode
                if encoding.lower() == "ascii":
                    stripped = decoded.strip()
                    if all(part.isdigit() for part in stripped.split()):
                        ascii_decoded = decoder(stripped)
                        warn += color(" [Auto-decoded as ASCII code points]", "1;33")
                        decoded = ascii_decoded
                        detected_codec = "ascii"
            except Exception as e:
                decoded = color(f"Decoding failed: {e}", "1;31")
        else:
            # Try common fallbacks if detection failed
            for fallback in ["utf-8", "latin-1"]:
                try:
                    decoded = raw.decode(fallback, errors="replace")
                    warn += color(f" [Tried fallback: {fallback}]", "1;33")
                    break
                except Exception:
                    decoded = color("Encoding could not be detected or decoded.", "1;31")
        # Try to analyze for common encoded formats if ascii or unknown
        import re
        candidate = decoded if isinstance(decoded, str) else ""
        # Only try if not already decoded as ascii code points
        if detected_codec != "ascii" and isinstance(candidate, str):
            stripped = candidate.strip()
            # Try base64
            base64_pattern = r"^[A-Za-z0-9+/=\s]+$"
            base32_pattern = r"^[A-Z2-7= \n\r\t]+$"
            base16_pattern = r"^[A-F0-9= \n\r\t]+$"
            base58_pattern = r"^[1-9A-HJ-NP-Za-km-z]+$"
            base62_pattern = r"^[0-9A-Za-z]+$"
            base85_pattern = r"^[!-u\s]+$"
            base91_pattern = r"^[A-Za-z0-9!#$%&()*+,./:;<=>?@[]^_`{|}~\"'-]+$"
            base36_pattern = r"^[0-9a-zA-Z]+$"
            base2_pattern = r"^[01\s]+$"
            # Try base64
            try:
                if re.fullmatch(base64_pattern, stripped) and len(stripped.replace(" ", "")) % 4 == 0:
                    decoded_try = base64.b64decode(stripped, validate=True)
                    decoded = decoded_try.decode("utf-8", errors="replace")
                    warn += color(" [Auto-decoded as base64]", "1;33")
                    detected_codec = "base64"
                elif re.fullmatch(base32_pattern, stripped) and len(stripped.replace(" ", "")) % 8 == 0:
                    decoded_try = base64.b32decode(stripped)
                    decoded = decoded_try.decode("utf-8", errors="replace")
                    warn += color(" [Auto-decoded as base32]", "1;33")
                    detected_codec = "base32"
                elif re.fullmatch(base16_pattern, stripped) and len(stripped.replace(" ", "")) % 2 == 0:
                    decoded_try = base64.b16decode(stripped)
                    decoded = decoded_try.decode("utf-8", errors="replace")
                    warn += color(" [Auto-decoded as base16]", "1;33")
                    detected_codec = "base16"
                elif re.fullmatch(base58_pattern, stripped) and len(stripped) > 5:
                    try:
                        decoded_try = base58_decode(stripped)
                        decoded = decoded_try.decode("utf-8", errors="replace")
                        warn += color(" [Auto-decoded as base58]", "1;33")
                        detected_codec = "base58"
                    except Exception:
                        pass
                elif re.fullmatch(base62_pattern, stripped) and len(stripped) > 5:
                    try:
                        decoded_try = base62_decode(stripped)
                        decoded = decoded_try.decode("utf-8", errors="replace")
                        warn += color(" [Auto-decoded as base62]", "1;33")
                        detected_codec = "base62"
                    except Exception:
                        pass
                elif re.fullmatch(base85_pattern, stripped) and len(stripped) > 5:
                    try:
                        decoded_try = base64.a85decode(stripped)
                        decoded = decoded_try.decode("utf-8", errors="replace")
                        warn += color(" [Auto-decoded as base85]", "1;33")
                        detected_codec = "base85"
                    except Exception:
                        pass
                elif re.fullmatch(base2_pattern, stripped) and len(stripped.replace(" ", "")) % 8 == 0:
                    try:
                        decoded_try = base2_decode(stripped)
                        decoded = decoded_try.decode("utf-8", errors="replace")
                        warn += color(" [Auto-decoded as base2]", "1;33")
                        detected_codec = "base2"
                    except Exception:
                        pass
                elif re.fullmatch(base36_pattern, stripped) and len(stripped) > 5:
                    try:
                        decoded_try = base36_decode(stripped)
                        decoded = decoded_try.decode("utf-8", errors="replace")
                        warn += color(" [Auto-decoded as base36]", "1;33")
                        detected_codec = "base36"
                    except Exception:
                        pass
                # Try base91 if installed
                elif re.fullmatch(base91_pattern, stripped) and len(stripped) > 5:
                    try:
                        decoded_try = base91_decode(stripped)
                        if not isinstance(decoded_try, str):
                            decoded = decoded_try.decode("utf-8", errors="replace")
                            warn += color(" [Auto-decoded as base91]", "1;33")
                            detected_codec = "base91"
                    except Exception:
                        pass
                # Try Z85 if installed
                elif len(stripped) % 5 == 0 and len(stripped) > 5:
                    try:
                        decoded_try = z85_decode(stripped)
                        if not isinstance(decoded_try, str):
                            decoded = decoded_try.decode("utf-8", errors="replace")
                            warn += color(" [Auto-decoded as z85]", "1;33")
                            detected_codec = "z85"
                    except Exception:
                        pass
                # Try ascii code points (again, if not already detected)
                elif all(part.isdigit() for part in stripped.split()):
                    ascii_decoded = decoder(stripped)
                    warn += color(" [Auto-decoded as ASCII code points]", "1;33")
                    decoded = ascii_decoded
                    detected_codec = "ascii"
            except Exception:
                pass
        return f"{filename}: {encoding} (confidence: {confidence:.2f}){warn}\n{decoded}"
    except Exception as e:
        return color(f"Error auto-decoding {filename}: {e}", "1;31")

def auto_identify_and_decode_text(text, min_confidence=0.85):
    try:
        import chardet
    except ImportError:
        return color("chardet module required for auto identification (pip install chardet)", "1;31")
    raw = text.encode("utf-8", errors="replace")
    result = chardet.detect(raw)
    encoding = result.get("encoding", "unknown")
    confidence = result.get("confidence", 0)
    warn = ""
    if confidence < min_confidence:
        warn = color(f" [Warning: Low confidence ({confidence:.2f}) in detected encoding '{encoding}']", "1;33")
    try:
        decoded = raw.decode(encoding) if encoding != "unknown" else ""
    except Exception as e:
        decoded = color(f"Decoding failed: {e}", "1;31")
    return f"Detected: {encoding} (confidence: {confidence:.2f}){warn}\n{decoded}"

def print_help():
    print(color("DENCODER.py - A simple text encoder/decoder", "0;32"))
    print(color("Usage: python DENCODER.py -codec <codec> [encode|decode] [text|-f files] [-output outputs]", "1;32"))
    print(color(" Options:\n", "1;32"))
    print("\033[1;37;40m  -help        Show this help message and exit")
    print("\033[1;37;40m  -codec       Encode or decode using a specific codec")
    print("\033[1;37;40m  -f           Specify a file to read from (comma-separated for multiple files)")
    print("\033[1;37;40m  -output      Specify an output file for the result (comma-separated for multiple files)")
    print("\033[1;37;40m  -identify    Identify the encoding of one or more files")
    print("\033[1;37;40m  -auto        Auto-detect encoding and decode text or files")
    print("\033[1;37;40m  -minconf     Set minimum confidence for auto-detection warning (default 0.85)")
    print(color("\n Supported codecs:", "1;36"))
    print("   ascii, utf-8, utf-16, utf-32, iso-8859-1 (latin-1), windows-1252, shift_jis, big5, ebcdic")
    print("   base64, base32, base16, base58, base62, base85 (ascii85), z85, base91, base36, base2")
    print(color("\n Examples:\n", "1;32"))
    print("  python DENCODER.py -codec ascii encode 'Hello'")
    print("                     -codec base64 encode 'Hello'")
    print("                     -codec base64 decode 'SGVsbG8='")
    print("                     -codec base58 encode 'Hello'")
    print("                     -codec ascii decode -f file1,file2 -output output1,output2")
    print("                     -codec utf-16 encode 'Hello'")
    print("                     -codec shift_jis decode -f encoded.txt -output decoded.txt")
    print("                     -identify file1.txt,file2.txt")
    print("                     -auto -f file1.txt,file2.txt")
    print("                     -auto 'some text to identify'")
    print("")
    # ...existing code...

def process_file(filename, action):
    try:
        with open(filename, "r", encoding="utf-8") as f:
            content = f.read()
        if action == "encode":
            result = encoder(content)
        elif action == "decode":
            result = decoder(content)
        else:
            return color("Unknown action for file processing.", "1;31")
        return result
    except FileNotFoundError:
        return color(f"File not found: {filename}", "1;31")
    except Exception as e:
        return color(f"Error processing file: {e}", "1;31")

def save_output(result, filename):
    try:
        with open(filename, "w", encoding="utf-8") as f:
            f.write(result)
        print(color(f"Output saved to {filename}", "1;34"))
    except Exception as e:
        print(color(f"Error saving output: {e}", "1;31"))

def process_files(filenames, action, codec):
    results = []
    for filename in filenames:
        try:
            with open(filename, "r", encoding="utf-8") as f:
                content = f.read()
            if action == "encode":
                result = codec_encoder(content, codec)
            elif action == "decode":
                result = codec_decoder(content, codec)
            else:
                result = color("Unknown action for file processing.", "1;31")
            results.append(result)
        except FileNotFoundError:
            results.append(color(f"File not found: {filename}", "1;31"))
        except Exception as e:
            results.append(color(f"Error processing file {filename}: {e}", "1;31"))
    return results

def save_outputs(results, output_files):
    for result, filename in zip(results, output_files):
        try:
            with open(filename, "w", encoding="utf-8") as f:
                f.write(result)
            print(color(f"Output saved to {filename}", "1;34"))
        except Exception as e:
            print(color(f"Error saving output to {filename}: {e}", "1;31"))

def split_arg_list(arg):
    # Split by comma, strip whitespace and quotes
    return [a.strip().strip('"').strip("'") for a in arg.split(",") if a.strip()]

def main():
    if len(sys.argv) == 1 or (len(sys.argv) > 1 and sys.argv[1] in ("-help", "--help", "-h")):
        print_help()
        return

    if "-auto" in sys.argv:
        idx = sys.argv.index("-auto")
        min_conf = 0.85
        if "-minconf" in sys.argv:
            conf_idx = sys.argv.index("-minconf")
            try:
                min_conf = float(sys.argv[conf_idx + 1])
            except Exception:
                print(color("Invalid value for -minconf, using default 0.85", "1;33"))
        if idx + 1 >= len(sys.argv):
            print(color("Usage: python DENCODER.py -auto [text|-f files] [-minconf value]", "1;31"))
            return
        if sys.argv[idx + 1] == "-f":
            if idx + 2 >= len(sys.argv):
                print(color("Usage: python DENCODER.py -auto -f file1[,file2,...] [-minconf value]", "1;31"))
                return
            file_arg = sys.argv[idx + 2]
            filenames = split_arg_list(file_arg)
            for filename in filenames:
                print(auto_identify_and_decode_file(filename, min_confidence=min_conf))
                print("-" * 40)
        else:
            text = ' '.join(sys.argv[idx + 1:])
            print(auto_identify_and_decode_text(text, min_confidence=min_conf))
        return

    if "-identify" in sys.argv:
        idx = sys.argv.index("-identify")
        if idx + 1 >= len(sys.argv):
            print(color("Usage: python DENCODER.py -identify [file1[,file2,...]|-f file1[,file2,...]]", "1;31"))
            return
        # Support both: -identify file1,file2 and -identify -f file1,file2
        if sys.argv[idx + 1] == "-f":
            if idx + 2 >= len(sys.argv):
                print(color("Usage: python DENCODER.py -identify -f file1[,file2,...]", "1;31"))
                return
            file_arg = sys.argv[idx + 2]
        else:
            file_arg = sys.argv[idx + 1]
        filenames = split_arg_list(file_arg)
        results = identify_files(filenames)
        for res in results:
            print(res)
        return

    # Unified codec-based encoding/decoding (including ascii)
    if "-codec" in sys.argv:
        codec_idx = sys.argv.index("-codec")
        if codec_idx + 1 >= len(sys.argv):
            print(color("Please specify a codec after -codec.", "1;31"))
            return
        codec_name = sys.argv[codec_idx + 1].lower().replace("-", "_")
        codec = SUPPORTED_CODECS.get(codec_name)
        if not codec:
            print(color(f"Unsupported codec: {codec_name}", "1;31"))
            print("Supported codecs:", ", ".join(SUPPORTED_CODECS.keys()))
            return
        if codec_idx + 2 >= len(sys.argv):
            print(color("Please specify encode or decode after codec.", "1;31"))
            return
        action = sys.argv[codec_idx + 2]
        output_files = []
        if "-output" in sys.argv:
            output_idx = sys.argv.index("-output")
            if output_idx + 1 < len(sys.argv):
                output_arg = sys.argv[output_idx + 1]
                output_files = split_arg_list(output_arg)
            else:
                print(color("Missing filename for -output option.", "1;31"))
                return
            args_end = output_idx
        else:
            args_end = len(sys.argv)
        if codec_idx + 3 < len(sys.argv) and sys.argv[codec_idx + 3] == "-f":
            if args_end < codec_idx + 5:
                print(color("Usage: python DENCODER.py -codec <codec> [encode|decode] -f file1[,file2,...] [-output out1[,out2,...]]", "1;31"))
                return
            file_arg = sys.argv[codec_idx + 4]
            filenames = split_arg_list(file_arg)
            results = process_files(filenames, action, codec)
            if output_files:
                if len(output_files) != len(results):
                    print(color("Number of output files must match number of input files.", "1;31"))
                    return
                save_outputs(results, output_files)
            else:
                for result in results:
                    print(result)
        else:
            # Text input
            input_text = ' '.join(sys.argv[codec_idx + 3:args_end])
            if action == "encode":
                result = codec_encoder(input_text, codec)
            elif action == "decode":
                result = codec_decoder(input_text, codec)
            else:
                print(color("Unknown action for codec. Use 'encode' or 'decode'.", "1;31"))
                return
            if output_files:
                if len(output_files) != 1:
                    print(color("Only one output file allowed for text input.", "1;31"))
                    return
                save_outputs([result], output_files)
            else:
                print(result)
        return

    # ...existing code for other functionality...

if __name__ == "__main__":
    main()
