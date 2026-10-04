"""Command-line interface for the offline Keeta a9 codec."""
import argparse
import json
import sys
from pathlib import Path

from . import a9_codec


def _read(path):
    return sys.stdin.buffer.read() if path == "-" else Path(path).read_bytes()


def _write(path, data):
    if path == "-":
        sys.stdout.buffer.write(data)
        sys.stdout.buffer.flush()
    else:
        Path(path).write_bytes(data)


def _profile(path):
    if path is None:
        return {}
    profile = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(profile, dict):
        raise ValueError("profile must be a JSON object")
    if set(profile) - {"a1", "salt_hex", "k3_hex", "a1_shift"}:
        raise ValueError("profile supports only a1, salt_hex, k3_hex and a1_shift")
    result = {}
    if "a1" in profile:
        if not isinstance(profile["a1"], str):
            raise ValueError("profile a1 must be a UUID string")
        result["a1"] = profile["a1"]
    if "a1_shift" in profile:
        shift = profile["a1_shift"]
        if isinstance(shift, bool) or not isinstance(shift, int) or not 0 <= shift < 36:
            raise ValueError("profile a1_shift must be an integer from 0 to 35")
        result["a1_shift"] = shift
    for field, dest in (("salt_hex", "salt"), ("k3_hex", "k3")):
        if field not in profile:
            continue
        if not isinstance(profile[field], str):
            raise ValueError(f"profile {field} must contain hexadecimal text")
        try:
            result[dest] = bytes.fromhex(profile[field])
        except ValueError as exc:
            raise ValueError(f"profile {field} must contain hexadecimal text") from exc
    return result


def _a9_input(data):
    text = data.decode("utf-8").strip()
    if not text:
        raise ValueError("input is empty")
    if text[0] not in '{["':
        return text, None
    value = json.loads(text)
    if isinstance(value, str):
        return value, None
    if isinstance(value, dict) and "mtgsig" in value:
        value = value["mtgsig"]
        if isinstance(value, str):
            value = json.loads(value)
    if not isinstance(value, dict) or not isinstance(value.get("a9"), str):
        raise ValueError("JSON input must contain a9 or an mtgsig object containing a9")
    if "a1" in value and not isinstance(value["a1"], str):
        raise ValueError("mtgsig a1 must be a UUID string")
    return value["a9"], value.get("a1")


def _a1(explicit, profile, embedded=None):
    values = [v for v in (explicit, profile, embedded) if v is not None]
    if not values:
        raise ValueError("original a1 is required: use mtgsig JSON, --a1 or --profile")
    if any(v != values[0] for v in values[1:]):
        raise ValueError("a1 differs between arguments, profile and mtgsig input")
    return values[0]


def _nonnegative(text):
    value = int(text)
    if value < 0:
        raise argparse.ArgumentTypeError("must be zero or a positive integer")
    return value


def _parser():
    parser = argparse.ArgumentParser(
        description="Offline a9 encryption/decryption for the analysed Keeta SDK."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command in ("encode", "decode"):
        sub = subparsers.add_parser(command)
        sub.add_argument("-i", "--input", default="-", help="input file; - reads stdin")
        sub.add_argument("-o", "--output", default="-", help="output file; - writes stdout")
        sub.add_argument("--a1", help="original 36-character UUID; a profile keeps it off the command line")
        sub.add_argument("--profile", help="JSON file with optional a1, salt_hex, k3_hex and a1_shift")
        if command == "encode":
            sub.add_argument("--mode", choices=a9_codec.MODES, default="aes")
            sub.add_argument("--level", choices=range(-1, 10), type=int, default=6,
                             help="zlib level, used unless --compressed is supplied")
            sub.add_argument("--compressed", action="store_true",
                             help="input already contains the exact zlib stream to encrypt")
        else:
            sub.add_argument("--mode", choices=("auto",) + a9_codec.MODES, default="auto")
            sub.add_argument("--max-plaintext", type=_nonnegative, default=4 << 20,
                             help="maximum decompressed bytes (default: 4194304)")
            sub.add_argument("--compressed-output", action="store_true",
                             help="write the verified compressed stream instead of plaintext")
    return parser


def main(argv=None):
    args = _parser().parse_args(argv)
    try:
        profile = _profile(args.profile)
        profile_a1 = profile.pop("a1", None)
        data = _read(args.input)
        if args.command == "decode":
            a9, embedded_a1 = _a9_input(data)
            a1 = _a1(args.a1, profile_a1, embedded_a1)
            result = a9_codec.decode(a9, a1, mode=args.mode,
                                     max_plaintext=args.max_plaintext, **profile)
            output = result.compressed if args.compressed_output else result.plaintext
            status = (f"mode={result.mode} compressed_bytes={len(result.compressed)} "
                      f"plaintext_bytes={len(result.plaintext)}")
        else:
            a1 = _a1(args.a1, profile_a1)
            if args.compressed:
                a9 = a9_codec.encode_compressed(data, a1, mode=args.mode, **profile)
            else:
                a9 = a9_codec.encode(data, a1, mode=args.mode, level=args.level, **profile)
            output = (a9 + "\n").encode("ascii")
            status = f"mode={args.mode} input_bytes={len(data)} a9_chars={len(a9)}"
        _write(args.output, output)
        print(status, file=sys.stderr)
        return 0
    except (OSError, ValueError, TypeError, a9_codec.zlib.error) as exc:
        # Neither successful status nor normal validation errors expose a1/key data.
        print(f"a9: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
