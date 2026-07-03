import os
import sys
import json
import base64
import argparse
from datetime import datetime, timezone
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from creduent.crypto import canonicalize
from creduent.exceptions import CreduentError


def generate_keys() -> tuple[str, str]:
    """Generate a new Ed25519 keypair.

    Args:
        None

    Returns:
        tuple[str, str]: A tuple containing the private key in PEM format
            and the public key prefixed with "ed25519:".

    Raises:
        CreduentError: If key generation or formatting fails.
    """
    try:
        private_key = ed25519.Ed25519PrivateKey.generate()

        # Format Private Key as PEM string
        private_pem_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        private_key_pem = private_pem_bytes.decode("utf-8")

        # Extract and format Public Key
        public_key = private_key.public_key()
        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )
        public_b64 = base64.b64encode(public_bytes).decode("utf-8")
        public_key_str = f"ed25519:{public_b64}"

        return private_key_pem, public_key_str
    except Exception as e:
        raise CreduentError(f"Failed to generate keys: {e}")


def sign(draft: dict, private_key_pem: str) -> dict:
    """Sign a draft agent.json dict and return the signed document.

    Adds JCS canonicalization (RFC 8785) + Ed25519 signature field.

    Args:
        draft (dict): The unsigned agent.json dictionary.
        private_key_pem (str): The Ed25519 private key in PEM format.

    Returns:
        dict: The signed agent.json dictionary with the signature included.

    Raises:
        CreduentError: If input validation fails or if there is an error
            during key parsing, JCS canonicalization, or signing.
    """
    if not isinstance(draft, dict):
        raise CreduentError("Draft must be a dictionary")

    doc = draft.copy()

    # Normalize fields
    doc["version"] = "1.0"
    if "issued_at" not in doc:
        doc["issued_at"] = (
            datetime.now(timezone.utc)
            .isoformat(timespec="seconds")
            .replace("+00:00", "Z")
        )

    # Remove signature before signing
    doc.pop("signature", None)

    try:
        # Load the Ed25519 private key
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode("utf-8"), password=None
        )
        if not isinstance(private_key, ed25519.Ed25519PrivateKey):
            raise ValueError("Key is not an Ed25519 private key")
    except Exception as e:
        raise CreduentError(f"Failed parsing private key PEM: {e}")

    try:
        # JCS canonicalization
        canonical_str = canonicalize(doc)
        canonical_bytes = canonical_str.encode("utf-8")

        # Sign payload
        signature_bytes = private_key.sign(canonical_bytes)
        signature_b64 = base64.b64encode(signature_bytes).decode("utf-8")

        # Append signature
        doc["signature"] = signature_b64
        return doc
    except Exception as e:
        raise CreduentError(f"Failed during JCS canonicalization or signing: {e}")


def print_help() -> None:
    """Print a styled help message for the signing CLI."""
    print("""
\033[1m\033[36m* CREDUENT SIGN CLI\033[0m \033[90m-\033[0m \033[1m\033[37mAI Agent Identity Signing Utility\033[0m
\033[90mVersion 0.4.0 | Developed by IDevSec

PyPI  : https://pypi.org/project/creduent/
GitHub: https://github.com/idevsec/creduent\033[0m

\033[1m\033[32mUSAGE:\033[0m
  $ \033[1mcreduent-sign\033[0m <command> [options]

\033[1m\033[36mCOMMANDS:\033[0m
  \033[1mgenerate-keys\033[0m       \033[90mGenerate Ed25519 private key and public key string\033[0m
  \033[1msign\033[0m \033[35m[options]\033[0m          \033[90mSign a draft agent.json payload\033[0m

\033[1m\033[35mSIGN OPTIONS:\033[0m
  \033[1m--key\033[0m \033[33m<path>\033[0m          \033[90mPath to Ed25519 private_key.pem\033[0m
  \033[1m--input\033[0m \033[33m<path>\033[0m        \033[90mPath to unsigned draft JSON file\033[0m
  \033[1m--output\033[0m \033[33m<path>\033[0m       \033[90mPath to write the signed JSON output file\033[0m

\033[1m\033[33mEXAMPLES:\033[0m
  \033[90m# Generate private_key.pem and public key\033[0m
  $ \033[1mcreduent-sign generate-keys\033[0m

  \033[90m# Sign a draft agent.json metadata\033[0m
  $ \033[1mcreduent-sign sign\033[0m --key private_key.pem --input draft.json --output agent.json
  """)


def main() -> None:
    """CLI entry point for generating keys and signing documents."""
    if len(sys.argv) < 2 or "-h" in sys.argv or "--help" in sys.argv:
        print_help()
        sys.exit(0)

    parser = argparse.ArgumentParser(add_help=False)
    subparsers = parser.add_subparsers(dest="command")

    # generate-keys parser
    subparsers.add_parser("generate-keys", add_help=False)

    # sign parser
    sign_parser = subparsers.add_parser("sign", add_help=False)
    sign_parser.add_argument("--key", required=True)
    sign_parser.add_argument("--input", required=True)
    sign_parser.add_argument("--output", required=True)

    try:
        args = parser.parse_args()
    except SystemExit:
        print_help()
        sys.exit(1)

    if args.command == "generate-keys":
        try:
            private_pem, public_key_str = generate_keys()

            # Save private key PEM locally
            with open("private_key.pem", "w", encoding="utf-8") as f:
                f.write(private_pem)
            try:
                os.chmod("private_key.pem", 0o600)
            except Exception:
                pass
            print("[SUCCESS] Private key saved to private_key.pem (KEEP THIS SECRET!)")

            print("\n" + "=" * 50)
            print("YOUR PUBLIC KEY (Add this to your agent.json):")
            print(public_key_str)
            print("=" * 50)
        except Exception as e:
            print(f"[-] Error: {e}", file=sys.stderr)
            sys.exit(1)

    elif args.command == "sign":
        if not os.path.exists(args.key):
            print(f"[-] Error: Key file not found at {args.key}", file=sys.stderr)
            sys.exit(1)

        if not os.path.exists(args.input):
            print(
                f"[-] Error: Input document not found at {args.input}", file=sys.stderr
            )
            sys.exit(1)

        try:
            with open(args.key, "r", encoding="utf-8") as f:
                private_pem = f.read()

            with open(args.input, "r", encoding="utf-8") as f:
                draft = json.load(f)

            signed_doc = sign(draft, private_pem)

            with open(args.output, "w", encoding="utf-8") as f:
                json.dump(signed_doc, f, indent=2, ensure_ascii=False)

            print(f"[SUCCESS] Successfully signed and generated {args.output}!")
        except Exception as e:
            print(f"[-] Error: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        print_help()


if __name__ == "__main__":
    main()
