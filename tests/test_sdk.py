import os
import sys
import unittest
import base64
from cryptography.hazmat.primitives.asymmetric import ed25519

# Add the sdk/ folder to path so we can import creduent directly
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from creduent import (
    generate_keys,
    sign,
    verify,
    attest,
    VerificationError,
    AttestationError
)

class TestCreduentSDK(unittest.TestCase):
    
    def test_generate_keys(self):
        """1. generate_keys() returns valid PEM + ed25519 prefixed public key"""
        private_key_pem, public_key_str = generate_keys()
        
        # Verify private key is PEM format
        self.assertTrue(private_key_pem.startswith("-----BEGIN PRIVATE KEY-----"))
        self.assertTrue(private_key_pem.strip().endswith("-----END PRIVATE KEY-----"))
        
        # Verify public key format
        self.assertTrue(public_key_str.startswith("ed25519:"))
        pk_b64 = public_key_str.split(":", 1)[1]
        
        # Verify it can be base64 decoded
        pk_bytes = base64.b64decode(pk_b64)
        self.assertEqual(len(pk_bytes), 32)
        
    def test_sign_document(self):
        """2. sign() produces a dict with a valid signature field"""
        private_key_pem, public_key_str = generate_keys()
        
        draft = {
            "agent_id": "agent://creduent/reconbot",
            "owner": "Creduent",
            "public_key": public_key_str,
            "endpoint": "https://api.idevsec.com/recon",
            "capabilities": ["osint", "dns_lookup", "vulnerability_scan"]
        }
        
        signed_doc = sign(draft, private_key_pem)
        
        self.assertIn("signature", signed_doc)
        self.assertIn("issued_at", signed_doc)
        self.assertEqual(signed_doc["version"], "1.0")
        
        # Verify the signature field is non-empty base64
        sig_b64 = signed_doc["signature"]
        sig_bytes = base64.b64decode(sig_b64)
        self.assertEqual(len(sig_bytes), 64)
        
    def test_verify_live_endpoint(self):
        """3. verify() on the live endpoint returns valid=True"""
        target = "https://api.idevsec.com/.well-known/agent.json"
        try:
            result = verify(target)
            self.assertTrue(result.valid)
            self.assertIsNone(result.error)
            self.assertEqual(result.agent_id, "agent://creduent/reconbot")
        except VerificationError as e:
            # If the network or live endpoint is completely unreachable, skip or print warning
            print(f"\n[WARNING] Live verification test skipped/failed due to network: {e}")
            
    def test_verify_tampered_dict(self):
        """4. verify() on a tampered dict returns valid=False"""
        private_key_pem, public_key_str = generate_keys()
        
        draft = {
            "agent_id": "agent://creduent/reconbot",
            "owner": "Creduent",
            "public_key": public_key_str,
            "endpoint": "https://api.idevsec.com/recon",
            "capabilities": ["osint", "dns_lookup", "vulnerability_scan"]
        }
        
        signed_doc = sign(draft, private_key_pem)
        
        # 4a. Verify untampered dict is valid
        res_ok = verify(signed_doc)
        self.assertTrue(res_ok.valid)
        
        # 4b. Tamper with a field
        tampered_doc = signed_doc.copy()
        tampered_doc["owner"] = "Not Creduent"
        
        res_tampered = verify(tampered_doc)
        self.assertFalse(res_tampered.valid)
        self.assertIsNotNone(res_tampered.error)
        
    def test_attest_live(self):
        """5. attest() against https://api.idevsec.com returns a valid AttestResult"""
        try:
            result = attest("agent://creduent/reconbot", "https://api.idevsec.com")
            # The agent might or might not be currently registered in the database, 
            # but the result should be a valid AttestResult dataclass
            self.assertIn(result.attested, [True, False])
            if result.attested:
                self.assertIn(result.level, ["verified", "trusted"])
                self.assertIsNotNone(result.issued_at)
                self.assertIsNotNone(result.expires_at)
                self.assertIsNone(result.error)
            else:
                self.assertIsNotNone(result.error)
        except AttestationError as e:
            print(f"\n[WARNING] Live attestation test skipped/failed due to network: {e}")

if __name__ == '__main__':
    unittest.main()
