import os
import sys
import unittest
from unittest.mock import patch
from fastapi.testclient import TestClient

# Add workspace paths to import SDK and Registry
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../creduent-vercel')))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from creduent import generate_keys, sign, challenge
from registry.main import app  # type: ignore
from registry.store import save_attestation, save_challenge  # type: ignore

class TestChallengeResponse(unittest.TestCase):
    
    def setUp(self):
        # Generate dynamic registry key for test environment
        from cryptography.hazmat.primitives.asymmetric import ed25519
        from cryptography.hazmat.primitives import serialization
        
        reg_private_key = ed25519.Ed25519PrivateKey.generate()
        reg_private_pem = reg_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')
        
        os.environ["CREDUENT_REGISTRY_KEY"] = reg_private_pem
        
        self.client = TestClient(app)
        self.agent_id = "agent://idevsec/reconbot"
        self.private_pem, self.public_key_str = generate_keys()
        
        # Mock register the agent in registry db (save attestation)
        save_attestation(self.agent_id, {
            "agent_id": self.agent_id,
            "public_key": self.public_key_str,
            "domain": "idevsec.com",
            "level": "trusted",
            "issued_at": "2026-05-31T00:00:00Z",
            "expires_at": "2027-05-31T00:00:00Z",
            "signature": "mock_sig"
        })

    def mock_get(self, url, *args, **kwargs):
        # Route to TestClient
        from urllib.parse import urlparse
        parsed = urlparse(url)
        path = parsed.path
        response = self.client.get(path, *args, **kwargs)
        return response

    def mock_post(self, url, *args, **kwargs):
        from urllib.parse import urlparse
        parsed = urlparse(url)
        path = parsed.path
        response = self.client.post(path, *args, **kwargs)
        return response

    @patch("creduent.challenge.safe_requests_get")
    @patch("creduent.challenge.safe_requests_post")
    def test_end_to_end_proof(self, mock_post_fn, mock_get_fn):
        mock_get_fn.side_effect = self.mock_get
        mock_post_fn.side_effect = self.mock_post
        
        # Test 1: create_proof
        proof = challenge.create_proof(
            agent_id=self.agent_id,
            private_key_pem=self.private_pem,
            registry_url="https://registry.idevsec.com"
        )
        
        self.assertTrue(proof["verified"])
        self.assertEqual(proof["level"], "trusted")
        self.assertIn("proof_token", proof)
        
        # Test 2: verify_proof
        with patch("creduent.challenge.attest") as mock_attest:
            from creduent.attest import AttestResult
            mock_attest.return_value = AttestResult(
                attested=True,
                level="trusted",
                issued_at="2026-05-31T00:00:00Z",
                expires_at="2027-05-31T00:00:00Z"
            )
            
            is_valid = challenge.verify_proof(
                proof_token=proof["proof_token"],
                agent_id=self.agent_id,
                registry_url="https://registry.idevsec.com"
            )
            self.assertTrue(is_valid)

    @patch("creduent.challenge.safe_requests_get")
    @patch("creduent.challenge.safe_requests_post")
    def test_invalid_proof_tampered(self, mock_post_fn, mock_get_fn):
        mock_get_fn.side_effect = self.mock_get
        mock_post_fn.side_effect = self.mock_post
        
        proof = challenge.create_proof(
            agent_id=self.agent_id,
            private_key_pem=self.private_pem,
            registry_url="https://registry.idevsec.com"
        )
        
        # Tamper with the proof token (decode, alter, encode)
        import base64
        import json
        decoded = base64.b64decode(proof["proof_token"]).decode('utf-8')
        proof_obj = json.loads(decoded)
        
        proof_obj["level"] = "unverified" # Tampered!
        
        tampered_token = base64.b64encode(json.dumps(proof_obj).encode('utf-8')).decode('utf-8')
        
        with patch("creduent.challenge.attest") as mock_attest:
            from creduent.attest import AttestResult
            mock_attest.return_value = AttestResult(
                attested=True,
                level="trusted",
                issued_at="2026-05-31T00:00:00Z",
                expires_at="2027-05-31T00:00:00Z"
            )
            
            is_valid = challenge.verify_proof(
                proof_token=tampered_token,
                agent_id=self.agent_id,
                registry_url="https://registry.idevsec.com"
            )
            self.assertFalse(is_valid)

    @patch("creduent.challenge.safe_requests_get")
    @patch("creduent.challenge.safe_requests_post")
    def test_verify_proof_with_pinned_key(self, mock_post_fn, mock_get_fn):
        mock_get_fn.side_effect = self.mock_get
        mock_post_fn.side_effect = self.mock_post
        
        proof = challenge.create_proof(
            agent_id=self.agent_id,
            private_key_pem=self.private_pem,
            registry_url="https://registry.idevsec.com"
        )
        
        # Get registry public key to verify
        pub_response = self.client.get("/registry/public-key")
        self.assertEqual(pub_response.status_code, 200)
        registry_pubkey = pub_response.json()["public_key"]
        
        with patch("creduent.challenge.attest") as mock_attest:
            from creduent.attest import AttestResult
            mock_attest.return_value = AttestResult(
                attested=True,
                level="trusted",
                issued_at="2026-05-31T00:00:00Z",
                expires_at="2027-05-31T00:00:00Z"
            )
            
            # 1. Test verification using argument pinning (avoids dynamic get)
            with patch("creduent.challenge.safe_requests_get", side_effect=Exception("Should not fetch")):
                is_valid = challenge.verify_proof(
                    proof_token=proof["proof_token"],
                    agent_id=self.agent_id,
                    registry_url="https://registry.idevsec.com",
                    registry_pubkey=registry_pubkey
                )
                self.assertTrue(is_valid)

            # 2. Test verification using env variable pinning (avoids dynamic get)
            os.environ["CREDUENT_REGISTRY_PUBKEY"] = registry_pubkey
            try:
                with patch("creduent.challenge.safe_requests_get", side_effect=Exception("Should not fetch")):
                    is_valid = challenge.verify_proof(
                        proof_token=proof["proof_token"],
                        agent_id=self.agent_id,
                        registry_url="https://registry.idevsec.com"
                    )
                    self.assertTrue(is_valid)
            finally:
                del os.environ["CREDUENT_REGISTRY_PUBKEY"]

if __name__ == '__main__':
    unittest.main()
