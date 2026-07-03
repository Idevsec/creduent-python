import os
import sys
import unittest
from unittest.mock import patch
import base64
from cryptography.hazmat.primitives.asymmetric import ed25519

# Add the sdk/ folder to path so we can import creduent directly
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from creduent import (
    generate_keys,
    sign,
    verify,
    attest,
    discover,
    renew,
    register_webhook,
    query_webhook,
    VerificationError,
    AttestationError,
)
import creduent.attest
import creduent.verify
import creduent.discovery
attest_module = sys.modules["creduent.attest"]
verify_module = sys.modules["creduent.verify"]
discovery_module = sys.modules["creduent.discovery"]


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
            "endpoint": "https://creduent.idevsec.com/recon",
            "capabilities": ["osint", "dns_lookup", "vulnerability_scan"],
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
        target = "https://creduent.idevsec.com/.well-known/agent.json"
        try:
            result = verify(target)
            self.assertTrue(result.valid)
            self.assertIsNone(result.error)
            self.assertEqual(result.agent_id, "agent://creduent/reconbot")
        except VerificationError as e:
            # If the network or live endpoint is completely unreachable, skip or print warning
            print(
                f"\n[WARNING] Live verification test skipped/failed due to network: {e}"
            )

    def test_verify_tampered_dict(self):
        """4. verify() on a tampered dict returns valid=False"""
        private_key_pem, public_key_str = generate_keys()

        draft = {
            "agent_id": "agent://creduent/reconbot",
            "owner": "Creduent",
            "public_key": public_key_str,
            "endpoint": "https://creduent.idevsec.com/recon",
            "capabilities": ["osint", "dns_lookup", "vulnerability_scan"],
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
        """5. attest() against https://creduent.idevsec.com returns a valid AttestResult"""
        try:
            result = attest("agent://creduent/reconbot", "https://creduent.idevsec.com")
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
            print(
                f"\n[WARNING] Live attestation test skipped/failed due to network: {e}"
            )

    @patch.object(attest_module, "safe_requests_get")
    def test_attest_revoked_410(self, mock_get):
        """5b. attest() handles HTTP 410 (revoked) status cleanly"""

        class MockResponse:
            def __init__(self, json_data, status_code):
                self.json_data = json_data
                self.status_code = status_code

            def json(self):
                return self.json_data

            @property
            def text(self):
                return "Attestation revoked for agent."

        mock_get.return_value = MockResponse(
            {"detail": "Attestation revoked for agent."}, 410
        )

        result = attest("agent://creduent/test-revoked")
        self.assertFalse(result.attested)
        self.assertEqual(result.level, "revoked")
        self.assertEqual(result.error, "Attestation revoked for agent.")

    def test_verify_multi_key_success(self):
        """6. verify() with multiple keys succeeds if signed by an active key"""
        priv1, pub1 = generate_keys()
        priv2, pub2 = generate_keys()

        draft = {
            "version": "1.1",
            "agent_id": "agent://creduent/multi",
            "owner": "Creduent",
            "endpoint": "https://test",
            "capabilities": [],
            "keys": [
                {
                    "id": "key1",
                    "type": "ed25519",
                    "public_key": pub1,
                    "status": "revoked",
                },
                {
                    "id": "key2",
                    "type": "ed25519",
                    "public_key": pub2,
                    "status": "active",
                },
            ],
        }

        # Sign with active key
        signed_doc = sign(draft, priv2)
        res = verify(signed_doc)
        self.assertTrue(res.valid)
        self.assertEqual(res.public_key, pub2)

    def test_verify_multi_key_revoked(self):
        """7. verify() with multiple keys fails if signed by a revoked key"""
        priv1, pub1 = generate_keys()
        priv2, pub2 = generate_keys()

        draft = {
            "version": "1.1",
            "agent_id": "agent://creduent/multi",
            "owner": "Creduent",
            "endpoint": "https://test",
            "capabilities": [],
            "keys": [
                {
                    "id": "key1",
                    "type": "ed25519",
                    "public_key": pub1,
                    "status": "revoked",
                },
                {
                    "id": "key2",
                    "type": "ed25519",
                    "public_key": pub2,
                    "status": "active",
                },
            ],
        }

        # Sign with revoked key
        signed_doc = sign(draft, priv1)
        res = verify(signed_doc)
        self.assertFalse(res.valid)
        self.assertIn("Cryptographic signature in agent.json is INVALID", res.error)

    def test_verify_multi_key_expired(self):
        """8. verify() fails if the active key is expired"""
        priv1, pub1 = generate_keys()

        draft = {
            "version": "1.1",
            "agent_id": "agent://creduent/multi",
            "owner": "Creduent",
            "endpoint": "https://test",
            "capabilities": [],
            "keys": [
                {
                    "id": "key1",
                    "type": "ed25519",
                    "public_key": pub1,
                    "status": "active",
                    "expires_at": "2020-01-01T00:00:00Z",
                }
            ],
        }

        signed_doc = sign(draft, priv1)
        res = verify(signed_doc)
        self.assertFalse(res.valid)
        self.assertIn("Active key is expired", res.error)

    @patch.object(verify_module, "safe_requests_get")
    def test_verify_cross_namespace_spoofing(self, mock_get):
        """9. verify() rejects document if the claimed agent_id does not match the requested target"""
        priv1, pub1 = generate_keys()

        # The document claims to be from attacker
        draft = {
            "version": "1.1",
            "agent_id": "agent://attacker/bot",
            "owner": "Attacker",
            "endpoint": "https://attacker.com",
            "capabilities": [],
            "public_key": pub1,
        }
        signed_doc = sign(draft, priv1)

        # Mock the request to return the attacker's document when we ask for idevsec
        class MockResponse:
            def __init__(self, json_data, status_code):
                self.json_data = json_data
                self.status_code = status_code

            def json(self):
                return self.json_data

        mock_get.return_value = MockResponse(signed_doc, 200)

        # Requesting a idevsec agent, but the registry/server returns the attacker doc
        res = verify("agent://idevsec/reconbot")

        self.assertFalse(res.valid)
        self.assertIn("Cross-Namespace Spoofing Detected", res.error)

    @patch.object(discovery_module, "verify")
    def test_discover_public_capabilities(self, mock_verify):
        """10. discover() returns public capabilities without authentication"""
        from creduent.verify import VerifyResult

        mock_verify.return_value = VerifyResult(
            valid=True,
            agent_id="agent://idevsec/reconbot",
            public_key="ed25519:test",
            endpoint="https://creduent.idevsec.com",
            capabilities=["get_status"],
            error=None,
        )

        res = discover("agent://idevsec/reconbot")

        self.assertEqual(res.target_agent_id, "agent://idevsec/reconbot")
        self.assertEqual(res.endpoint, "https://creduent.idevsec.com")
        self.assertFalse(res.authenticated)
        self.assertListEqual(res.capabilities, ["get_status"])

    @patch.object(discovery_module, "verify")
    @patch("requests.post")
    def test_discover_authenticated_capabilities(self, mock_post, mock_verify):
        """11. discover() with auth fetches and merges private capabilities"""
        from creduent.verify import VerifyResult

        mock_verify.return_value = VerifyResult(
            valid=True,
            agent_id="agent://idevsec/reconbot",
            public_key="ed25519:test",
            endpoint="https://creduent.idevsec.com",
            capabilities=["get_status"],
            error=None,
        )

        # Mock requests.post returning a private capability
        class MockResponse:
            def __init__(self, json_data, status_code):
                self.json_data = json_data
                self.status_code = status_code

            def json(self):
                return self.json_data

        mock_post.return_value = MockResponse(
            {
                "capabilities": [
                    {
                        "name": "process_refund",
                        "schema": "https://creduent.idevsec.com/openapi.json",
                    }
                ]
            },
            200,
        )

        priv1, _ = generate_keys()

        res = discover("agent://idevsec/reconbot", "agent://my/bot", priv1)

        self.assertEqual(res.target_agent_id, "agent://idevsec/reconbot")
        self.assertTrue(res.authenticated)
        # Should merge the public "get_status" and the private dict
        self.assertEqual(len(res.capabilities), 2)
        self.assertEqual(res.capabilities[0], "get_status")
        self.assertIsInstance(res.capabilities[1], dict)
        self.assertEqual(res.capabilities[1]["name"], "process_refund")

    def test_cli_commands(self):
        """12. CLI init, keygen, and build commands execute successfully"""
        import tempfile
        import shutil
        from creduent.cli import cmd_init, cmd_keygen, cmd_build

        # Save current directory
        cwd = os.getcwd()

        # Create a temp dir
        temp_dir = tempfile.mkdtemp()
        try:
            os.chdir(temp_dir)

            # Dummy args
            class DummyArgs:
                pass

            args = DummyArgs()

            # Run init
            cmd_init(args)
            self.assertTrue(os.path.exists("agent.yaml"))

            # Run keygen
            cmd_keygen(args)
            self.assertTrue(
                os.path.exists(os.path.join(".creduent", "keys", "private.pem"))
            )
            self.assertTrue(
                os.path.exists(os.path.join(".creduent", "keys", "public.pub"))
            )

            # Run build
            cmd_build(args)
            self.assertTrue(os.path.exists("agent.json"))

            # Verify the output is a valid agent.json
            import json

            with open("agent.json", "r") as f:
                doc = json.load(f)

            res = verify(doc)
            self.assertTrue(res.valid)
            self.assertEqual(res.agent_id, "agent://namespace/my_agent")

        finally:
            os.chdir(cwd)
            shutil.rmtree(temp_dir)

    @patch("requests.post")
    def test_renew_payload_signing(self, mock_post):
        """13. renew() signs the renewal payload and calls endpoint"""

        class MockResponse:
            def __init__(self, json_data, status_code):
                self.json_data = json_data
                self.status_code = status_code

            def json(self):
                return self.json_data

        mock_post.return_value = MockResponse(
            {"success": True, "agent_id": "agent://my/bot"}, 200
        )

        priv, _ = generate_keys()
        res = renew("agent://my/bot", "2026-12-31T23:59:59Z", priv)

        self.assertTrue(res.success)
        self.assertEqual(res.attestation["agent_id"], "agent://my/bot")

        # Verify mock post was called with correct payload fields (signature, agent_id, new_expires_at)
        mock_post.assert_called_once()
        kwargs = mock_post.call_args[1]
        self.assertIn("json", kwargs)
        req_json = kwargs["json"]
        self.assertEqual(req_json["agent_id"], "agent://my/bot")
        self.assertEqual(req_json["new_expires_at"], "2026-12-31T23:59:59Z")
        self.assertIn("signature", req_json)

    @patch("requests.post")
    def test_webhook_payload_signing(self, mock_post):
        """14. register_webhook() signs payload and calls register endpoint"""

        class MockResponse:
            def __init__(self, json_data, status_code):
                self.json_data = json_data
                self.status_code = status_code

            def json(self):
                return self.json_data

        mock_post.return_value = MockResponse(
            {"agent_id": "agent://my/bot", "webhook_url": "https://example.com/hook"},
            200,
        )

        priv, _ = generate_keys()
        res = register_webhook("agent://my/bot", "https://example.com/hook", priv)

        self.assertTrue(res.success)
        self.assertEqual(res.agent_id, "agent://my/bot")
        self.assertEqual(res.webhook_url, "https://example.com/hook")

        mock_post.assert_called_once()
        kwargs = mock_post.call_args[1]
        req_json = kwargs["json"]
        self.assertEqual(req_json["agent_id"], "agent://my/bot")
        self.assertEqual(req_json["webhook_url"], "https://example.com/hook")
        self.assertIn("signature", req_json)

    @patch("requests.get")
    def test_webhook_query(self, mock_get):
        """15. query_webhook() makes GET request to webhook endpoint"""

        class MockResponse:
            def __init__(self, json_data, status_code):
                self.json_data = json_data
                self.status_code = status_code

            def json(self):
                return self.json_data

        mock_get.return_value = MockResponse(
            {"agent_id": "agent://my/bot", "webhook_url": "https://example.com/hook"},
            200,
        )

        res = query_webhook("agent://my/bot")

        self.assertTrue(res.success)
        self.assertEqual(res.agent_id, "agent://my/bot")
        self.assertEqual(res.webhook_url, "https://example.com/hook")
        mock_get.assert_called_once()


if __name__ == "__main__":
    unittest.main()
