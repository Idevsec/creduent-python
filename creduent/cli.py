import os
import sys
import argparse
import json
import yaml

from creduent.sign import generate_keys, sign
from creduent.discovery import discover

def cmd_init(args):
    """Scaffolds a new agent.yaml CRD."""
    if os.path.exists("agent.yaml"):
        print("Error: agent.yaml already exists in the current directory.")
        sys.exit(1)
        
    crd = {
        "apiVersion": "creduent.idevsec.com/v1.1",
        "kind": "Agent",
        "metadata": {
            "agent_id": "agent://namespace/my_agent",
            "owner": "My Organization",
            "endpoint": "https://api.namespace.com"
        },
        "spec": {
            "capabilities": [
                "public_capability_1",
                {"name": "private_capability", "schema": "https://api.namespace.com/openapi.json"}
            ]
        }
    }
    
    with open("agent.yaml", "w") as f:
        yaml.dump(crd, f, default_flow_style=False, sort_keys=False)
        
    print("Successfully created agent.yaml")

def cmd_keygen(args):
    """Generates an Ed25519 keypair and saves it to .creduent/keys/."""
    keys_dir = os.path.join(".creduent", "keys")
    os.makedirs(keys_dir, exist_ok=True)
    
    priv_path = os.path.join(keys_dir, "private.pem")
    pub_path = os.path.join(keys_dir, "public.pub")
    
    if os.path.exists(priv_path):
        print(f"Error: Key already exists at {priv_path}")
        sys.exit(1)
        
    priv_pem, pub_str = generate_keys()
    
    with open(priv_path, "w") as f:
        f.write(priv_pem)
        
    with open(pub_path, "w") as f:
        f.write(pub_str)
        
    # Create a .gitignore so keys are not committed
    gitignore_path = os.path.join(".creduent", ".gitignore")
    if not os.path.exists(gitignore_path):
        with open(gitignore_path, "w") as f:
            f.write("keys/\n")
            
    print(f"Successfully generated keys in {keys_dir}")
    print(f"Public Key: {pub_str}")

def cmd_build(args):
    """Compiles agent.yaml and the local private key into a signed agent.json."""
    if not os.path.exists("agent.yaml"):
        print("Error: agent.yaml not found. Run 'creduent init' first.")
        sys.exit(1)
        
    with open("agent.yaml", "r") as f:
        crd = yaml.safe_load(f)
        
    if crd.get("kind") != "Agent":
        print("Error: agent.yaml is not of kind: Agent")
        sys.exit(1)
        
    # Construct the base draft
    metadata = crd.get("metadata", {})
    spec = crd.get("spec", {})
    
    draft = {
        "version": crd.get("apiVersion", "1.1").split("/")[-1].replace("v", ""),
        "agent_id": metadata.get("agent_id", ""),
        "owner": metadata.get("owner", ""),
        "endpoint": metadata.get("endpoint", ""),
        "capabilities": spec.get("capabilities", [])
    }
    
    # Get the private key (from env var or local file)
    priv_pem = None
    pub_str = None
    
    env_key = os.environ.get("CREDUENT_PRIVATE_KEY")
    if env_key:
        priv_pem = env_key
        # We also need the public key. If using env_key, we might need to derive it.
        # For simplicity in this build command, we'll try to load public.pub if it exists,
        # otherwise we'll regenerate the public key from the private key if needed.
        # But for the SDK sign(), we actually don't pass public_key, sign() doesn't derive it?
        # Oh, sign() needs the document to already have public_key or keys set!
        # So we MUST derive or read the public key.
        from cryptography.hazmat.primitives.serialization import load_pem_private_key
        import base64
        from cryptography.hazmat.primitives.asymmetric import ed25519
        from cryptography.hazmat.primitives import serialization
        
        try:
            sk = load_pem_private_key(priv_pem.encode('utf-8'), password=None)
            pk = sk.public_key()
            pk_bytes = pk.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
            pub_str = "ed25519:" + base64.b64encode(pk_bytes).decode('utf-8')
        except Exception as e:
            print(f"Error parsing CREDUENT_PRIVATE_KEY: {e}")
            sys.exit(1)
    else:
        # Load from file
        priv_path = os.path.join(".creduent", "keys", "private.pem")
        pub_path = os.path.join(".creduent", "keys", "public.pub")
        if not os.path.exists(priv_path):
            print("Error: No private key found. Run 'creduent keygen' or set CREDUENT_PRIVATE_KEY.")
            sys.exit(1)
            
        with open(priv_path, "r") as f:
            priv_pem = f.read()
            
        if os.path.exists(pub_path):
            with open(pub_path, "r") as f:
                pub_str = f.read().strip()
        else:
            # Derive
            from cryptography.hazmat.primitives.serialization import load_pem_private_key
            import base64
            from cryptography.hazmat.primitives.asymmetric import ed25519
            from cryptography.hazmat.primitives import serialization
            sk = load_pem_private_key(priv_pem.encode('utf-8'), password=None)
            pk = sk.public_key()
            pk_bytes = pk.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
            pub_str = "ed25519:" + base64.b64encode(pk_bytes).decode('utf-8')
            
    # Add keys to draft
    draft["keys"] = [
        {
            "id": "key1",
            "type": "ed25519",
            "public_key": pub_str,
            "status": "active"
        }
    ]
    
    # Sign
    try:
        signed_doc = sign(draft, priv_pem)
    except Exception as e:
        print(f"Error signing document: {e}")
        sys.exit(1)
        
    with open("agent.json", "w") as f:
        json.dump(signed_doc, f, indent=2)
        
    print("Successfully built and signed agent.json")

def cmd_discover(args):
    """Discovers capabilities of a target agent."""
    target = args.target
    my_agent_id = args.as_agent
    
    priv_pem = None
    if my_agent_id:
        env_key = os.environ.get("CREDUENT_PRIVATE_KEY")
        if env_key:
            priv_pem = env_key
        else:
            priv_path = os.path.join(".creduent", "keys", "private.pem")
            if os.path.exists(priv_path):
                with open(priv_path, "r") as f:
                    priv_pem = f.read()
            else:
                print("Error: --as requires a private key in .creduent/keys/ or CREDUENT_PRIVATE_KEY env var.")
                sys.exit(1)
                
    result = discover(target, my_agent_id, priv_pem)
    
    print(f"Target Agent: {result.target_agent_id}")
    print(f"Endpoint: {result.endpoint}")
    print(f"Authenticated: {result.authenticated}")
    if result.error:
        print(f"Error: {result.error}")
    print("Capabilities:")
    for cap in result.capabilities:
        if isinstance(cap, dict):
            print(f"  - {cap.get('name')}: {cap.get('schema')}")
        else:
            print(f"  - {cap}")

def main():
    parser = argparse.ArgumentParser(description="Creduent CLI v2 - Agent identity and capability management.")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # Init
    subparsers.add_parser("init", help="Scaffold a new agent.yaml")
    
    # Keygen
    subparsers.add_parser("keygen", help="Generate Ed25519 keys locally")
    
    # Build
    subparsers.add_parser("build", help="Compile agent.yaml to a signed agent.json")
    
    # Discover
    parser_discover = subparsers.add_parser("discover", help="Discover an agent's capabilities")
    parser_discover.add_argument("target", help="The target agent URI (e.g., agent://stripe/payments)")
    parser_discover.add_argument("--as", dest="as_agent", help="Perform authenticated discovery as this agent_id")
    
    args = parser.parse_args()
    
    if args.command == "init":
        cmd_init(args)
    elif args.command == "keygen":
        cmd_keygen(args)
    elif args.command == "build":
        cmd_build(args)
    elif args.command == "discover":
        cmd_discover(args)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
