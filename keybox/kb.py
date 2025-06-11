#!/usr/bin/env python3

import xml.etree.ElementTree as ET
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key
import base64

input_file = "keybox.xml"
output_file = "keybox_pkcs8_priv.xml"

tree = ET.parse(input_file)
root = tree.getroot()

def convert_to_pkcs8(pem_data: str) -> str:
    """Convert PEM to PKCS#8 PEM format."""
    key = load_pem_private_key(pem_data.encode(), password=None)
    pkcs8_bytes = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    return pkcs8_bytes.decode()

for key in root.findall(".//Key"):
    algo = key.attrib.get("algorithm", "")
    private_key_elem = key.find("PrivateKey")
    if private_key_elem is not None:
        pem_text = private_key_elem.text.strip()
        if "RSA PRIVATE KEY" in pem_text or "EC PRIVATE KEY" in pem_text:
            print(f"Converting {algo} key to PKCS#8 format")
            pkcs8_pem = convert_to_pkcs8(pem_text)
            private_key_elem.set("format", "pem")
            private_key_elem.text = pkcs8_pem

tree.write(output_file, encoding="utf-8", xml_declaration=True)
print(f"Updated keybox saved to {output_file}")
