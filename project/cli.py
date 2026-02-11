from encryption_system import (
    generate_ecc_keys,
    verify_signature,
    decapsulate_aes_key,
    decrypt_aes,
    encrypt_aes,
    encapsulate_aes_key,
    sign_data,
    load_input_data
)
from secure_package import create_secure_package
import binascii
import sys

def to_hex(data):
    """Helper to display bytes as hex (truncated if too long)"""
    if isinstance(data, bytes):
        hex_str = binascii.hexlify(data).decode()
        return hex_str if len(hex_str) <= 64 else hex_str[:60] + "..."
    return str(data)

def test_create_secure_package(input_data):
    print("=" * 70)
    print("🔐 STARTING SECURE PACKAGE TEST (VERBOSE MODE)")
    print("=" * 70)

    # === STEP 1: Input Preview ===
    print(f"\n🔹 STEP 1: Input plaintext:")
    try:
        text_preview = input_data.decode('utf-8')
        print(f"   Text: {text_preview}")
    except UnicodeDecodeError:
        print("   Text: <Binary data – not printable>")
    print(f"   Bytes: {to_hex(input_data)}")

    # === STEP 0: Generate Keys ===
    print("\n🔹 STEP 0: Generating ECC key pairs...")
    sender_private_key, sender_public_key = generate_ecc_keys()
    recipient_private_key, recipient_public_key = generate_ecc_keys()
    print("✅ Sender and recipient ECC keys generated.")

    # === STEP 2: AES Encryption ===
    print(f"\n🔹 STEP 2: Encrypting data with AES-256-CBC...")
    aes_result = encrypt_aes(input_data)
    print(f"   AES Key (32B): {to_hex(aes_result['key'])}")
    print(f"   IV (16B)     : {to_hex(aes_result['iv'])}")
    print(f"   Ciphertext   : {to_hex(aes_result['ciphertext'])}")

    # === STEP 3: Encapsulate AES Key ===
    print(f"\n🔹 STEP 3: Encapsulating AES key for recipient using ECDH + AES-GCM...")
    encap = encapsulate_aes_key(aes_result['key'], recipient_public_key)
    print(f"   Ephemeral Public Key (compressed): {to_hex(encap['ephemeral_public_key'].to_string())}")
    print(f"   Encrypted AES Key (GCM)         : {to_hex(encap['encrypted_aes_key'])}")
    print(f"   GCM Nonce (12B)                 : {to_hex(encap['nonce'])}")
    print(f"   GCM Tag (16B)                   : {to_hex(encap['tag'])}")

    # === STEP 4: Sign Ciphertext ===
    print(f"\n🔹 STEP 4: Signing ciphertext with sender's private key (ECDSA-SHA1)...")
    signature = sign_data(aes_result['ciphertext'], sender_private_key)
    print(f"   Signature (64B raw r||s): {to_hex(signature)}")

    # === STEP 5: Build Secure Package ===
    print(f"\n🔹 STEP 5: Assembling secure package...")
    secure_package = {
        'ciphertext': aes_result['ciphertext'],
        'iv': aes_result['iv'],
        'encrypted_aes_key': encap['encrypted_aes_key'],
        'nonce': encap['nonce'],
        'tag': encap['tag'],
        'ephemeral_public_key': encap['ephemeral_public_key'],
        'signature': signature
    }
    print("✅ Secure package assembled with all components.")

    # === STEP 6: Verify Signature ===
    print(f"\n🔹 STEP 6: Verifying signature using sender's public key...")
    is_valid = verify_signature(
        secure_package['ciphertext'],
        secure_package['signature'],
        sender_public_key
    )
    print(f"   Signature valid? {is_valid}")
    assert is_valid, "❌ Signature verification failed!"
    print("✅ Signature verified — message is authentic and unaltered.")

    # === STEP 7: Decapsulate AES Key ===
    print(f"\n🔹 STEP 7: Recipient decapsulating AES key using their private key...")
    decrypted_aes_key = decapsulate_aes_key(
        encrypted_aes_key_bytes=secure_package['encrypted_aes_key'],
        recipient_private_key_obj=recipient_private_key,
        ephemeral_public_key=secure_package['ephemeral_public_key'],
        nonce=secure_package['nonce'],
        tag=secure_package['tag']
    )
    print(f"   Recovered AES Key: {to_hex(decrypted_aes_key)}")
    assert decrypted_aes_key == aes_result['key'], "AES key mismatch!"
    print("✅ AES key successfully recovered!")

    # === STEP 8: Decrypt Message ===
    print(f"\n🔹 STEP 8: Decrypting ciphertext with recovered AES key...")
    decrypted_data = decrypt_aes(
        aes_key_bytes=decrypted_aes_key,
        iv_bytes=secure_package['iv'],
        ciphertext_bytes=secure_package['ciphertext']
    )
    print(f"   Decrypted plaintext: ", end="")
    try:
        print(decrypted_data.decode('utf-8'))
    except UnicodeDecodeError:
        print("<Binary data – not printable as text>")
    print(f"   Bytes: {to_hex(decrypted_data)}")

    # === STEP 9: Final Validation ===
    assert decrypted_data == input_data, "Decryption failed!"
    print("\n" + "=" * 70)
    print("🎉 END-TO-END TEST PASSED! All stages successful.")
    print("=" * 70)

if __name__ == "__main__":
    print("🔐 Secure Hybrid Encryption Demo")
    print("Select input type:")
    choice = input("(1) Text message\n(2) File path\nYour choice: ").strip()

    if choice == "1":
        user_input = input("Enter your message: ")
    elif choice == "2":
        user_input = input("Enter file path (e.g., report.pdf): ").strip()
    else:
        print("❌ Invalid choice. Exiting.")
        sys.exit(1)

    try:
        input_bytes = load_input_data(user_input)
    except Exception as e:
        print(f"❌ Error loading input: {e}")
        sys.exit(1)

    test_create_secure_package(input_bytes)