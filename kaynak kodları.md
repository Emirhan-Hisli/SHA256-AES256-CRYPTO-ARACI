#!/usr/bin/env python3

import os
import base64
import hashlib
import getpass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ============================================================
# SHA-256 + AES-256-GCM MESAJ ŞİFRELEME ARACI
# ============================================================


def derive_key(password):
    """
    Ortak paroladan SHA-256 kullanarak
    256-bit (32 byte) AES anahtarı üretir.
    """
    return hashlib.sha256(
        password.encode("utf-8")
    ).digest()


def encrypt_message(message, password):
    """
    Mesajı AES-256-GCM ile şifreler.
    Sonucu Base64 olarak döndürür.
    """

    # SHA-256 -> 32 byte = 256 bit AES anahtarı
    key = derive_key(password)

    # AES-GCM için 96-bit (12 byte) benzersiz nonce
    nonce = os.urandom(12)

    # AES-256-GCM
    aes = AESGCM(key)

    ciphertext = aes.encrypt(
        nonce,
        message.encode("utf-8"),
        None
    )

    # Nonce + şifreli veri
    # Çözerken nonce'u tekrar ayıracağız.
    encrypted_data = nonce + ciphertext

    # Base64 ile mesaj olarak gönderilebilir hale getir
    encoded = base64.urlsafe_b64encode(
        encrypted_data
    ).decode("utf-8")

    return encoded


def decrypt_message(encrypted_message, password):
    """
    Base64 AES-256-GCM mesajını çözer.
    """

    try:
        # SHA-256 -> AES-256 anahtarı
        key = derive_key(password)

        # Base64 çöz
        encrypted_data = base64.urlsafe_b64decode(
            encrypted_message.encode("utf-8")
        )

        # İlk 12 byte nonce
        nonce = encrypted_data[:12]

        # Geri kalan şifreli veri + authentication tag
        ciphertext = encrypted_data[12:]

        # AES-256-GCM
        aes = AESGCM(key)

        plaintext = aes.decrypt(
            nonce,
            ciphertext,
            None
        )

        return plaintext.decode("utf-8")

    except Exception:
        return None


def encrypt_mode():
    print("\n" + "=" * 60)
    print(" MESAJ ŞİFRELE")
    print("=" * 60)

    message = input("\nMesaj: ")

    if not message:
        print("\n[!] Boş mesaj şifrelenemez.")
        return

    password = getpass.getpass(
        "Ortak parola: "
    )

    if not password:
        print("\n[!] Parola boş olamaz.")
        return

    encrypted = encrypt_message(
        message,
        password
    )

    print("\n" + "-" * 60)
    print("ŞİFRELİ MESAJ")
    print("-" * 60)

    print(encrypted)

    print("-" * 60)
    print("Bu metni arkadaşına gönderebilirsin.")
    print()


def decrypt_mode():
    print("\n" + "=" * 60)
    print(" MESAJ ÇÖZ")
    print("=" * 60)

    encrypted = input(
        "\nŞifreli mesaj: "
    ).strip()

    if not encrypted:
        print("\n[!] Şifreli mesaj boş olamaz.")
        return

    password = getpass.getpass(
        "Ortak parola: "
    )

    if not password:
        print("\n[!] Parola boş olamaz.")
        return

    decrypted = decrypt_message(
        encrypted,
        password
    )

    if decrypted is None:
        print("\n[!] MESAJ ÇÖZÜLEMEDİ!")
        print("[!] Parola yanlış olabilir.")
        print("[!] Mesaj bozulmuş veya değiştirilmiş olabilir.")
        return

    print("\n" + "-" * 60)
    print("ÇÖZÜLEN MESAJ")
    print("-" * 60)

    print(decrypted)

    print("-" * 60)
    print()


def main():
    while True:

        print()
        print("=" * 60)
        print("       SHA-256 / AES-256-GCM MESAJ ARACI")
        print("=" * 60)
        print()
        print("[1] Mesaj şifrele")
        print("[2] Mesaj çöz")
        print("[3] Çıkış")
        print()

        choice = input(
            "Seçim: "
        ).strip()

        if choice == "1":
            encrypt_mode()

        elif choice == "2":
            decrypt_mode()

        elif choice == "3":
            print("\nÇıkılıyor...")
            break

        else:
            print("\n[!] Geçersiz seçim.")


if __name__ == "__main__":
    main()
