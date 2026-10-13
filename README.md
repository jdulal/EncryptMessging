# Cipher Messenger

A Java Android Studio prototype for composing, encrypting, and decrypting messages offline. It does not create accounts, connect to a server, or deliver messages; users must transfer public keys and encrypted text through another channel.

## Open and run

1. Open this folder in Android Studio and allow Gradle sync to finish.
2. Run the `app` configuration on an Android device or emulator running API 24 or later.
3. Tap **Create / load my device key** on each device. The app creates a 3072-bit RSA key pair in Android Keystore and reuses it on later launches.
4. Share the **public key** with the sender. Compare the displayed SHA-256 fingerprint with the recipient over a separate, trusted channel before using a key.
5. Paste the recipient's public key, type a message, and tap **Encrypt message**. Transfer only the resulting `CM1` ciphertext to the recipient.
6. The recipient pastes the ciphertext and taps **Decrypt on this device**.

For a same-device demonstration, create a key, copy that device's public key into the recipient field, encrypt a message, then paste the ciphertext into the decrypt field.

## Cryptography and data handling

- A fresh AES-256 key and 96-bit nonce are generated for every message. AES-GCM provides message confidentiality and tamper detection.
- The AES key is wrapped with the recipient's RSA public key using OAEP with SHA-256.
- The RSA private key is kept in Android Keystore and is never exported by the app. Hardware-backed protection depends on the device.
- No Internet permission is declared; Android backup and device transfer are disabled; plaintext and ciphertext input views are excluded from saved view state; screenshots and recents snapshots are blocked.

This is a learning prototype, not an audited messaging product. It does not authenticate senders, prevent replay, implement key rotation or multi-device identities, or securely deliver messages. Public keys can be substituted unless fingerprints are verified out of band. Clipboard contents and the operating system, keyboard, or a compromised device may expose data. For a real service, use an established, independently reviewed end-to-end encryption protocol and have the complete design professionally reviewed before handling sensitive communications.
