package com.example.cipher;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.RSAKey;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Locale;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;

final class MessageCipher {
    static final String KEY_ALIAS = "cipher-messenger-device-key-v1";

    private static final String ANDROID_KEY_STORE = "AndroidKeyStore";
    private static final String ENVELOPE_VERSION = "CM1";
    private static final String RSA_TRANSFORMATION = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
    private static final String AES_TRANSFORMATION = "AES/GCM/NoPadding";
    private static final String AAD = "CipherMessenger:CM1";
    private static final int RSA_KEY_SIZE = 3072;
    private static final int MIN_RSA_KEY_SIZE = 2048;
    private static final int MAX_RSA_KEY_SIZE = 8192;
    private static final int AES_KEY_SIZE = 256;
    private static final int GCM_NONCE_SIZE = 12;
    private static final int GCM_TAG_SIZE_BITS = 128;
    private static final int GCM_TAG_SIZE_BYTES = GCM_TAG_SIZE_BITS / 8;
    private static final int MAX_MESSAGE_BYTES = 1024 * 1024;
    private static final int MAX_ENVELOPE_CHARS = 2 * 1024 * 1024;
    private static final OAEPParameterSpec OAEP_PARAMETERS = new OAEPParameterSpec(
            "SHA-256", "MGF1", MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT);

    private MessageCipher() {
    }

    static PublicKey loadDevicePublicKey() throws GeneralSecurityException {
        KeyStore keyStore = loadKeyStore();
        if (!keyStore.containsAlias(KEY_ALIAS)) {
            return null;
        }

        KeyStore.Entry entry = keyStore.getEntry(KEY_ALIAS, null);
        if (!(entry instanceof KeyStore.PrivateKeyEntry)) {
            throw new GeneralSecurityException("The saved device key is unavailable.");
        }

        PublicKey publicKey = ((KeyStore.PrivateKeyEntry) entry).getCertificate().getPublicKey();
        validateRsaKey(publicKey);
        return publicKey;
    }

    static PublicKey createOrLoadDeviceKey() throws GeneralSecurityException {
        PublicKey existingKey = loadDevicePublicKey();
        if (existingKey != null) {
            return existingKey;
        }

        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", ANDROID_KEY_STORE);
        KeyGenParameterSpec keySpec = new KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setKeySize(RSA_KEY_SIZE)
                .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA1)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
                .build();
        generator.initialize(keySpec);
        generator.generateKeyPair();

        PublicKey publicKey = loadDevicePublicKey();
        if (publicKey == null) {
            throw new GeneralSecurityException("The device did not save the new key.");
        }
        return publicKey;
    }

    static String encodePublicKey(PublicKey publicKey) {
        return Base64.encodeToString(publicKey.getEncoded(), Base64.NO_WRAP);
    }

    static String fingerprint(PublicKey publicKey) throws GeneralSecurityException {
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(publicKey.getEncoded());
        StringBuilder result = new StringBuilder("SHA-256 fingerprint: ");
        for (int i = 0; i < digest.length; i++) {
            if (i > 0) {
                result.append(i % 4 == 0 ? "  " : " ");
            }
            result.append(String.format(Locale.ROOT, "%02X", digest[i] & 0xff));
        }
        return result.toString();
    }

    static String encrypt(String message, String recipientKeyText) throws GeneralSecurityException {
        byte[] plaintext = message.getBytes(StandardCharsets.UTF_8);
        if (plaintext.length == 0) {
            throw new IllegalArgumentException("Enter a message to encrypt.");
        }
        if (plaintext.length > MAX_MESSAGE_BYTES) {
            throw new IllegalArgumentException("The message is larger than 1 MB.");
        }

        PublicKey recipientKey = decodePublicKey(recipientKeyText);
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(AES_KEY_SIZE);
        SecretKey messageKey = keyGenerator.generateKey();

        byte[] nonce = new byte[GCM_NONCE_SIZE];
        new SecureRandom().nextBytes(nonce);
        Cipher messageCipher = Cipher.getInstance(AES_TRANSFORMATION);
        messageCipher.init(Cipher.ENCRYPT_MODE, messageKey, new GCMParameterSpec(GCM_TAG_SIZE_BITS, nonce));
        messageCipher.updateAAD(AAD.getBytes(StandardCharsets.UTF_8));
        byte[] encryptedMessage = messageCipher.doFinal(plaintext);

        Cipher keyCipher = createOaepCipher();
        keyCipher.init(Cipher.ENCRYPT_MODE, recipientKey, OAEP_PARAMETERS);
        byte[] encryptedKey = keyCipher.doFinal(messageKey.getEncoded());

        return ENVELOPE_VERSION
                + "." + encodeUrlSafe(encryptedKey)
                + "." + encodeUrlSafe(nonce)
                + "." + encodeUrlSafe(encryptedMessage);
    }

    static String decrypt(String envelope) throws GeneralSecurityException {
        if (envelope == null || envelope.length() > MAX_ENVELOPE_CHARS) {
            throw new IllegalArgumentException("The encrypted message is too large or empty.");
        }

        String[] parts = envelope.trim().split("\\.", -1);
        if (parts.length != 4 || !ENVELOPE_VERSION.equals(parts[0])) {
            throw new IllegalArgumentException("This is not a supported Cipher Messenger message.");
        }

        byte[] encryptedKey = decodeUrlSafe(parts[1]);
        byte[] nonce = decodeUrlSafe(parts[2]);
        byte[] encryptedMessage = decodeUrlSafe(parts[3]);
        if (encryptedKey.length < MIN_RSA_KEY_SIZE / 8
                || encryptedKey.length > MAX_RSA_KEY_SIZE / 8
                || nonce.length != GCM_NONCE_SIZE
                || encryptedMessage.length < GCM_TAG_SIZE_BYTES
                || encryptedMessage.length > MAX_MESSAGE_BYTES + GCM_TAG_SIZE_BYTES) {
            throw new IllegalArgumentException("The encrypted message has an invalid format.");
        }

        KeyStore keyStore = loadKeyStore();
        KeyStore.Entry entry = keyStore.getEntry(KEY_ALIAS, null);
        if (!(entry instanceof KeyStore.PrivateKeyEntry)) {
            throw new GeneralSecurityException("This device has no key to decrypt the message.");
        }

        Cipher keyCipher = createOaepCipher();
        keyCipher.init(Cipher.DECRYPT_MODE, ((KeyStore.PrivateKeyEntry) entry).getPrivateKey(), OAEP_PARAMETERS);
        byte[] messageKeyBytes = keyCipher.doFinal(encryptedKey);
        if (messageKeyBytes.length != AES_KEY_SIZE / 8) {
            throw new GeneralSecurityException("The encrypted message contains an invalid key.");
        }

        SecretKey messageKey = new SecretKeySpec(messageKeyBytes, "AES");
        Cipher messageCipher = Cipher.getInstance(AES_TRANSFORMATION);
        messageCipher.init(Cipher.DECRYPT_MODE, messageKey, new GCMParameterSpec(GCM_TAG_SIZE_BITS, nonce));
        messageCipher.updateAAD(AAD.getBytes(StandardCharsets.UTF_8));
        byte[] plaintext;
        try {
            plaintext = messageCipher.doFinal(encryptedMessage);
        } catch (AEADBadTagException exception) {
            throw new AEADBadTagException("Message authentication failed.");
        }
        return new String(plaintext, StandardCharsets.UTF_8);
    }

    private static PublicKey decodePublicKey(String encodedKey) throws GeneralSecurityException {
        if (encodedKey == null || encodedKey.trim().isEmpty() || encodedKey.length() > 16 * 1024) {
            throw new IllegalArgumentException("Paste the recipient's public key first.");
        }

        final byte[] decoded;
        try {
            decoded = Base64.decode(encodedKey.replaceAll("\\s", ""), Base64.DEFAULT);
        } catch (IllegalArgumentException exception) {
            throw new IllegalArgumentException("The recipient public key is not valid Base64.");
        }

        PublicKey publicKey = KeyFactory.getInstance("RSA")
                .generatePublic(new X509EncodedKeySpec(decoded));
        validateRsaKey(publicKey);
        return publicKey;
    }

    private static void validateRsaKey(PublicKey publicKey) throws GeneralSecurityException {
        if (!(publicKey instanceof RSAKey)) {
            throw new GeneralSecurityException("The recipient key must be an RSA public key.");
        }

        int keySize = ((RSAKey) publicKey).getModulus().bitLength();
        if (keySize < MIN_RSA_KEY_SIZE || keySize > MAX_RSA_KEY_SIZE) {
            throw new GeneralSecurityException("The RSA key must be between 2048 and 8192 bits.");
        }
    }

    private static KeyStore loadKeyStore() throws GeneralSecurityException {
        KeyStore keyStore = KeyStore.getInstance(ANDROID_KEY_STORE);
        try {
            keyStore.load(null);
        } catch (java.io.IOException exception) {
            throw new GeneralSecurityException("The Android secure key store could not be read.", exception);
        } catch (java.security.cert.CertificateException exception) {
            throw new GeneralSecurityException("The Android secure key store could not be read.", exception);
        }
        return keyStore;
    }

    private static Cipher createOaepCipher() throws GeneralSecurityException {
        return Cipher.getInstance(RSA_TRANSFORMATION);
    }

    private static String encodeUrlSafe(byte[] value) {
        return Base64.encodeToString(value, Base64.URL_SAFE | Base64.NO_WRAP | Base64.NO_PADDING);
    }

    private static byte[] decodeUrlSafe(String value) {
        if (value.isEmpty()) {
            throw new IllegalArgumentException("The encrypted message has an invalid format.");
        }
        for (int i = 0; i < value.length(); i++) {
            char character = value.charAt(i);
            boolean valid = (character >= 'A' && character <= 'Z')
                    || (character >= 'a' && character <= 'z')
                    || (character >= '0' && character <= '9')
                    || character == '-' || character == '_';
            if (!valid) {
                throw new IllegalArgumentException("The encrypted message has an invalid format.");
            }
        }
        return Base64.decode(value, Base64.URL_SAFE | Base64.NO_WRAP | Base64.NO_PADDING);
    }
}
