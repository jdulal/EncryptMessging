package com.example.cipher;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

import androidx.test.ext.junit.runners.AndroidJUnit4;

import org.junit.Test;
import org.junit.runner.RunWith;

import java.security.PublicKey;
import java.security.interfaces.RSAKey;

import javax.crypto.AEADBadTagException;

@RunWith(AndroidJUnit4.class)
public final class MessageCipherTest {
    @Test
    public void encryptsAndDecryptsWithDeviceKeyAndPreservesKeyAcrossLoads() throws Exception {
        PublicKey createdKey = MessageCipher.createOrLoadDeviceKey();
        PublicKey loadedKey = MessageCipher.loadDevicePublicKey();

        assertNotNull(createdKey);
        assertNotNull(loadedKey);
        assertEquals(3072, ((RSAKey) createdKey).getModulus().bitLength());
        assertEquals(MessageCipher.encodePublicKey(createdKey), MessageCipher.encodePublicKey(loadedKey));

        String message = "Hello, encrypted world! こんにちは";
        String envelope = MessageCipher.encrypt(message, MessageCipher.encodePublicKey(loadedKey));

        assertEquals(message, MessageCipher.decrypt(envelope));
    }

    @Test
    public void rejectsTamperedCiphertext() throws Exception {
        PublicKey publicKey = MessageCipher.createOrLoadDeviceKey();
        String envelope = MessageCipher.encrypt("authenticated", MessageCipher.encodePublicKey(publicKey));
        String[] components = envelope.split("\\.", -1);
        char firstCharacter = components[3].charAt(0);
        components[3] = (firstCharacter == 'A' ? "B" : "A") + components[3].substring(1);
        String tamperedEnvelope = components[0] + "."
                + components[1] + "."
                + components[2] + "."
                + components[3];

        try {
            MessageCipher.decrypt(tamperedEnvelope);
            fail("Tampered ciphertext must not decrypt.");
        } catch (AEADBadTagException expected) {
            assertNotNull(expected.getMessage());
        }
    }

    @Test
    public void rejectsAnUnsupportedEnvelope() throws Exception {
        try {
            MessageCipher.decrypt("CM2.invalid.invalid.invalid");
            fail("An unsupported envelope must be rejected.");
        } catch (IllegalArgumentException expected) {
            assertNotNull(expected.getMessage());
        }
    }
}
