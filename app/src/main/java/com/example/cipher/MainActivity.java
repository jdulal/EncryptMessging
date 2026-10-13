package com.example.cipher;

import android.app.Activity;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.WindowManager;
import android.view.inputmethod.EditorInfo;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import javax.crypto.AEADBadTagException;
import javax.crypto.BadPaddingException;

public final class MainActivity extends Activity {
    private final ExecutorService cryptoExecutor = Executors.newSingleThreadExecutor();
    private final Handler mainHandler = new Handler(Looper.getMainLooper());

    private TextView keyStatus;
    private TextView myPublicKey;
    private TextView myKeyFingerprint;
    private TextView encryptedOutput;
    private TextView decryptedOutput;
    private EditText recipientPublicKeyInput;
    private EditText messageInput;
    private EditText ciphertextInput;
    private Button copyPublicKeyButton;
    private Button copyEncryptedButton;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        getWindow().setFlags(
                WindowManager.LayoutParams.FLAG_SECURE,
                WindowManager.LayoutParams.FLAG_SECURE);
        setContentView(R.layout.activity_main);

        keyStatus = findViewById(R.id.keyStatus);
        myPublicKey = findViewById(R.id.myPublicKey);
        myKeyFingerprint = findViewById(R.id.myKeyFingerprint);
        encryptedOutput = findViewById(R.id.encryptedOutput);
        decryptedOutput = findViewById(R.id.decryptedOutput);
        recipientPublicKeyInput = findViewById(R.id.recipientPublicKeyInput);
        messageInput = findViewById(R.id.messageInput);
        ciphertextInput = findViewById(R.id.ciphertextInput);
        copyPublicKeyButton = findViewById(R.id.copyPublicKeyButton);
        copyEncryptedButton = findViewById(R.id.copyEncryptedButton);

        disablePersonalizedKeyboardLearning(messageInput);
        disablePersonalizedKeyboardLearning(ciphertextInput);
        disablePersonalizedKeyboardLearning(recipientPublicKeyInput);

        findViewById(R.id.createKeyButton).setOnClickListener(view -> createOrLoadKey());
        copyPublicKeyButton.setOnClickListener(
                view -> copyText(R.string.public_key_label, myPublicKey.getText().toString()));
        copyEncryptedButton.setOnClickListener(
                view -> copyText(R.string.encrypted_message_label, encryptedOutput.getText().toString()));
        findViewById(R.id.encryptButton).setOnClickListener(view -> encryptMessage());
        findViewById(R.id.decryptButton).setOnClickListener(view -> decryptMessage());

        loadExistingKey();
    }

    private void disablePersonalizedKeyboardLearning(EditText input) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            input.setImeOptions(input.getImeOptions() | EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING);
        }
    }

    private void loadExistingKey() {
        keyStatus.setText(R.string.status_checking_saved_key);
        cryptoExecutor.execute(() -> {
            try {
                PublicKey publicKey = MessageCipher.loadDevicePublicKey();
                mainHandler.post(() -> {
                    if (isFinishing()) {
                        return;
                    }
                    if (publicKey == null) {
                        keyStatus.setText(R.string.status_no_key);
                    } else {
                        showPublicKey(publicKey);
                        keyStatus.setText(R.string.status_key_ready);
                    }
                });
            } catch (GeneralSecurityException exception) {
                showError(getString(R.string.error_load_key, errorMessage(exception)));
            }
        });
    }

    private void createOrLoadKey() {
        keyStatus.setText(R.string.status_creating_key);
        cryptoExecutor.execute(() -> {
            try {
                PublicKey publicKey = MessageCipher.createOrLoadDeviceKey();
                mainHandler.post(() -> {
                    if (isFinishing()) {
                        return;
                    }
                    showPublicKey(publicKey);
                    keyStatus.setText(R.string.status_key_ready);
                });
            } catch (GeneralSecurityException exception) {
                showError(getString(R.string.error_create_key, errorMessage(exception)));
            }
        });
    }

    private void showPublicKey(PublicKey publicKey) {
        myPublicKey.setText(MessageCipher.encodePublicKey(publicKey));
        copyPublicKeyButton.setEnabled(true);
        try {
            myKeyFingerprint.setText(getString(
                    R.string.fingerprint_value, MessageCipher.fingerprint(publicKey)));
        } catch (GeneralSecurityException exception) {
            myKeyFingerprint.setText(getString(R.string.error_fingerprint, errorMessage(exception)));
        }
    }

    private void encryptMessage() {
        String recipientKey = recipientPublicKeyInput.getText().toString();
        String message = messageInput.getText().toString();
        encryptedOutput.setText(R.string.encrypting);
        copyEncryptedButton.setEnabled(false);
        cryptoExecutor.execute(() -> {
            try {
                String result = MessageCipher.encrypt(message, recipientKey);
                mainHandler.post(() -> {
                    if (isFinishing()) {
                        return;
                    }
                    encryptedOutput.setText(result);
                    copyEncryptedButton.setEnabled(true);
                });
            } catch (GeneralSecurityException | IllegalArgumentException exception) {
                showError(getString(R.string.error_encrypt, errorMessage(exception)));
            }
        });
    }

    private void decryptMessage() {
        String envelope = ciphertextInput.getText().toString();
        decryptedOutput.setText(R.string.decrypting);
        cryptoExecutor.execute(() -> {
            try {
                String plaintext = MessageCipher.decrypt(envelope);
                mainHandler.post(() -> {
                    if (!isFinishing()) {
                        decryptedOutput.setText(plaintext);
                    }
                });
            } catch (AEADBadTagException exception) {
                showError(getString(R.string.error_tampered_message));
            } catch (BadPaddingException exception) {
                showError(getString(R.string.error_wrong_device_key));
            } catch (GeneralSecurityException | IllegalArgumentException exception) {
                showError(getString(R.string.error_decrypt, errorMessage(exception)));
            }
        });
    }

    private void copyText(int labelResource, String value) {
        ClipboardManager clipboard = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
        String label = getString(labelResource);
        clipboard.setPrimaryClip(ClipData.newPlainText(label, value));
        Toast.makeText(this, getString(R.string.copied_message, label), Toast.LENGTH_SHORT).show();
    }

    private void showError(String message) {
        mainHandler.post(() -> {
            if (isFinishing()) {
                return;
            }
            keyStatus.setText(message);
            Toast.makeText(this, message, Toast.LENGTH_LONG).show();
        });
    }

    private String errorMessage(Exception exception) {
        String message = exception.getMessage();
        return message == null || message.trim().isEmpty()
                ? getString(R.string.error_unexpected_crypto)
                : message;
    }

    @Override
    protected void onDestroy() {
        cryptoExecutor.shutdownNow();
        super.onDestroy();
    }
}
