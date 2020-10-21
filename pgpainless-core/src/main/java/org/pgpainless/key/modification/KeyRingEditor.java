package org.pgpainless.key.modification;

import javax.annotation.Nullable;

import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.pgpainless.key.OpenPgpV4Fingerprint;
import org.pgpainless.key.generation.KeySpec;
import org.pgpainless.util.Passphrase;

public class KeyRingEditor implements KeyRingEditorInterface {

    private PGPSecretKeyRing secretKeyRing;

    public KeyRingEditor(PGPSecretKeyRing secretKeyRing) {
        this(secretKeyRing, null);
    }

    public KeyRingEditor(PGPSecretKeyRing secretKeyRing, @Nullable Passphrase passphrase) {
        if (secretKeyRing == null) {
            throw new NullPointerException("SecretKeyRing MUST NOT be null.");
        }
        this.secretKeyRing = secretKeyRing;
    }

    @Override
    public KeyRingEditorInterface addUserId(String userId) {
        return this;
    }

    @Override
    public KeyRingEditorInterface deleteUserId(String userId) {
        return this;
    }

    @Override
    public KeyRingEditorInterface addSubKey(KeySpec keySpec) {
        return this;
    }

    @Override
    public KeyRingEditorInterface deleteSubKey(OpenPgpV4Fingerprint fingerprint) {
        return this;
    }

    @Override
    public KeyRingEditorInterface deleteSubKey(long subKeyId) {
        return this;
    }

    @Override
    public KeyRingEditorInterface revokeSubKey(OpenPgpV4Fingerprint fingerprint) {
        return this;
    }

    @Override
    public KeyRingEditorInterface revokeSubKey(long subKeyId) {
        return this;
    }

    @Override
    public PGPSecretKeyRing done() {
        return secretKeyRing;
    }
}
