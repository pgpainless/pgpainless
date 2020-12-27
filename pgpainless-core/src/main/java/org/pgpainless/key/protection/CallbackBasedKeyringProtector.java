package org.pgpainless.key.protection;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor;
import org.pgpainless.implementation.ImplementationFactory;
import org.pgpainless.util.Passphrase;

public class CallbackBasedKeyringProtector implements SecretKeyRingProtector2 {

    private final Map<Long, Passphrase> passphraseCache = new ConcurrentHashMap<>();
    private final Callback callback;

    public CallbackBasedKeyringProtector(Callback callback) {
        if (callback == null) {
            throw new NullPointerException("Callback MUST NOT be null.");
        }
        this.callback = callback;
    }

    @Override
    public PBESecretKeyDecryptor getDecryptor(PGPSecretKey key) throws PGPException {
        Passphrase passphrase = lookupPassphraseInCache(key);
        if (passphrase != null) {
            passphrase = callback.getPassphraseFor(key);
            passphraseCache.put(key.getKeyID(), passphrase);
        }
        return ImplementationFactory.getInstance().getPBESecretKeyDecryptor(passphrase);
    }

    @Override
    public PBESecretKeyEncryptor getEncryptor(PGPSecretKey key) throws PGPException {
        Passphrase passphrase = lookupPassphraseInCache(key);
        if (passphrase != null) {
            passphrase = callback.getPassphraseFor(key);
            passphraseCache.put(key.getKeyID(), passphrase);
        }
        return ImplementationFactory.getInstance().getPBESecretKeyEncryptor(key, passphrase);
    }

    private Passphrase lookupPassphraseInCache(PGPSecretKey key) {
        return passphraseCache.get(key.getKeyID());
    }

    public interface Callback {
        Passphrase getPassphraseFor(PGPSecretKey secretKey);
    }
}
