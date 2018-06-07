package de.vanitasvitae.crypto.pgpainless.encryption_signing;

import java.io.IOException;
import java.io.OutputStream;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

import de.vanitasvitae.crypto.pgpainless.PublicKeyNotFoundException;
import de.vanitasvitae.crypto.pgpainless.SecretKeyNotFoundException;
import de.vanitasvitae.crypto.pgpainless.algorithm.CompressionAlgorithm;
import de.vanitasvitae.crypto.pgpainless.algorithm.HashAlgorithm;
import de.vanitasvitae.crypto.pgpainless.algorithm.SymmetricKeyAlgorithm;
import de.vanitasvitae.crypto.pgpainless.key.SecretKeyRingProtector;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;

public class EncryptionBuilder implements EncryptionBuilderInterface {

    private OutputStream outputStream;
    private final Set<PGPPublicKey> encryptionKeys = new HashSet<>();
    private final Set<PGPSecretKey> signingKeys = new HashSet<>();
    private SecretKeyRingProtector signingKeysDecryptor;
    private SymmetricKeyAlgorithm symmetricKeyAlgorithm = SymmetricKeyAlgorithm.AES_128;
    private HashAlgorithm hashAlgorithm = HashAlgorithm.SHA256;
    private CompressionAlgorithm compressionAlgorithm = CompressionAlgorithm.UNCOMPRESSED;
    private boolean asciiArmor = false;

    @Override
    public ToRecipients onOutputStream(OutputStream outputStream) {
        this.outputStream = outputStream;
        return new ToRecipientsImpl();
    }

    class ToRecipientsImpl implements ToRecipients {

        @Override
        public WithAlgorithms toRecipient(PGPPublicKey key) {
            if (!key.isEncryptionKey()) {
                throw new IllegalStateException("Public Key " + Long.toHexString(key.getKeyID()) + " is not capable of encryption.");
            }
            EncryptionBuilder.this.encryptionKeys.add(key);
            return new WithAlgorithmsImpl();
        }

        @Override
        public WithAlgorithms toRecipients(Set<PGPPublicKeyRing> keys) {
            for (PGPPublicKeyRing ring : keys) {
                for (PGPPublicKey k : ring) {
                    if (k.isEncryptionKey()) {
                        EncryptionBuilder.this.encryptionKeys.add(k);
                    }
                }
            }
            return new WithAlgorithmsImpl();
        }

        @Override
        public WithAlgorithms toRecipients(Set<Long> keyIds, Set<PGPPublicKeyRingCollection> keys)
                throws PublicKeyNotFoundException {
            Set<PGPPublicKeyRing> rings = new HashSet<>();

            for (PGPPublicKeyRingCollection collection : keys) {
                for (long keyId : keyIds) {
                    try {
                        PGPPublicKeyRing ring = collection.getPublicKeyRing(keyId);
                        if (ring != null) {
                            rings.add(ring);
                            keyIds.remove(keyId);
                        }
                    } catch (PGPException e) {
                        throw new PublicKeyNotFoundException(e);
                    }
                }
            }

            return toRecipients(rings);
        }

        @Override
        public SignWith doNotEncrypt() {
            return new SignWithImpl();
        }
    }

    class WithAlgorithmsImpl implements WithAlgorithms {

        @Override
        public WithAlgorithms andToSelf(PGPPublicKey key) {
            EncryptionBuilder.this.encryptionKeys.add(key);
            return this;
        }

        @Override
        public WithAlgorithms andToSelf(Set<PGPPublicKeyRing> keyRings) {
            for (PGPPublicKeyRing ring : keyRings) {
                for (Iterator<PGPPublicKey> i = ring.getPublicKeys(); i.hasNext(); ) {
                    PGPPublicKey key = i.next();
                    if (key.isEncryptionKey()) {
                        EncryptionBuilder.this.encryptionKeys.add(key);
                    }
                }
            }
            return this;
        }

        @Override
        public SignWith usingAlgorithms(SymmetricKeyAlgorithm symmetricKeyAlgorithm,
                                        HashAlgorithm hashAlgorithm,
                                        CompressionAlgorithm compressionAlgorithm) {

            EncryptionBuilder.this.symmetricKeyAlgorithm = symmetricKeyAlgorithm;
            EncryptionBuilder.this.hashAlgorithm = hashAlgorithm;
            EncryptionBuilder.this.compressionAlgorithm = compressionAlgorithm;

            return new SignWithImpl();
        }

        @Override
        public SignWith usingSecureAlgorithms() {
            EncryptionBuilder.this.symmetricKeyAlgorithm = SymmetricKeyAlgorithm.AES_256;
            EncryptionBuilder.this.hashAlgorithm = HashAlgorithm.SHA512;
            EncryptionBuilder.this.compressionAlgorithm = CompressionAlgorithm.UNCOMPRESSED;

            return new SignWithImpl();
        }
    }

    class SignWithImpl implements SignWith {

        @Override
        public Armor signWith(PGPSecretKeyRing key, SecretKeyRingProtector decryptor) {
            return signWith(Collections.singleton(key), decryptor);
        }

        @Override
        public Armor signWith(Set<PGPSecretKeyRing> keys, SecretKeyRingProtector decryptor) {
            for (PGPSecretKeyRing key : keys) {
                for (Iterator<PGPSecretKey> i = key.getSecretKeys(); i.hasNext(); ) {
                    PGPSecretKey s = i.next();
                    if (s.isSigningKey()) {
                        EncryptionBuilder.this.signingKeys.add(s);
                    }
                }
            }
            EncryptionBuilder.this.signingKeysDecryptor = decryptor;
            return new ArmorImpl();
        }

        @Override
        public Armor signWith(Set<Long> keyIds, Set<PGPSecretKeyRingCollection> keyRings, SecretKeyRingProtector decryptor)
                throws SecretKeyNotFoundException {
            Set<PGPSecretKeyRing> rings = new HashSet<>();
            for (PGPSecretKeyRingCollection collection : keyRings) {
                for (long keyId : keyIds) {
                    try {
                        PGPSecretKeyRing ring = collection.getSecretKeyRing(keyId);
                        if (ring != null) {
                            rings.add(ring);
                            keyIds.remove(keyId);
                        }
                    } catch (PGPException e) {
                        throw new SecretKeyNotFoundException(keyId);
                    }
                }
            }
            return signWith(rings, decryptor);
        }

        @Override
        public Armor doNotSign() {
            return new ArmorImpl();
        }
    }

    class ArmorImpl implements Armor {

        @Override
        public OutputStream asciiArmor() throws IOException, PGPException {
            EncryptionBuilder.this.asciiArmor = true;
            return build();
        }

        @Override
        public OutputStream noArmor() throws IOException, PGPException {
            EncryptionBuilder.this.asciiArmor = false;
            return build();
        }

        private OutputStream build() throws IOException, PGPException {

            Set<PGPPrivateKey> privateKeys = new HashSet<>();
            for (PGPSecretKey secretKey : signingKeys) {
                privateKeys.add(secretKey.extractPrivateKey(signingKeysDecryptor.getDecryptor(secretKey.getKeyID())));
            }

            return EncryptionStream.create(
                    EncryptionBuilder.this.outputStream,
                    EncryptionBuilder.this.encryptionKeys,
                    privateKeys,
                    EncryptionBuilder.this.symmetricKeyAlgorithm,
                    EncryptionBuilder.this.hashAlgorithm,
                    EncryptionBuilder.this.compressionAlgorithm,
                    EncryptionBuilder.this.asciiArmor);
        }
    }
}
