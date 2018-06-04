package de.vanitasvitae.crypto.pgpainless.encryption_signing;

import java.io.OutputStream;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

import de.vanitasvitae.crypto.pgpainless.PublicKeyNotFoundException;
import de.vanitasvitae.crypto.pgpainless.SecretKeyNotFoundException;
import de.vanitasvitae.crypto.pgpainless.algorithm.CompressionAlgorithm;
import de.vanitasvitae.crypto.pgpainless.algorithm.HashAlgorithm;
import de.vanitasvitae.crypto.pgpainless.algorithm.SymmetricKeyAlgorithm;
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
    private SymmetricKeyAlgorithm symmetricKeyAlgorithm;
    private HashAlgorithm hashAlgorithm;
    private CompressionAlgorithm compressionAlgorithm;
    private boolean asciiArmor = false;

    @Override
    public ToRecipients onOutputStream(OutputStream outputStream) {
        this.outputStream = outputStream;
        return new ToRecipientsImpl();
    }

    class ToRecipientsImpl implements ToRecipients {

        @Override
        public WithAlgorithms toRecipient(PGPPublicKey key) {
            EncryptionBuilder.this.encryptionKeys.add(key);
            return new WithAlgorithmsImpl();
        }

        @Override
        public WithAlgorithms toRecipients(Set<PGPPublicKey> keys) {
            EncryptionBuilder.this.encryptionKeys.addAll(keys);
            return new WithAlgorithmsImpl();
        }

        @Override
        public WithAlgorithms toRecipients(Set<Long> keyIds, Set<PGPPublicKeyRing> keyRings)
                throws PublicKeyNotFoundException {

            Set<PGPPublicKey> keys = new HashSet<>();

            for (Long id : keyIds) {
                PGPPublicKey key = null;

                for (PGPPublicKeyRing ring : keyRings) {
                    key = ring.getPublicKey(id);
                    if (key != null) {
                        break; // Found key. Break inner loop
                    }
                }

                if (key == null) {
                    throw new PublicKeyNotFoundException(id);
                }

                keys.add(key);
            }
            return toRecipients(keys);
        }

        @Override
        public WithAlgorithms toRecipients(Set<Long> keyIds, PGPPublicKeyRingCollection keyRings)
                throws PublicKeyNotFoundException {

            Set<PGPPublicKeyRing> rings = new HashSet<>();

            for (Iterator<PGPPublicKeyRing> i = keyRings.getKeyRings(); i.hasNext();) {
                rings.add(i.next());
            }

            return toRecipients(keyIds, rings);
        }

        @Override
        public SignWith doNotEncrypt() {
            return new SignWithImpl();
        }
    }

    class WithAlgorithmsImpl implements WithAlgorithms {

        @Override
        public WithAlgorithms andToSelf(Set<PGPPublicKey> keys) {
            EncryptionBuilder.this.encryptionKeys.addAll(keys);
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
    }

    class SignWithImpl implements SignWith {

        @Override
        public Armor signWith(PGPSecretKey key) {
            EncryptionBuilder.this.signingKeys.add(key);
            return new ArmorImpl();
        }

        @Override
        public Armor signWith(Set<PGPSecretKey> keys) {
            EncryptionBuilder.this.signingKeys.addAll(keys);
            return new ArmorImpl();
        }

        @Override
        public Armor signWith(Set<Long> keyIds, Set<PGPSecretKeyRing> keyRings)
                throws SecretKeyNotFoundException {
            Set<PGPSecretKey> keys = new HashSet<>();

            for (Long id : keyIds) {

                PGPSecretKey key = null;

                for (PGPSecretKeyRing ring : keyRings) {
                    key = ring.getSecretKey(id);
                    if (key != null) {
                        break; // Found key. Break inner loop
                    }
                }

                if (key == null) {
                    throw new SecretKeyNotFoundException(id);
                }

                keys.add(key);
            }
            return signWith(keys);
        }

        @Override
        public Armor signWith(Set<Long> keyIds, PGPSecretKeyRingCollection keys)
                throws SecretKeyNotFoundException {

            Set<PGPSecretKeyRing> rings = new HashSet<>();

            for (Iterator<PGPSecretKeyRing> i = keys.getKeyRings(); i.hasNext();) {
                rings.add(i.next());
            }
            return signWith(keyIds, rings);
        }

        @Override
        public Armor doNotSign() {
            return new ArmorImpl();
        }
    }

    class ArmorImpl implements Armor {

        @Override
        public OutputStream asciiArmor() {
            EncryptionBuilder.this.asciiArmor = true;
            return build();
        }

        @Override
        public OutputStream noArmor() {
            EncryptionBuilder.this.asciiArmor = false;
            return build();
        }

        private OutputStream build() {
            return EncryptionStream.create(
                    EncryptionBuilder.this.outputStream,
                    EncryptionBuilder.this.encryptionKeys,
                    EncryptionBuilder.this.signingKeys,
                    EncryptionBuilder.this.symmetricKeyAlgorithm,
                    EncryptionBuilder.this.hashAlgorithm,
                    EncryptionBuilder.this.compressionAlgorithm,
                    EncryptionBuilder.this.asciiArmor);
        }
    }
}
