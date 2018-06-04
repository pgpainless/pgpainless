package de.vanitasvitae.crypto.pgpainless.encryption_signing;

import java.io.InputStream;
import java.io.OutputStream;
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

public interface EncryptionBuilderInterface {

    ToRecipients onOutputStream(OutputStream outputStream);

    interface ToRecipients {

        WithAlgorithms toRecipient(PGPPublicKey key);

        WithAlgorithms toRecipients(Set<PGPPublicKey> keys);

        WithAlgorithms toRecipients(Set<Long> keyIds, Set<PGPPublicKeyRing> keyRings)
                throws PublicKeyNotFoundException;

        WithAlgorithms toRecipients(Set<Long> keyIds, PGPPublicKeyRingCollection keys)
                throws PublicKeyNotFoundException;

        SignWith doNotEncrypt();

    }

    interface WithAlgorithms {

        WithAlgorithms andToSelf(Set<PGPPublicKey> keys);

        SignWith usingAlgorithms(SymmetricKeyAlgorithm symmetricKeyAlgorithm,
                                 HashAlgorithm hashAlgorithm,
                                 CompressionAlgorithm compressionAlgorithm);

    }

    interface SignWith {

        Armor signWith(PGPSecretKey key);

        Armor signWith(Set<PGPSecretKey> keys);

        Armor signWith(Set<Long> keyIds, Set<PGPSecretKeyRing> keyRings) throws SecretKeyNotFoundException;

        Armor signWith(Set<Long> keyIds, PGPSecretKeyRingCollection keys) throws SecretKeyNotFoundException;

        Armor doNotSign();

    }

    interface Armor {

        OutputStream asciiArmor();

        OutputStream noArmor();

    }

}
