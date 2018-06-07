package de.vanitasvitae.crypto.pgpainless.encryption_signing;

import java.io.IOException;
import java.io.OutputStream;
import java.util.Set;

import de.vanitasvitae.crypto.pgpainless.PublicKeyNotFoundException;
import de.vanitasvitae.crypto.pgpainless.SecretKeyNotFoundException;
import de.vanitasvitae.crypto.pgpainless.algorithm.CompressionAlgorithm;
import de.vanitasvitae.crypto.pgpainless.algorithm.HashAlgorithm;
import de.vanitasvitae.crypto.pgpainless.algorithm.SymmetricKeyAlgorithm;
import de.vanitasvitae.crypto.pgpainless.key.SecretKeyRingProtector;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;

public interface EncryptionBuilderInterface {

    ToRecipients onOutputStream(OutputStream outputStream);

    interface ToRecipients {

        WithAlgorithms toRecipient(PGPPublicKey key);

        WithAlgorithms toRecipients(Set<PGPPublicKeyRing> keys);

        WithAlgorithms toRecipients(Set<Long> keyIds, Set<PGPPublicKeyRingCollection> keys)
                throws PublicKeyNotFoundException;

        SignWith doNotEncrypt();

    }

    interface WithAlgorithms {

        WithAlgorithms andToSelf(PGPPublicKey key);

        WithAlgorithms andToSelf(Set<PGPPublicKeyRing> keys);

        SignWith usingAlgorithms(SymmetricKeyAlgorithm symmetricKeyAlgorithm,
                                 HashAlgorithm hashAlgorithm,
                                 CompressionAlgorithm compressionAlgorithm);

        SignWith usingSecureAlgorithms();

    }

    interface SignWith {

        Armor signWith(PGPSecretKeyRing key, SecretKeyRingProtector decryptor);

        Armor signWith(Set<PGPSecretKeyRing> keyRings, SecretKeyRingProtector decryptor)
                throws SecretKeyNotFoundException;

        Armor signWith(Set<Long> keyIds, Set<PGPSecretKeyRingCollection> keys, SecretKeyRingProtector decryptor)
                throws SecretKeyNotFoundException;

        Armor doNotSign();

    }

    interface Armor {

        OutputStream asciiArmor() throws IOException, PGPException;

        OutputStream noArmor() throws IOException, PGPException;

    }

}
