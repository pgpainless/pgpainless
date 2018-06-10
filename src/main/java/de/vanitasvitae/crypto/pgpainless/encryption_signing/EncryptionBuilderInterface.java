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
import de.vanitasvitae.crypto.pgpainless.key.selection.keyring.PublicKeyRingSelectionStrategy;
import de.vanitasvitae.crypto.pgpainless.key.selection.keyring.SecretKeyRingSelectionStrategy;
import de.vanitasvitae.crypto.pgpainless.util.MultiMap;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;

public interface EncryptionBuilderInterface {

    ToRecipients onOutputStream(OutputStream outputStream);

    interface ToRecipients {

        WithAlgorithms toRecipients(PGPPublicKey... keys);

        WithAlgorithms toRecipients(PGPPublicKeyRing... keys);

        <O> WithAlgorithms toRecipients(PublicKeyRingSelectionStrategy<O> selectionStrategy,
                                       MultiMap<O, PGPPublicKeyRingCollection> keys);

        SignWith doNotEncrypt();

    }

    interface WithAlgorithms {

        WithAlgorithms andToSelf(PGPPublicKey... keys);

        WithAlgorithms andToSelf(PGPPublicKeyRing... keys);

        <O> WithAlgorithms andToSelf(PublicKeyRingSelectionStrategy<O> selectionStrategy,
                                    MultiMap<O, PGPPublicKeyRingCollection> keys);

        SignWith usingAlgorithms(SymmetricKeyAlgorithm symmetricKeyAlgorithm,
                                 HashAlgorithm hashAlgorithm,
                                 CompressionAlgorithm compressionAlgorithm);

        SignWith usingSecureAlgorithms();

    }

    interface SignWith {

        <O> Armor signWith(SecretKeyRingProtector decryptor, PGPSecretKey... keys);

        <O> Armor signWith(SecretKeyRingProtector decryptor, PGPSecretKeyRing... keyRings);

        <O> Armor signWith(SecretKeyRingSelectionStrategy<O> selectionStrategy,
                          SecretKeyRingProtector decryptor,
                          MultiMap<O, PGPSecretKeyRingCollection> keys)
                throws SecretKeyNotFoundException;

        Armor doNotSign();

    }

    interface Armor {

        OutputStream asciiArmor() throws IOException, PGPException;

        OutputStream noArmor() throws IOException, PGPException;

    }

}
