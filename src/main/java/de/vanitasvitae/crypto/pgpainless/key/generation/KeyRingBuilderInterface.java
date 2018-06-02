package de.vanitasvitae.crypto.pgpainless.key.generation;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSecretKeyRing;

public interface KeyRingBuilderInterface {

    WithSubKeyType generateCompositeKeyRing();

    WithCertificationKeyType generateSingleKeyKeyRing();

    interface WithSubKeyType {

        WithSubKeyType withSubKey(KeySpec keySpec);

        WithCertificationKeyType done();
    }

    interface WithCertificationKeyType {
        WithPrimaryUserId withCertificationKeyType(KeySpec keySpec);
    }

    interface WithPrimaryUserId {

        WithAdditionalUserIds withPrimaryUserId(String userId);

        WithAdditionalUserIds withPrimaryUserId(byte[] userId);

    }

    interface WithAdditionalUserIds {

        WithAdditionalUserIds withAdditionalUserId(String userId);

        WithAdditionalUserIds withAdditionalUserId(byte[] userId);

        WithPassphrase done();

    }

    interface WithPassphrase {

        Build withPassphrase(String passphrase);

        Build withPassphrase(char[] passphrase);

        Build withoutPassphrase();
    }

    interface Build {

        PGPSecretKeyRing build() throws NoSuchAlgorithmException, PGPException, NoSuchProviderException;

    }
}
