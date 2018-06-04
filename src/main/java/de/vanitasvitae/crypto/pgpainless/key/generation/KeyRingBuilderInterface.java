package de.vanitasvitae.crypto.pgpainless.key.generation;

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSecretKeyRing;

public interface KeyRingBuilderInterface {

    KeyRingBuilderInterface withSubKey(KeySpec keySpec);

    WithPrimaryUserId withMasterKey(KeySpec keySpec);

    interface WithPrimaryUserId {

        WithPassphrase withPrimaryUserId(String userId);

        WithPassphrase withPrimaryUserId(byte[] userId);

    }

    interface WithPassphrase {

        Build withPassphrase(String passphrase);

        Build withPassphrase(char[] passphrase);

        Build withoutPassphrase();
    }

    interface Build {

        PGPSecretKeyRing build() throws NoSuchAlgorithmException, PGPException, NoSuchProviderException,
                InvalidAlgorithmParameterException;

    }
}
