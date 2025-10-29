// SPDX-FileCopyrightText: 2025 Alexander Grahn
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.example;

import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;

import org.bouncycastle.bcpg.KeyIdentifier;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.exception.WrongPassphraseException;
import org.pgpainless.key.protection.UnlockSecretKey;
import org.pgpainless.util.Passphrase;

public class ModifyStrippedKeyTest {

    private OpenPGPKey strippedKey;

    /**
     * This example tries to change the passphrase of the encryption subkey in a "stripped" key to a new passphrase.
     * The key is stripped, as the primary secret key is diverted to a smart card.
     */
    @Test
    public void changeEncryptionSubkeyPassphrase() throws PGPException, IOException {

        String strippedKeyString =
                "-----BEGIN PGP PRIVATE KEY BLOCK-----\n\n" +
                        "lDsEaNz9VhYJKwYBBAHaRw8BAQdANvkQp6G9vVPUtxHplmw44lclTAm2vSqREnfi\n" +
                        "bsqmDDP/AGUAR05VAbQfQm9iIFVzZXIgPGJvYi51c2VyQGV4YW1wbGUub3JnPoiT\n" +
                        "BBMWCgA7FiEE81kLNGDerGMA7okHMcFP0Qqg/SwFAmjc/VYCGwEFCwkIBwICIgIG\n" +
                        "FQoJCAsCBBYCAwECHgcCF4AACgkQMcFP0Qqg/Szv3AEA5Q0S6UrHI6YC9IqCV86Z\n" +
                        "xF7zegeUJiTGfbIMmp+7qk4BAIJBZyfpsutfdnLBmXMQmPPvdlfNZ0H781sm4vq4\n" +
                        "1KkFnIsEaNz9pRIKKwYBBAGXVQEFAQEHQLilfhrcbzI6XI7a+HbOfqNj/9cwZk8s\n" +
                        "O4H/4IMhY7ZZAwEIB/4HAwIpPDPOpRpcw//ZZTsMuT5ZRDGnSA+3i34NWnhv50ex\n" +
                        "yf51MgrvY+E3NaE9ObFfvEJILF8kub206yaQRbHWPrj7fU1C+DKJ9AbDcXZmzu/U\n" +
                        "iHgEGBYKACAWIQTzWQs0YN6sYwDuiQcxwU/RCqD9LAUCaNz9pQIbDAAKCRAxwU/R\n" +
                        "CqD9LCNSAP9v7GminBOFV8XkMsL4T+0P0woGjTZxUrYKKVR98NhXswEAhDfkQh0n\n" +
                        "IyhOyHwzLuoGJ31M7a1rtB44tcJNtnP6XQQ=\n" +
                        "=jquc\n" +
                        "-----END PGP PRIVATE KEY BLOCK-----\n";

        PGPainless api = PGPainless.getInstance();

        strippedKey = api.readKey().parseKey(strippedKeyString);

        KeyIdentifier encryptionSubkeyId = strippedKey.getEncryptionKeys().get(0).getKeyIdentifier();

        strippedKey = api.modify(strippedKey)
                // Here we change the passphrase of the encryption subkey
                .changeSubKeyPassphraseFromOldPassphrase(encryptionSubkeyId, Passphrase.fromPassword("12345678"))
                .withSecureDefaultSettings()
                .toNewPassphrase(Passphrase.fromPassword("asdfghjk"))
                .done();

        // encryption key can now only be unlocked using the new passphrase
        assertThrows(WrongPassphraseException.class, () ->
                UnlockSecretKey.unlockSecretKey(
                        strippedKey.getSecretKey(encryptionSubkeyId).getPGPSecretKey(), Passphrase.fromPassword("12345678")));
        UnlockSecretKey.unlockSecretKey(
                strippedKey.getSecretKey(encryptionSubkeyId).getPGPSecretKey(), Passphrase.fromPassword("asdfghjk"));
    }

}
