// SPDX-FileCopyrightText: 2025 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.sop.fuzzing;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.junit.FuzzTest;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.api.KeyPassphraseProvider;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.bouncycastle.openpgp.api.OpenPGPKeyReader;
import org.bouncycastle.openpgp.api.exception.KeyPassphraseException;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;
import org.pgpainless.sop.SOPImpl;
import sop.SOP;
import sop.exception.SOPGPException;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertNotNull;

public class GenerateKeyFuzzTest {

    private final SOP sop = new SOPImpl();

    @FuzzTest(maxDuration = "5m")
    public void generateKeyWithFuzzedUserId(FuzzedDataProvider provider) throws IOException {
        String userId = provider.consumeRemainingAsString();

        try {
            byte[] keyBytes = sop.generateKey()
                    .userId(userId)
                    .generate()
                    .getBytes();

            OpenPGPKey key = new OpenPGPKeyReader().parseKey(keyBytes);
            assertNotNull(key.getUserId(userId), "Cannot fetch user-id for '" + userId + "' (" + Hex.toHexString(userId.getBytes(StandardCharsets.UTF_8)) + ")\n" + new String(keyBytes));
        } catch (IllegalArgumentException e) {
            // expected.
        }
    }

    @FuzzTest
    public void generateKeyWithFuzzedPassphrase(FuzzedDataProvider provider) throws IOException, KeyPassphraseException {
        byte[] passphrase = provider.consumeRemainingAsBytes();

        try {
            byte[] keyBytes = sop.generateKey()
                    .withKeyPassword(passphrase)
                    .generate()
                    .getBytes();

            OpenPGPKey key = new OpenPGPKeyReader().parseKey(keyBytes);
            OpenPGPKey.OpenPGPPrivateKey pk = key.getPrimarySecretKey().unlock(new String(passphrase).toCharArray());
            assertNotNull(pk, "Got null result unlocking key that was generated with passphrase 0x'" + Hex.toHexString(passphrase) + "'");
        }
        catch (SOPGPException.PasswordNotHumanReadable e) {
            // expected.
        }
        catch (PGPException e) {
            throw new RuntimeException("Cannot unlock key that was generated with passphrase 0x'" + Hex.toHexString(passphrase) + "'", e);
        }
    }
}
