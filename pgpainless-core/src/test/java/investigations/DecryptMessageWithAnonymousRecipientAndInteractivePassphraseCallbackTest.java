// SPDX-FileCopyrightText: 2026 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package investigations;

import org.bouncycastle.bcpg.KeyIdentifier;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.bouncycastle.util.io.Streams;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.decryption_verification.ConsumerOptions;
import org.pgpainless.decryption_verification.DecryptionStream;
import org.pgpainless.decryption_verification.MissingKeyPassphraseStrategy;
import org.pgpainless.encryption_signing.EncryptionOptions;
import org.pgpainless.encryption_signing.EncryptionStream;
import org.pgpainless.encryption_signing.ProducerOptions;
import org.pgpainless.key.protection.CachingSecretKeyRingProtector;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.key.protection.passphrase_provider.SecretKeyPassphraseProvider;
import org.pgpainless.util.Passphrase;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

public class DecryptMessageWithAnonymousRecipientAndInteractivePassphraseCallbackTest {

    @Test
    public void test() throws PGPException, IOException {
        PGPainless api = PGPainless.getInstance();

        OpenPGPKey key = api.generateKey()
                .modernKeyRing("Alice", "sw0rdf1sh");

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        EncryptionStream eOut = api.generateMessage()
                .onOutputStream(bOut)
                .withOptions(ProducerOptions.encrypt(
                        EncryptionOptions.get(api)
                                .addHiddenRecipient(key.toCertificate())
                ));

        eOut.write("Hello World".getBytes());
        eOut.close();

        SecretKeyRingProtector protector = new CachingSecretKeyRingProtector(
                new SecretKeyPassphraseProvider() {
                    @Override
                    @Nullable
                    public Passphrase getPassphraseFor(@NotNull KeyIdentifier keyIdentifier) {
                        return Passphrase.fromPassword("sw0rdf1sh");
                    }

                    @Override
                    public boolean hasPassphrase(@NotNull KeyIdentifier keyIdentifier) {
                        return false;
                    }
                }
        );

        ByteArrayInputStream bIn = new ByteArrayInputStream(bOut.toByteArray());
        DecryptionStream decIn = api.processMessage()
                .onInputStream(bIn)
                .withOptions(ConsumerOptions.get(api)
                        .setMissingKeyPassphraseStrategy(MissingKeyPassphraseStrategy.INTERACTIVE)
                        .addDecryptionKey(key, protector));

        Streams.drain(decIn);
        decIn.close();
    }
}
