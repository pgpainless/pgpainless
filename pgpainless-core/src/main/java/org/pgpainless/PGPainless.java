/*
 * Copyright 2018 Paul Schaub.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.pgpainless;

import javax.annotation.Nonnull;
import java.io.IOException;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.pgpainless.algorithm.CompressionAlgorithm;
import org.pgpainless.algorithm.SymmetricKeyAlgorithm;
import org.pgpainless.decryption_verification.DecryptionBuilder;
import org.pgpainless.decryption_verification.DecryptionStream;
import org.pgpainless.encryption_signing.EncryptionBuilder;
import org.pgpainless.encryption_signing.EncryptionStream;
import org.pgpainless.key.generation.KeyRingBuilder;
import org.pgpainless.key.modification.KeyRingEditor;
import org.pgpainless.key.modification.KeyRingEditorInterface;
import org.pgpainless.key.parsing.KeyRingReader;
import org.pgpainless.key.protection.passphrase_provider.SecretKeyPassphraseProvider;
import org.pgpainless.key.protection.passphrase_provider.SolitaryPassphraseProvider;
import org.pgpainless.symmetric_encryption.SymmetricEncryptorDecryptor;
import org.pgpainless.util.Passphrase;

public class PGPainless {

    /**
     * Generate a new OpenPGP key ring.
     * @return builder
     */
    public static KeyRingBuilder generateKeyRing() {
        return new KeyRingBuilder();
    }

    /**
     * Read an existing OpenPGP key ring.
     * @return builder
     */
    public static KeyRingReader readKeyRing() {
        return new KeyRingReader();
    }

    /**
     * Create an {@link EncryptionStream}, which can be used to encrypt and/or sign data using OpenPGP.
     * @return builder
     */
    public static EncryptionBuilder createEncryptor() {
        return new EncryptionBuilder();
    }

    /**
     * Create a {@link DecryptionStream}, which can be used to decrypt and/or verify data using OpenPGP.
     * @return builder
     */
    public static DecryptionBuilder createDecryptor() {
        return new DecryptionBuilder();
    }

    public static KeyRingEditorInterface modifyKeyRing(PGPSecretKeyRing secretKeys) {
        return new KeyRingEditor(secretKeys);
    }

    /**
     * Encrypt some data symmetrically using OpenPGP and a password.
     * The resulting data will be uncompressed and integrity protected.
     *
     * @param data input data.
     * @param password password.
     * @return symmetrically OpenPGP encrypted data.
     * @throws IOException IO is dangerous.
     * @throws PGPException PGP is brittle.
     */
    public static byte[] encryptWithPassword(@Nonnull byte[] data, @Nonnull Passphrase password, @Nonnull SymmetricKeyAlgorithm algorithm) throws IOException, PGPException {
        return SymmetricEncryptorDecryptor.symmetricallyEncrypt(data, password,
                algorithm, CompressionAlgorithm.UNCOMPRESSED);
    }

    /**
     * Decrypt some symmetrically encrypted data using a password.
     * The data is suspected to be integrity protected.
     *
     * @param data symmetrically OpenPGP encrypted data.
     * @param password password.
     * @return decrypted data.
     * @throws IOException IO is dangerous.
     * @throws PGPException PGP is brittle.
     */
    public static byte[] decryptWithPassword(@Nonnull byte[] data, @Nonnull Passphrase password) throws IOException, PGPException {
        return SymmetricEncryptorDecryptor.symmetricallyDecrypt(data, password);
    }
}
