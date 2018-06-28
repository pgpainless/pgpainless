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
package org.pgpainless.pgpainless;

import java.io.ByteArrayInputStream;
import java.io.IOException;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.pgpainless.pgpainless.algorithm.CompressionAlgorithm;
import org.pgpainless.pgpainless.algorithm.SymmetricKeyAlgorithm;
import org.pgpainless.pgpainless.decryption_verification.DecryptionBuilder;
import org.pgpainless.pgpainless.encryption_signing.EncryptionBuilder;
import org.pgpainless.pgpainless.key.generation.KeyRingBuilder;
import org.pgpainless.pgpainless.symmetric_encryption.SymmetricEncryptorDecryptor;

public class PGPainless {

    public static KeyRingBuilder generateKeyRing() {
        return new KeyRingBuilder();
    }

    public static EncryptionBuilder createEncryptor() {
        return new EncryptionBuilder();
    }

    public static DecryptionBuilder createDecryptor() {
        return new DecryptionBuilder();
    }

    public static PGPPublicKeyRing publicKeyRingFromBytes(byte[] bytes) throws IOException {
        return new PGPPublicKeyRing(new ArmoredInputStream(new ByteArrayInputStream(bytes)), new BcKeyFingerprintCalculator());
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
    public static byte[] encryptWithPassword(byte[] data, char[] password, SymmetricKeyAlgorithm algorithm) throws IOException, PGPException {
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
    public static byte[] decryptWithPassword(byte[] data, char[] password) throws IOException, PGPException {
        return SymmetricEncryptorDecryptor.symmetricallyDecrypt(data, password);
    }
}
