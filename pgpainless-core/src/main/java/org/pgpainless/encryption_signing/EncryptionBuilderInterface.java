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
package org.pgpainless.encryption_signing;

import javax.annotation.Nonnull;
import java.io.IOException;
import java.io.OutputStream;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.pgpainless.algorithm.CompressionAlgorithm;
import org.pgpainless.algorithm.HashAlgorithm;
import org.pgpainless.algorithm.SymmetricKeyAlgorithm;
import org.pgpainless.exception.SecretKeyNotFoundException;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.key.selection.keyring.PublicKeyRingSelectionStrategy;
import org.pgpainless.key.selection.keyring.SecretKeyRingSelectionStrategy;
import org.pgpainless.util.MultiMap;

public interface EncryptionBuilderInterface {

    ToRecipients onOutputStream(@Nonnull OutputStream outputStream);

    interface ToRecipients {

        WithAlgorithms toRecipients(@Nonnull PGPPublicKey... keys);

        WithAlgorithms toRecipients(@Nonnull PGPPublicKeyRing... keys);

        WithAlgorithms toRecipients(@Nonnull PGPPublicKeyRingCollection... keys);

        <O> WithAlgorithms toRecipients(@Nonnull PublicKeyRingSelectionStrategy<O> selectionStrategy,
                                       @Nonnull MultiMap<O, PGPPublicKeyRingCollection> keys);

        SignWith doNotEncrypt();

    }

    interface WithAlgorithms {

        WithAlgorithms andToSelf(@Nonnull PGPPublicKey... keys);

        WithAlgorithms andToSelf(@Nonnull PGPPublicKeyRing... keys);

        WithAlgorithms andToSelf(@Nonnull PGPPublicKeyRingCollection keys);

        <O> WithAlgorithms andToSelf(@Nonnull PublicKeyRingSelectionStrategy<O> selectionStrategy,
                                    @Nonnull MultiMap<O, PGPPublicKeyRingCollection> keys);

        SignWith usingAlgorithms(@Nonnull SymmetricKeyAlgorithm symmetricKeyAlgorithm,
                                 @Nonnull HashAlgorithm hashAlgorithm,
                                 @Nonnull CompressionAlgorithm compressionAlgorithm);

        SignWith usingSecureAlgorithms();

    }

    interface SignWith {

        <O> Armor signWith(@Nonnull SecretKeyRingProtector decryptor, @Nonnull PGPSecretKey... keys);

        <O> Armor signWith(@Nonnull SecretKeyRingProtector decryptor, @Nonnull PGPSecretKeyRing... keyRings);

        <O> Armor signWith(@Nonnull SecretKeyRingSelectionStrategy<O> selectionStrategy,
                          @Nonnull SecretKeyRingProtector decryptor,
                          @Nonnull MultiMap<O, PGPSecretKeyRingCollection> keys)
                throws SecretKeyNotFoundException;

        Armor doNotSign();

    }

    interface Armor {

        EncryptionStream asciiArmor() throws IOException, PGPException;

        EncryptionStream noArmor() throws IOException, PGPException;

    }

}
