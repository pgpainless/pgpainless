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
package org.pgpainless.pgpainless.encryption_signing;

import java.io.IOException;
import java.io.OutputStream;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.pgpainless.pgpainless.exception.SecretKeyNotFoundException;
import org.pgpainless.pgpainless.algorithm.CompressionAlgorithm;
import org.pgpainless.pgpainless.algorithm.HashAlgorithm;
import org.pgpainless.pgpainless.algorithm.SymmetricKeyAlgorithm;
import org.pgpainless.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.pgpainless.key.selection.keyring.PublicKeyRingSelectionStrategy;
import org.pgpainless.pgpainless.key.selection.keyring.SecretKeyRingSelectionStrategy;
import org.pgpainless.pgpainless.util.MultiMap;

public interface EncryptionBuilderInterface {

    ToRecipients onOutputStream(OutputStream outputStream);

    interface ToRecipients {

        WithAlgorithms toRecipients(PGPPublicKey... keys);

        WithAlgorithms toRecipients(PGPPublicKeyRing... keys);

        WithAlgorithms toRecipients(PGPPublicKeyRingCollection... keys);

        <O> WithAlgorithms toRecipients(PublicKeyRingSelectionStrategy<O> selectionStrategy,
                                       MultiMap<O, PGPPublicKeyRingCollection> keys);

        SignWith doNotEncrypt();

    }

    interface WithAlgorithms {

        WithAlgorithms andToSelf(PGPPublicKey... keys);

        WithAlgorithms andToSelf(PGPPublicKeyRing... keys);

        WithAlgorithms andToSelf(PGPPublicKeyRingCollection keys);

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

        EncryptionStream asciiArmor() throws IOException, PGPException;

        EncryptionStream noArmor() throws IOException, PGPException;

    }

}
