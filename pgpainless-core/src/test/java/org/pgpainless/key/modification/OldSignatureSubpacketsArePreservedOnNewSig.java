/*
 * Copyright 2021 Paul Schaub.
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
package org.pgpainless.key.modification;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.Date;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureSubpacketVector;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.pgpainless.PGPainless;
import org.pgpainless.implementation.ImplementationFactory;
import org.pgpainless.key.OpenPgpV4Fingerprint;
import org.pgpainless.key.protection.UnprotectedKeysProtector;

public class OldSignatureSubpacketsArePreservedOnNewSig {

    @ParameterizedTest
    @MethodSource("org.pgpainless.util.TestUtil#provideImplementationFactories")
    public void verifyOldSignatureSubpacketsArePreservedOnNewExpirationDateSig(ImplementationFactory implementationFactory)
            throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, PGPException, InterruptedException, IOException {
        ImplementationFactory.setFactoryImplementation(implementationFactory);
        PGPSecretKeyRing secretKeys = PGPainless.generateKeyRing()
                .simpleEcKeyRing("Alice <alice@wonderland.lit>");

        OpenPgpV4Fingerprint subkeyFingerprint = new OpenPgpV4Fingerprint(PGPainless.inspectKeyRing(secretKeys).getPublicKeys().get(1));

        PGPSignature oldSignature = PGPainless.inspectKeyRing(secretKeys).getCurrentSubkeyBindingSignature(subkeyFingerprint.getKeyId());
        PGPSignatureSubpacketVector oldPackets = oldSignature.getHashedSubPackets();

        assertEquals(0, oldPackets.getKeyExpirationTime());

        Thread.sleep(1000);
        secretKeys = PGPainless.modifyKeyRing(secretKeys)
                .setExpirationDate(subkeyFingerprint, new Date(), new UnprotectedKeysProtector())
                .done();
        PGPSignature newSignature = PGPainless.inspectKeyRing(secretKeys).getCurrentSubkeyBindingSignature(subkeyFingerprint.getKeyId());
        PGPSignatureSubpacketVector newPackets = newSignature.getHashedSubPackets();

        assertNotEquals(0, newPackets.getKeyExpirationTime());

        assertArrayEquals(oldPackets.getPreferredHashAlgorithms(), newPackets.getPreferredHashAlgorithms());
    }
}
