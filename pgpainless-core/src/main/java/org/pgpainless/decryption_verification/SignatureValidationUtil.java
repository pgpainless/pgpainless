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
package org.pgpainless.decryption_verification;

import java.util.Date;

import org.bouncycastle.bcpg.sig.NotationData;
import org.bouncycastle.openpgp.PGPDataValidationException;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureSubpacketVector;
import org.pgpainless.algorithm.SignatureSubpacket;
import org.pgpainless.util.NotationRegistry;

/**
 * Utility class that implements validation of signatures.
 */
public class SignatureValidationUtil {

    public static void validate(PGPSignature signature) throws PGPException {
        validateHashedAreaHasSignatureCreationTime(signature);
        validateSignatureCreationTimeIsNotInUnhashedArea(signature);
        validateSignatureDoesNotContainCriticalUnknownSubpackets(signature);
        validateSignatureDoesNotContainCriticalUnknownNotations(signature);
    }

    public static void validateHashedAreaHasSignatureCreationTime(PGPSignature signature) throws PGPDataValidationException {
        PGPSignatureSubpacketVector hashedSubpackets = signature.getHashedSubPackets();
        if (hashedSubpackets.getSignatureCreationTime() == null) {
            throw new PGPDataValidationException("Hashed area of the signature MUST carry signature creation time subpacket.");
        }
    }

    public static void validateSignatureCreationTimeIsNotInUnhashedArea(PGPSignature signature) throws PGPDataValidationException {
        PGPSignatureSubpacketVector unhashedSubpackets = signature.getUnhashedSubPackets();
        Date unhashedCreationTime = unhashedSubpackets.getSignatureCreationTime();
        if (unhashedCreationTime == null) {
            return;
        }
        throw new PGPDataValidationException("Signature creation time MUST be in hashed area of the signature.");
    }

    public static void validateSignatureDoesNotContainCriticalUnknownSubpackets(PGPSignature signature) throws PGPDataValidationException {
        try {
            throwIfContainsCriticalUnknownSubpacket(signature.getHashedSubPackets());
        } catch (PGPDataValidationException e) {
            throw new PGPDataValidationException("Signature has unknown critical subpacket in hashed area.\n" + e.getMessage());
        }
        try {
            throwIfContainsCriticalUnknownSubpacket(signature.getHashedSubPackets());
        } catch (PGPDataValidationException e) {
            throw new PGPDataValidationException("Signature has unknown critical subpacket in unhashed area.\n" + e.getMessage());
        }
    }

    private static void throwIfContainsCriticalUnknownSubpacket(PGPSignatureSubpacketVector subpacketVector) throws PGPDataValidationException {
        for (int critical : subpacketVector.getCriticalTags()) {
            try {
                SignatureSubpacket.fromCode(critical);
            } catch (IllegalArgumentException e) {
                throw new PGPDataValidationException("Unknown critical signature subpacket: " + Long.toHexString(critical));
            }
        }
    }

    public static void validateSignatureDoesNotContainCriticalUnknownNotations(PGPSignature signature) throws PGPDataValidationException {
        PGPSignatureSubpacketVector hashedSubpackets = signature.getHashedSubPackets();
        try {
            throwIfSubpacketsContainCriticalUnknownNotation(hashedSubpackets);
        } catch (PGPDataValidationException e) {
            throw new PGPDataValidationException("Signature contains unknown critical notation in hashed area:\n" + e.getMessage());
        }
        PGPSignatureSubpacketVector unhashedSubpackets = signature.getUnhashedSubPackets();
        try {
            throwIfSubpacketsContainCriticalUnknownNotation(unhashedSubpackets);
        } catch (PGPDataValidationException e) {
            throw new PGPDataValidationException("Signature contains unknown critical notation in unhashed area:\n" + e.getMessage());
        }
    }

    private static void throwIfSubpacketsContainCriticalUnknownNotation(PGPSignatureSubpacketVector subpacketVector) throws PGPDataValidationException {
        for (NotationData notation : subpacketVector.getNotationDataOccurrences()) {
            if (notation.isCritical() && !NotationRegistry.getInstance().isKnownNotation(notation.getNotationName())) {
                throw new PGPDataValidationException("Critical unknown notation encountered: " + notation.getNotationName());
            }
        }
    }
}
