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

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPOnePassSignatureList;
import org.bouncycastle.openpgp.PGPPBEEncryptedData;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.pgpainless.implementation.ImplementationFactory;
import org.pgpainless.util.ArmorUtils;

/**
 * Inspect an OpenPGP message to determine IDs of its encryption keys or whether it is passphrase protected.
 */
public final class MessageInspector {

    public static class EncryptionInfo {
        private final List<Long> keyIds = new ArrayList<>();
        private boolean isPassphraseEncrypted = false;
        private boolean isSignedOnly = false;

        /**
         * Return a list of recipient key ids for whom the message is encrypted.
         * @return recipient key ids
         */
        public List<Long> getKeyIds() {
            return Collections.unmodifiableList(keyIds);
        }

        public boolean isPassphraseEncrypted() {
            return isPassphraseEncrypted;
        }

        /**
         * Return true, if the message is encrypted.
         *
         * @return true if encrypted
         */
        public boolean isEncrypted() {
            return isPassphraseEncrypted || !keyIds.isEmpty();
        }

        /**
         * Return true, if the message is not encrypted, but signed using {@link org.bouncycastle.openpgp.PGPOnePassSignature OnePassSignatures}.
         *
         * @return true if message is signed only
         */
        public boolean isSignedOnly() {
            return isSignedOnly;
        }
    }

    private MessageInspector() {

    }

    /**
     * Parses parts of the provided OpenPGP message in order to determine which keys were used to encrypt it.
     * Note: This method does not rewind the passed in Stream, so you might need to take care of that yourselves.
     *
     * @param dataIn openpgp message
     * @return encryption information
     * @throws IOException
     * @throws PGPException
     */
    public static EncryptionInfo determineEncryptionInfoForMessage(InputStream dataIn) throws IOException, PGPException {
        InputStream decoded = ArmorUtils.getDecoderStream(dataIn);
        EncryptionInfo info = new EncryptionInfo();

        processMessage(decoded, info);

        return info;
    }

    private static void processMessage(InputStream dataIn, EncryptionInfo info) throws PGPException {
        PGPObjectFactory objectFactory = new PGPObjectFactory(dataIn,
                ImplementationFactory.getInstance().getKeyFingerprintCalculator());

        for (Object next : objectFactory) {
            if (next instanceof PGPOnePassSignatureList) {
                PGPOnePassSignatureList signatures = (PGPOnePassSignatureList) next;
                if (!signatures.isEmpty()) {
                    info.isSignedOnly = true;
                    return;
                }
            }

            if (next instanceof PGPEncryptedDataList) {
                PGPEncryptedDataList encryptedDataList = (PGPEncryptedDataList) next;
                for (PGPEncryptedData encryptedData : encryptedDataList) {
                    if (encryptedData instanceof PGPPublicKeyEncryptedData) {
                        PGPPublicKeyEncryptedData pubKeyEncryptedData = (PGPPublicKeyEncryptedData) encryptedData;
                        info.keyIds.add(pubKeyEncryptedData.getKeyID());
                    } else if (encryptedData instanceof PGPPBEEncryptedData) {
                        info.isPassphraseEncrypted = true;
                    }
                }
            }

            if (next instanceof PGPCompressedData) {
                PGPCompressedData compressed = (PGPCompressedData) next;
                InputStream decompressed = compressed.getDataStream();
                processMessage(decompressed, info);
            }

            if (next instanceof PGPLiteralData) {
                return;
            }
        }
    }
}
