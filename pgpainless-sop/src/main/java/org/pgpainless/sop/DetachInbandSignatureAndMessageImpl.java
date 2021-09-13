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
package org.pgpainless.sop;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.pgpainless.exception.WrongConsumingMethodException;
import org.pgpainless.decryption_verification.cleartext_signatures.ClearsignedMessageUtil;
import org.pgpainless.util.ArmoredOutputStreamFactory;
import sop.ReadyWithResult;
import sop.Signatures;
import sop.exception.SOPGPException;
import sop.operation.DetachInbandSignatureAndMessage;

public class DetachInbandSignatureAndMessageImpl implements DetachInbandSignatureAndMessage {

    private boolean armor = true;

    @Override
    public DetachInbandSignatureAndMessage noArmor() {
        this.armor = false;
        return this;
    }

    @Override
    public ReadyWithResult<Signatures> message(InputStream messageInputStream) {

        return new ReadyWithResult<Signatures>() {
            @Override
            public Signatures writeTo(OutputStream messageOutputStream) throws SOPGPException.NoSignature {

                return new Signatures() {
                    @Override
                    public void writeTo(OutputStream signatureOutputStream) throws IOException {
                        PGPSignatureList signatures = null;
                        try {
                            signatures = ClearsignedMessageUtil.detachSignaturesFromInbandClearsignedMessage(messageInputStream, messageOutputStream);
                        } catch (WrongConsumingMethodException e) {
                            throw new IOException(e);
                        }
                        if (armor) {
                            ArmoredOutputStream armorOut = ArmoredOutputStreamFactory.get(signatureOutputStream);
                            for (PGPSignature signature : signatures) {
                                signature.encode(armorOut);
                            }
                            armorOut.close();
                        } else {
                            for (PGPSignature signature : signatures) {
                                signature.encode(signatureOutputStream);
                            }
                        }
                    }
                };
            }
        };
    }
}
