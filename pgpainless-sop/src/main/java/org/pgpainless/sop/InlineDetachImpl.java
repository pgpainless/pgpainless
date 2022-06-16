// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.sop;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.util.io.Streams;
import org.pgpainless.decryption_verification.cleartext_signatures.ClearsignedMessageUtil;
import org.pgpainless.exception.WrongConsumingMethodException;
import org.pgpainless.util.ArmoredOutputStreamFactory;
import sop.ReadyWithResult;
import sop.Signatures;
import sop.exception.SOPGPException;
import sop.operation.InlineDetach;

public class InlineDetachImpl implements InlineDetach {

    private boolean armor = true;

    @Override
    public InlineDetach noArmor() {
        this.armor = false;
        return this;
    }

    @Override
    public ReadyWithResult<Signatures> message(InputStream messageInputStream) {

        return new ReadyWithResult<Signatures>() {

            private final ByteArrayOutputStream sigOut = new ByteArrayOutputStream();

            @Override
            public Signatures writeTo(OutputStream messageOutputStream)
                    throws SOPGPException.NoSignature, IOException {

                PGPSignatureList signatures;
                try {
                    signatures = ClearsignedMessageUtil.detachSignaturesFromInbandClearsignedMessage(messageInputStream, messageOutputStream);
                } catch (WrongConsumingMethodException e) {
                    throw new IOException(e);
                }

                if (armor) {
                    ArmoredOutputStream armorOut = ArmoredOutputStreamFactory.get(sigOut);
                    for (PGPSignature signature : signatures) {
                        signature.encode(armorOut);
                    }
                    armorOut.close();
                } else {
                    for (PGPSignature signature : signatures) {
                        signature.encode(sigOut);
                    }
                }

                return new Signatures() {
                    @Override
                    public void writeTo(OutputStream signatureOutputStream) throws IOException {
                        Streams.pipeAll(new ByteArrayInputStream(sigOut.toByteArray()), signatureOutputStream);
                    }
                };
            }
        };
    }
}
