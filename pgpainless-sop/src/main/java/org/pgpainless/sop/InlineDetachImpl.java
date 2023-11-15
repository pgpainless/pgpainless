// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.sop;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPOnePassSignatureList;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.util.io.Streams;
import org.pgpainless.decryption_verification.OpenPgpInputStream;
import org.pgpainless.decryption_verification.cleartext_signatures.ClearsignedMessageUtil;
import org.pgpainless.exception.WrongConsumingMethodException;
import org.pgpainless.implementation.ImplementationFactory;
import org.pgpainless.util.ArmoredOutputStreamFactory;
import sop.ReadyWithResult;
import sop.Signatures;
import sop.exception.SOPGPException;
import sop.operation.InlineDetach;

import javax.annotation.Nonnull;

/**
 * Implementation of the <pre>inline-detach</pre> operation using PGPainless.
 */
public class InlineDetachImpl implements InlineDetach {

    private boolean armor = true;

    @Override
    @Nonnull
    public InlineDetach noArmor() {
        this.armor = false;
        return this;
    }

    @Override
    @Nonnull
    public ReadyWithResult<Signatures> message(@Nonnull InputStream messageInputStream) {

        return new ReadyWithResult<Signatures>() {

            private final ByteArrayOutputStream sigOut = new ByteArrayOutputStream();

            @Override
            public Signatures writeTo(@Nonnull OutputStream messageOutputStream)
                    throws SOPGPException.NoSignature, IOException {

                PGPSignatureList signatures = null;
                OpenPgpInputStream pgpIn = new OpenPgpInputStream(messageInputStream);

                if (pgpIn.isNonOpenPgp()) {
                    throw new SOPGPException.BadData("Data appears to be non-OpenPGP.");
                }

                // handle ASCII armor
                if (pgpIn.isAsciiArmored()) {
                    ArmoredInputStream armorIn = new ArmoredInputStream(pgpIn);

                    // Handle cleartext signature framework
                    if (armorIn.isClearText()) {
                        try {
                            signatures = ClearsignedMessageUtil.detachSignaturesFromInbandClearsignedMessage(armorIn, messageOutputStream);
                            if (signatures.isEmpty()) {
                                throw new SOPGPException.BadData("Data did not contain OpenPGP signatures.");
                            }
                        } catch (WrongConsumingMethodException e) {
                            throw new SOPGPException.BadData(e);
                        }
                    }
                    // else just dearmor
                    pgpIn = new OpenPgpInputStream(armorIn);
                }

                // if data was not using cleartext signatures framework
                if (signatures == null) {

                    if (!pgpIn.isBinaryOpenPgp()) {
                        throw new SOPGPException.BadData("Data was containing ASCII armored non-OpenPGP data.");
                    }

                    // handle binary OpenPGP data
                    PGPObjectFactory objectFactory = ImplementationFactory.getInstance().getPGPObjectFactory(pgpIn);
                    Object next;
                    while ((next = objectFactory.nextObject()) != null) {

                        if (next instanceof PGPOnePassSignatureList) {
                            // skip over ops
                            continue;
                        }

                        if (next instanceof PGPLiteralData) {
                            // write out contents of literal data packet
                            PGPLiteralData literalData = (PGPLiteralData) next;
                            InputStream literalIn = literalData.getDataStream();
                            Streams.pipeAll(literalIn, messageOutputStream);
                            literalIn.close();
                            continue;
                        }

                        if (next instanceof PGPCompressedData) {
                            // decompress compressed data
                            PGPCompressedData compressedData = (PGPCompressedData) next;
                            try {
                                objectFactory = ImplementationFactory.getInstance().getPGPObjectFactory(compressedData.getDataStream());
                            } catch (PGPException e) {
                                throw new SOPGPException.BadData("Cannot decompress PGPCompressedData", e);
                            }
                            continue;
                        }

                        if (next instanceof PGPSignatureList) {
                            signatures = (PGPSignatureList) next;
                        }
                    }
                }

                if (signatures == null) {
                    throw new SOPGPException.BadData("Data did not contain OpenPGP signatures.");
                }

                // write out signatures
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
                    public void writeTo(@Nonnull OutputStream signatureOutputStream) throws IOException {
                        Streams.pipeAll(new ByteArrayInputStream(sigOut.toByteArray()), signatureOutputStream);
                    }
                };
            }
        };
    }
}
