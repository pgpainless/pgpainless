// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.sop;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.util.io.Streams;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.DocumentSignatureType;
import org.pgpainless.encryption_signing.EncryptionStream;
import org.pgpainless.encryption_signing.ProducerOptions;
import org.pgpainless.encryption_signing.SigningOptions;
import org.pgpainless.exception.KeyException;
import org.pgpainless.key.OpenPgpFingerprint;
import org.pgpainless.key.info.KeyRingInfo;
import org.pgpainless.util.Passphrase;
import sop.Ready;
import sop.enums.InlineSignAs;
import sop.exception.SOPGPException;
import sop.operation.InlineSign;

public class InlineSignImpl implements InlineSign {

    private boolean armor = true;
    private InlineSignAs mode = InlineSignAs.binary;
    private final SigningOptions signingOptions = new SigningOptions();
    private final MatchMakingSecretKeyRingProtector protector = new MatchMakingSecretKeyRingProtector();
    private final List<PGPSecretKeyRing> signingKeys = new ArrayList<>();

    @Override
    public InlineSign mode(InlineSignAs mode) throws SOPGPException.UnsupportedOption {
        this.mode = mode;
        return this;
    }

    @Override
    public InlineSign noArmor() {
        this.armor = false;
        return this;
    }

    @Override
    public InlineSign key(InputStream keyIn) throws SOPGPException.KeyCannotSign, SOPGPException.BadData, IOException {
        PGPSecretKeyRingCollection keys = KeyReader.readSecretKeys(keyIn, true);
        for (PGPSecretKeyRing key : keys) {
            KeyRingInfo info = PGPainless.inspectKeyRing(key);
            if (!info.isUsableForSigning()) {
                throw new SOPGPException.KeyCannotSign("Key " + info.getFingerprint() + " does not have valid, signing capable subkeys.");
            }
            protector.addSecretKey(key);
            signingKeys.add(key);
        }
        return this;
    }

    @Override
    public InlineSign withKeyPassword(byte[] password) {
        String string = new String(password, Charset.forName("UTF8"));
        protector.addPassphrase(Passphrase.fromPassword(string));
        return this;
    }

    @Override
    public Ready data(InputStream data) throws SOPGPException.KeyIsProtected, SOPGPException.ExpectedText {
        for (PGPSecretKeyRing key : signingKeys) {
            try {
                if (mode == InlineSignAs.clearsigned) {
                    signingOptions.addDetachedSignature(protector, key, DocumentSignatureType.CANONICAL_TEXT_DOCUMENT);
                } else {
                    signingOptions.addInlineSignature(protector, key, modeToSigType(mode));
                }
            } catch (KeyException.UnacceptableSigningKeyException | KeyException.MissingSecretKeyException e) {
                throw new SOPGPException.KeyCannotSign("Key " + OpenPgpFingerprint.of(key) + " cannot sign.", e);
            } catch (PGPException e) {
                throw new SOPGPException.KeyIsProtected("Key " + OpenPgpFingerprint.of(key) + " cannot be unlocked.", e);
            }
        }

        ProducerOptions producerOptions = ProducerOptions.sign(signingOptions);
        if (mode == InlineSignAs.clearsigned) {
            producerOptions.setCleartextSigned();
            producerOptions.setAsciiArmor(true);
        } else {
            producerOptions.setAsciiArmor(armor);
        }

        return new Ready() {
            @Override
            public void writeTo(OutputStream outputStream) throws IOException, SOPGPException.NoSignature {
                try {
                    EncryptionStream signingStream = PGPainless.encryptAndOrSign()
                            .onOutputStream(outputStream)
                            .withOptions(producerOptions);

                    if (signingStream.isClosed()) {
                        throw new IllegalStateException("EncryptionStream is already closed.");
                    }

                    Streams.pipeAll(data, signingStream);
                    signingStream.close();

                    // forget passphrases
                    protector.clear();
                } catch (PGPException e) {
                    throw new RuntimeException(e);
                }
            }
        };
    }

    private static DocumentSignatureType modeToSigType(InlineSignAs mode) {
        return mode == InlineSignAs.binary ? DocumentSignatureType.BINARY_DOCUMENT
                : DocumentSignatureType.CANONICAL_TEXT_DOCUMENT;
    }
}
