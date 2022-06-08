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
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.util.io.Streams;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.DocumentSignatureType;
import org.pgpainless.encryption_signing.EncryptionResult;
import org.pgpainless.encryption_signing.EncryptionStream;
import org.pgpainless.encryption_signing.ProducerOptions;
import org.pgpainless.encryption_signing.SigningOptions;
import org.pgpainless.exception.KeyException;
import org.pgpainless.key.SubkeyIdentifier;
import org.pgpainless.util.Passphrase;
import sop.MicAlg;
import sop.ReadyWithResult;
import sop.SigningResult;
import sop.enums.InlineSignAs;
import sop.exception.SOPGPException;
import sop.operation.InlineSign;

public class InlineSignImpl implements InlineSign {

    private boolean armor = true;
    private InlineSignAs mode = InlineSignAs.Binary;
    private final SigningOptions signingOptions = new SigningOptions();
    private final MatchMakingSecretKeyRingProtector protector = new MatchMakingSecretKeyRingProtector();

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
    public InlineSign key(InputStream keyIn) throws SOPGPException.KeyIsProtected, SOPGPException.BadData, IOException {
        try {
            PGPSecretKeyRingCollection keys = PGPainless.readKeyRing().secretKeyRingCollection(keyIn);

            for (PGPSecretKeyRing key : keys) {
                protector.addSecretKey(key);
                if (mode == InlineSignAs.CleartextSigned) {
                    signingOptions.addDetachedSignature(protector, key, DocumentSignatureType.BINARY_DOCUMENT);
                } else {
                    signingOptions.addInlineSignature(protector, key, modeToSigType(mode));
                }
            }
        } catch (PGPException | KeyException e) {
            throw new SOPGPException.BadData(e);
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
    public ReadyWithResult<SigningResult> data(InputStream data) throws IOException, SOPGPException.ExpectedText {

        ProducerOptions producerOptions = ProducerOptions.sign(signingOptions);
        if (mode == InlineSignAs.CleartextSigned) {
            producerOptions.setCleartextSigned();
            producerOptions.setAsciiArmor(true);
        } else {
            producerOptions.setAsciiArmor(armor);
        }

        return new ReadyWithResult<SigningResult>() {
            @Override
            public SigningResult writeTo(OutputStream outputStream) throws IOException, SOPGPException.NoSignature {
                try {
                    EncryptionStream signingStream = PGPainless.encryptAndOrSign()
                            .onOutputStream(outputStream)
                            .withOptions(producerOptions);

                    if (signingStream.isClosed()) {
                        throw new IllegalStateException("EncryptionStream is already closed.");
                    }

                    Streams.pipeAll(data, signingStream);
                    signingStream.close();
                    EncryptionResult encryptionResult = signingStream.getResult();

                    // forget passphrases
                    protector.clear();

                    List<PGPSignature> signatures = new ArrayList<>();
                    for (SubkeyIdentifier key : encryptionResult.getDetachedSignatures().keySet()) {
                        signatures.addAll(encryptionResult.getDetachedSignatures().get(key));
                    }

                    return SigningResult.builder()
                            .setMicAlg(micAlgFromSignatures(signatures))
                            .build();
                } catch (PGPException e) {
                    throw new RuntimeException(e);
                }
            }
        };
    }

    private MicAlg micAlgFromSignatures(Iterable<PGPSignature> signatures) {
        int algorithmId = 0;
        for (PGPSignature signature : signatures) {
            int sigAlg = signature.getHashAlgorithm();
            if (algorithmId == 0 || algorithmId == sigAlg) {
                algorithmId = sigAlg;
            } else {
                return MicAlg.empty();
            }
        }
        return algorithmId == 0 ? MicAlg.empty() : MicAlg.fromHashAlgorithmId(algorithmId);
    }

    private static DocumentSignatureType modeToSigType(InlineSignAs mode) {
        return mode == InlineSignAs.Binary ? DocumentSignatureType.BINARY_DOCUMENT
                : DocumentSignatureType.CANONICAL_TEXT_DOCUMENT;
    }
}
