/*
 * Copyright 2020 Paul Schaub.
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
package org.pgpainless.sop.commands;

import static org.pgpainless.sop.Print.err_ln;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.List;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.util.io.Streams;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.DocumentSignatureType;
import org.pgpainless.encryption_signing.EncryptionOptions;
import org.pgpainless.encryption_signing.EncryptionStream;
import org.pgpainless.encryption_signing.ProducerOptions;
import org.pgpainless.encryption_signing.SigningOptions;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.sop.SopKeyUtil;
import org.pgpainless.util.Passphrase;
import picocli.CommandLine;

@CommandLine.Command(name = "encrypt",
        description = "Encrypt a message from standard input",
        exitCodeOnInvalidInput = 37)
public class Encrypt implements Runnable {

    public enum Type {
        binary,
        text,
        mime
    }

    @CommandLine.Option(names = "--no-armor",
            description = "ASCII armor the output",
            negatable = true)
    boolean armor = true;

    @CommandLine.Option(names = {"--as"},
            description = "Type of the input data. Defaults to 'binary'",
            paramLabel = "{binary|text|mime}")
    Type type;

    @CommandLine.Option(names = "--with-password",
            description = "Encrypt the message with a password",
            paramLabel = "PASSWORD")
    String[] withPassword = new String[0];

    @CommandLine.Option(names = "--sign-with",
            description = "Sign the output with a private key",
            paramLabel = "KEY")
    File[] signWith = new File[0];

    @CommandLine.Parameters(description = "Certificates the message gets encrypted to",
            index = "0..*",
            paramLabel = "CERTS")
    File[] certs = new File[0];

    @Override
    public void run() {
        if (certs.length == 0 && withPassword.length == 0) {
            err_ln("Please either provide --with-password or at least one CERT");
            System.exit(19);
        }

        EncryptionOptions encOpt = new EncryptionOptions();
        SigningOptions signOpt = new SigningOptions();

        try {
            List<PGPPublicKeyRing> encryptionKeys = SopKeyUtil.loadCertificatesFromFile(certs);
            for (PGPPublicKeyRing key : encryptionKeys) {
                encOpt.addRecipient(key);
            }
        } catch (IOException e) {
            err_ln(e.getMessage());
            System.exit(1);
            return;
        }

        for (String s : withPassword) {
            Passphrase passphrase = Passphrase.fromPassword(s);
            encOpt.addPassphrase(passphrase);
        }

        SecretKeyRingProtector protector = SecretKeyRingProtector.unprotectedKeys();

        for (int i = 0; i < signWith.length; i++) {
            try (FileInputStream fileIn = new FileInputStream(signWith[i])) {
                PGPSecretKeyRing secretKey = PGPainless.readKeyRing().secretKeyRing(fileIn);
                signOpt.addInlineSignature(protector, secretKey, parseType(type));
            } catch (IOException | PGPException e) {
                err_ln("Cannot read secret key from file " + signWith[i].getName());
                err_ln(e.getMessage());
                System.exit(1);
            }
        }

        try {
        EncryptionStream encryptionStream = PGPainless.encryptAndOrSign()
                .onOutputStream(System.out)
                .withOptions(ProducerOptions
                        .signAndEncrypt(encOpt, signOpt)
                        .setAsciiArmor(armor));

            Streams.pipeAll(System.in, encryptionStream);

            encryptionStream.close();
        } catch (IOException | PGPException e) {
            err_ln("An error happened.");
            err_ln(e.getMessage());
            System.exit(1);
        }
    }

    private static DocumentSignatureType parseType(Type type) {
        return type == Type.binary ? DocumentSignatureType.BINARY_DOCUMENT : DocumentSignatureType.CANONICAL_TEXT_DOCUMENT;
    }
}
