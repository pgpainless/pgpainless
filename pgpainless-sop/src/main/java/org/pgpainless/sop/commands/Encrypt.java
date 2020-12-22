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

import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor;
import org.bouncycastle.util.io.Streams;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.KeyFlag;
import org.pgpainless.algorithm.SymmetricKeyAlgorithm;
import org.pgpainless.encryption_signing.EncryptionBuilderInterface;
import org.pgpainless.encryption_signing.EncryptionStream;
import org.pgpainless.key.OpenPgpV4Fingerprint;
import org.pgpainless.key.protection.KeyRingProtectionSettings;
import org.pgpainless.key.protection.PassphraseMapKeyRingProtector;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.key.protection.passphrase_provider.SecretKeyPassphraseProvider;
import org.pgpainless.util.Passphrase;
import picocli.CommandLine;

import javax.annotation.Nullable;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;

import static org.pgpainless.sop.Print.err_ln;
import static org.pgpainless.sop.Print.print_ln;

@CommandLine.Command(name = "encrypt",
        description = "Encrypt a message from standard input")
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

        PGPPublicKeyRing[] publicKeys = new PGPPublicKeyRing[certs.length];
        for (int i = 0 ; i < certs.length; i++) {
            try (InputStream fileIn = new FileInputStream(certs[i])) {
                PGPPublicKeyRing publicKey = PGPainless.readKeyRing().publicKeyRing(fileIn);
                publicKeys[i] = publicKey;
            } catch (IOException e) {
                err_ln("Cannot read certificate " + certs[i].getName());
                err_ln(e.getMessage());
                System.exit(1);
            }
        }
        PGPSecretKeyRing[] secretKeys = new PGPSecretKeyRing[signWith.length];
        for (int i = 0; i < signWith.length; i++) {
            try(FileInputStream fileIn = new FileInputStream(signWith[i])) {
                PGPSecretKeyRing secretKey = PGPainless.readKeyRing().secretKeyRing(fileIn);
                secretKeys[i] = secretKey;
            } catch (IOException | PGPException e) {
                err_ln("Cannot read secret key from file " + signWith[i].getName());
                err_ln(e.getMessage());
                System.exit(1);
            }
        }

        Map<Long, Passphrase> passphraseMap = new HashMap<>();
        Scanner scanner = null;
        for (PGPSecretKeyRing ring : secretKeys) {
            for (PGPSecretKey key : ring) {
                // Skip non-signing keys
                PGPSignature signature = (PGPSignature) key.getPublicKey().getSignatures().next();
                int flags = signature.getHashedSubPackets().getKeyFlags();
                if (!key.isSigningKey() || !KeyFlag.hasKeyFlag(flags, KeyFlag.SIGN_DATA)) {
                    // Key cannot sign
                    continue;
                }

                if (key.getKeyEncryptionAlgorithm() == SymmetricKeyAlgorithm.NULL.getAlgorithmId()) {
                    passphraseMap.put(key.getKeyID(), Passphrase.emptyPassphrase());
                } else {
                    print_ln("Please provide the passphrase for key " + new OpenPgpV4Fingerprint(key));
                    if (scanner == null) {
                        scanner = new Scanner(System.in);
                    }
                    String password = scanner.nextLine();
                    Passphrase passphrase = Passphrase.fromPassword(password.trim());
                    passphraseMap.put(key.getKeyID(), passphrase);
                }
            }
        }

        EncryptionBuilderInterface.DetachedSign builder = PGPainless.encryptAndOrSign()
                .onOutputStream(System.out)
                .toRecipients(publicKeys)
                .usingSecureAlgorithms();
        EncryptionBuilderInterface.Armor builder_armor;
        if (signWith.length != 0) {
            EncryptionBuilderInterface.DocumentType documentType = builder.signWith(new PassphraseMapKeyRingProtector(passphraseMap,
                    KeyRingProtectionSettings.secureDefaultSettings(), null), secretKeys);
            if (type == Type.text || type == Type.mime) {
                builder_armor = documentType.signCanonicalText();
            } else {
                builder_armor = documentType.signBinaryDocument();
            }
        } else {
            builder_armor = builder.doNotSign();
        }
        try {
            EncryptionStream encryptionStream = !armor ? builder_armor.noArmor() : builder_armor.asciiArmor();

            Streams.pipeAll(System.in, encryptionStream);

            encryptionStream.close();
        } catch (IOException | PGPException e) {
            err_ln("An error happened.");
            err_ln(e.getMessage());
            System.exit(1);
        }
    }
}
