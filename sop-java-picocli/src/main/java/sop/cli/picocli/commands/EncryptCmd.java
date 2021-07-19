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
package sop.cli.picocli.commands;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import picocli.CommandLine;
import sop.Ready;
import sop.cli.picocli.SopCLI;
import sop.enums.EncryptAs;
import sop.exception.SOPGPException;
import sop.operation.Encrypt;

@CommandLine.Command(name = "encrypt",
        description = "Encrypt a message from standard input",
        exitCodeOnInvalidInput = 37)
public class EncryptCmd implements Runnable {

    @CommandLine.Option(names = "--no-armor",
            description = "ASCII armor the output",
            negatable = true)
    boolean armor = true;

    @CommandLine.Option(names = {"--as"},
            description = "Type of the input data. Defaults to 'binary'",
            paramLabel = "{binary|text|mime}")
    EncryptAs type;

    @CommandLine.Option(names = "--with-password",
            description = "Encrypt the message with a password",
            paramLabel = "PASSWORD")
    List<String> withPassword = new ArrayList<>();

    @CommandLine.Option(names = "--sign-with",
            description = "Sign the output with a private key",
            paramLabel = "KEY")
    List<File> signWith = new ArrayList<>();

    @CommandLine.Parameters(description = "Certificates the message gets encrypted to",
            index = "0..*",
            paramLabel = "CERTS")
    List<File> certs = new ArrayList<>();

    @Override
    public void run() {
        Encrypt encrypt = SopCLI.getSop().encrypt();
        if (type != null) {
            try {
                encrypt.mode(type);
            } catch (SOPGPException.UnsupportedOption unsupportedOption) {
                throw new SOPGPException.UnsupportedOption("Unsupported option '--as'.", unsupportedOption);
            }
        }

        if (withPassword.isEmpty() && certs.isEmpty()) {
            throw new SOPGPException.MissingArg("At least one password or cert file required for encryption.");
        }

        for (String password : withPassword) {
            try {
                encrypt.withPassword(password);
            } catch (SOPGPException.UnsupportedOption unsupportedOption) {
                throw new SOPGPException.UnsupportedOption("Unsupported option '--with-password'.", unsupportedOption);
            }
        }

        for (File keyFile : signWith) {
            try (FileInputStream keyIn = new FileInputStream(keyFile)) {
                encrypt.signWith(keyIn);
            } catch (FileNotFoundException e) {
                throw new SOPGPException.MissingInput("Key file " + keyFile.getAbsolutePath() + " not found.", e);
            } catch (IOException e) {
                throw new RuntimeException(e);
            } catch (SOPGPException.KeyIsProtected keyIsProtected) {
                throw new SOPGPException.KeyIsProtected("Key from " + keyFile.getAbsolutePath() + " is password protected.", keyIsProtected);
            } catch (SOPGPException.UnsupportedAsymmetricAlgo unsupportedAsymmetricAlgo) {
                throw new SOPGPException.UnsupportedAsymmetricAlgo("Key from " + keyFile.getAbsolutePath() + " has unsupported asymmetric algorithm.", unsupportedAsymmetricAlgo);
            } catch (SOPGPException.CertCannotSign certCannotSign) {
                throw new RuntimeException("Key from " + keyFile.getAbsolutePath() + " cannot sign.", certCannotSign);
            } catch (SOPGPException.BadData badData) {
                throw new SOPGPException.BadData("Key file " + keyFile.getAbsolutePath() + " does not contain a valid OpenPGP private key.", badData);
            }
        }

        for (File certFile : certs) {
            try (FileInputStream certIn = new FileInputStream(certFile)) {
                encrypt.withCert(certIn);
            } catch (FileNotFoundException e) {
                throw new SOPGPException.MissingInput("Certificate file " + certFile.getAbsolutePath() + " not found.", e);
            } catch (IOException e) {
                throw new RuntimeException(e);
            } catch (SOPGPException.UnsupportedAsymmetricAlgo unsupportedAsymmetricAlgo) {
                throw new SOPGPException.UnsupportedAsymmetricAlgo("Certificate from " + certFile.getAbsolutePath() + " has unsupported asymmetric algorithm.", unsupportedAsymmetricAlgo);
            } catch (SOPGPException.CertCannotEncrypt certCannotEncrypt) {
                throw new SOPGPException.CertCannotEncrypt("Certificate from " + certFile.getAbsolutePath() + " is not capable of encryption.", certCannotEncrypt);
            } catch (SOPGPException.BadData badData) {
                throw new SOPGPException.BadData("Certificate file " + certFile.getAbsolutePath() + " does not contain a valid OpenPGP certificate.", badData);
            }
        }

        if (!armor) {
            encrypt.noArmor();
        }

        try {
            Ready ready = encrypt.plaintext(System.in);
            ready.writeTo(System.out);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
