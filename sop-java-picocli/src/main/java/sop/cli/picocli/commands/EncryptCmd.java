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
import sop.cli.picocli.Print;
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
                Print.errln("Unsupported option '--as'.");
                Print.trace(unsupportedOption);
                System.exit(unsupportedOption.getExitCode());
            }
        }

        if (withPassword.isEmpty() && certs.isEmpty()) {
            Print.errln("At least one password or cert file required for encryption.");
            System.exit(19);
        }

        for (String password : withPassword) {
            try {
                encrypt.withPassword(password);
            } catch (SOPGPException.PasswordNotHumanReadable passwordNotHumanReadable) {
                Print.errln("Password is not human-readable.");
                Print.trace(passwordNotHumanReadable);
                System.exit(passwordNotHumanReadable.getExitCode());
            } catch (SOPGPException.UnsupportedOption unsupportedOption) {
                Print.errln("Unsupported option '--with-password'.");
                Print.trace(unsupportedOption);
                System.exit(unsupportedOption.getExitCode());
            }
        }

        for (File keyFile : signWith) {
            try (FileInputStream keyIn = new FileInputStream(keyFile)) {
                encrypt.signWith(keyIn);
            } catch (FileNotFoundException e) {
                Print.errln("Key file " + keyFile.getAbsolutePath() + " not found.");
                Print.trace(e);
                System.exit(1);
            } catch (IOException e) {
                Print.errln("IO Error.");
                Print.trace(e);
                System.exit(1);
            } catch (SOPGPException.KeyIsProtected keyIsProtected) {
                Print.errln("Key from " + keyFile.getAbsolutePath() + " is password protected.");
                Print.trace(keyIsProtected);
                System.exit(1);
            } catch (SOPGPException.UnsupportedAsymmetricAlgo unsupportedAsymmetricAlgo) {
                Print.errln("Key from " + keyFile.getAbsolutePath() + " has unsupported asymmetric algorithm.");
                Print.trace(unsupportedAsymmetricAlgo);
                System.exit(unsupportedAsymmetricAlgo.getExitCode());
            } catch (SOPGPException.CertCannotSign certCannotSign) {
                Print.errln("Key from " + keyFile.getAbsolutePath() + " cannot sign.");
                Print.trace(certCannotSign);
                System.exit(1);
            } catch (SOPGPException.BadData badData) {
                Print.errln("Key file " + keyFile.getAbsolutePath() + " does not contain a valid OpenPGP private key.");
                Print.trace(badData);
                System.exit(badData.getExitCode());
            }
        }

        for (File certFile : certs) {
            try (FileInputStream certIn = new FileInputStream(certFile)) {
                encrypt.withCert(certIn);
            } catch (FileNotFoundException e) {
                Print.errln("Certificate file " + certFile.getAbsolutePath() + " not found.");
                Print.trace(e);
                System.exit(1);
            } catch (IOException e) {
                Print.errln("IO Error.");
                Print.trace(e);
                System.exit(1);
            } catch (SOPGPException.UnsupportedAsymmetricAlgo unsupportedAsymmetricAlgo) {
                Print.errln("Certificate from " + certFile.getAbsolutePath() + " has unsupported asymmetric algorithm.");
                Print.trace(unsupportedAsymmetricAlgo);
                System.exit(unsupportedAsymmetricAlgo.getExitCode());
            } catch (SOPGPException.CertCannotEncrypt certCannotEncrypt) {
                Print.errln("Certificate from " + certFile.getAbsolutePath() + " is not capable of encryption.");
                Print.trace(certCannotEncrypt);
                System.exit(certCannotEncrypt.getExitCode());
            } catch (SOPGPException.BadData badData) {
                Print.errln("Certificate file " + certFile.getAbsolutePath() + " does not contain a valid OpenPGP certificate.");
                Print.trace(badData);
                System.exit(badData.getExitCode());
            }
        }

        if (!armor) {
            encrypt.noArmor();
        }

        try {
            Ready ready = encrypt.plaintext(System.in);
            ready.writeTo(System.out);
        } catch (IOException e) {
            Print.errln("IO Error.");
            Print.trace(e);
            System.exit(1);
        }
    }
}
