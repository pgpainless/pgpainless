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
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.regex.Pattern;

import picocli.CommandLine;
import sop.DecryptionResult;
import sop.ReadyWithResult;
import sop.SessionKey;
import sop.Verification;
import sop.cli.picocli.DateParser;
import sop.cli.picocli.SopCLI;
import sop.exception.SOPGPException;
import sop.operation.Decrypt;
import sop.util.HexUtil;

@CommandLine.Command(name = "decrypt",
        description = "Decrypt a message from standard input",
        exitCodeOnInvalidInput = SOPGPException.UnsupportedOption.EXIT_CODE)
public class DecryptCmd implements Runnable {

    @CommandLine.Option(
            names = {"--session-key-out"},
            description = "Can be used to learn the session key on successful decryption",
            paramLabel = "SESSIONKEY")
    File sessionKeyOut;

    @CommandLine.Option(
            names = {"--with-session-key"},
            description = "Enables decryption of the \"CIPHERTEXT\" using the session key directly against the \"SEIPD\" packet",
            paramLabel = "SESSIONKEY")
    List<String> withSessionKey = new ArrayList<>();

    @CommandLine.Option(
            names = {"--with-password"},
            description = "Enables decryption based on any \"SKESK\" packets in the \"CIPHERTEXT\"",
            paramLabel = "PASSWORD")
    List<String> withPassword = new ArrayList<>();

    @CommandLine.Option(names = {"--verify-out"},
            description = "Produces signature verification status to the designated file",
            paramLabel = "VERIFICATIONS")
    File verifyOut;

    @CommandLine.Option(names = {"--verify-with"},
            description = "Certificates whose signatures would be acceptable for signatures over this message",
            paramLabel = "CERT")
    List<File> certs = new ArrayList<>();

    @CommandLine.Option(names = {"--not-before"},
            description = "ISO-8601 formatted UTC date (eg. '2020-11-23T16:35Z)\n" +
                    "Reject signatures with a creation date not in range.\n" +
                    "Defaults to beginning of time (\"-\").",
            paramLabel = "DATE")
    String notBefore = "-";

    @CommandLine.Option(names = {"--not-after"},
            description = "ISO-8601 formatted UTC date (eg. '2020-11-23T16:35Z)\n" +
                    "Reject signatures with a creation date not in range.\n" +
                    "Defaults to current system time (\"now\").\n" +
                    "Accepts special value \"-\" for end of time.",
            paramLabel = "DATE")
    String notAfter = "now";

    @CommandLine.Parameters(index = "0..*",
            description = "Secret keys to attempt decryption with",
            paramLabel = "KEY")
    List<File> keys = new ArrayList<>();

    @Override
    public void run() {
        throwIfVerifyOutExists(verifyOut);

        Decrypt decrypt = SopCLI.getSop().decrypt();
        if (decrypt == null) {
            throw new SOPGPException.UnsupportedSubcommand("Subcommand 'decrypt' not implemented.");
        }

        setNotAfter(notAfter, decrypt);
        setNotBefore(notBefore, decrypt);
        setWithPasswords(withPassword, decrypt);
        setWithSessionKeys(withSessionKey, decrypt);
        setVerifyWith(certs, decrypt);
        setDecryptWith(keys, decrypt);

        if (verifyOut != null && certs.isEmpty()) {
            throw new SOPGPException.IncompleteVerification("--verify-out is requested, but no --verify-with was provided.");
        }

        try {
            ReadyWithResult<DecryptionResult> ready = decrypt.ciphertext(System.in);
            DecryptionResult result = ready.writeTo(System.out);
            writeSessionKeyOut(result);
            writeVerifyOut(result);
        } catch (SOPGPException.BadData badData) {
            throw new SOPGPException.BadData("No valid OpenPGP message found on Standard Input.", badData);
        } catch (IOException ioException) {
            throw new RuntimeException(ioException);
        }
    }

    private void writeVerifyOut(DecryptionResult result) throws IOException {
        if (verifyOut != null) {
            if (!verifyOut.createNewFile()) {
                throw new IOException("Cannot create file " + verifyOut.getAbsolutePath());
            }
            try (FileOutputStream outputStream = new FileOutputStream(verifyOut)) {
                PrintWriter writer = new PrintWriter(outputStream);
                for (Verification verification : result.getVerifications()) {
                    // CHECKSTYLE:OFF
                    writer.println(verification.toString());
                    // CHECKSTYLE:ON
                }
                writer.flush();
            }
        }
    }

    private void writeSessionKeyOut(DecryptionResult result) throws IOException {
        if (sessionKeyOut != null) {
            if (sessionKeyOut.exists()) {
                throw new SOPGPException.OutputExists("Target " + sessionKeyOut.getAbsolutePath() + " of option --session-key-out already exists.");
            }

            try (FileOutputStream outputStream = new FileOutputStream(sessionKeyOut)) {
                if (!result.getSessionKey().isPresent()) {
                    throw new SOPGPException.UnsupportedOption("Session key not extracted. Possibly the feature --session-key-out is not supported.");
                } else {
                    SessionKey sessionKey = result.getSessionKey().get();
                    outputStream.write(sessionKey.getAlgorithm());
                    outputStream.write(sessionKey.getKey());
                }
            }
        }
    }

    private void throwIfVerifyOutExists(File verifyOut) throws SOPGPException.OutputExists {
        if (verifyOut == null) {
            return;
        }

        if (verifyOut.exists()) {
            throw new SOPGPException.OutputExists("Target " + verifyOut.getAbsolutePath() + " of option --verify-out already exists.");
        }
    }

    private void setDecryptWith(List<File> keys, Decrypt decrypt) {
        for (File key : keys) {
            try (FileInputStream keyIn = new FileInputStream(key)) {
                decrypt.withKey(keyIn);
            } catch (SOPGPException.KeyIsProtected keyIsProtected) {
                throw new SOPGPException.KeyIsProtected("Key in file " + key.getAbsolutePath() + " is password protected.", keyIsProtected);
            } catch (SOPGPException.BadData badData) {
                throw new SOPGPException.BadData("File " + key.getAbsolutePath() + " does not contain a private key.", badData);
            } catch (FileNotFoundException e) {
                throw new SOPGPException.MissingInput("File " + key.getAbsolutePath() + " does not exist.", e);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
    }

    private void setVerifyWith(List<File> certs, Decrypt decrypt) {
        for (File cert : certs) {
            try (FileInputStream certIn = new FileInputStream(cert)) {
                decrypt.verifyWithCert(certIn);
            } catch (FileNotFoundException e) {
                throw new SOPGPException.MissingInput("File " + cert.getAbsolutePath() + " does not exist.", e);
            } catch (SOPGPException.BadData badData) {
                throw new SOPGPException.BadData("File " + cert.getAbsolutePath() + " does not contain a valid certificate.", badData);
            } catch (IOException ioException) {
                throw new RuntimeException(ioException);
            }
        }
    }

    private void setWithSessionKeys(List<String> withSessionKey, Decrypt decrypt) {
        Pattern sessionKeyPattern = Pattern.compile("^\\d+:[0-9A-F]+$");
        for (String sessionKey : withSessionKey) {
            if (!sessionKeyPattern.matcher(sessionKey).matches()) {
                throw new IllegalArgumentException("Session keys are expected in the format 'ALGONUM:HEXKEY'.");
            }
            String[] split = sessionKey.split(":");
            byte algorithm = (byte) Integer.parseInt(split[0]);
            byte[] key = HexUtil.hexToBytes(split[1]);

            try {
                decrypt.withSessionKey(new SessionKey(algorithm, key));
            } catch (SOPGPException.UnsupportedOption unsupportedOption) {
                throw new SOPGPException.UnsupportedOption("Unsupported option '--with-session-key'.", unsupportedOption);
            }
        }
    }

    private void setWithPasswords(List<String> withPassword, Decrypt decrypt) {
        for (String password : withPassword) {
            try {
                decrypt.withPassword(password);
            } catch (SOPGPException.UnsupportedOption unsupportedOption) {
                throw new SOPGPException.UnsupportedOption("Unsupported option '--with-password'.", unsupportedOption);
            }
        }
    }

    private void setNotAfter(String notAfter, Decrypt decrypt) {
        Date notAfterDate = DateParser.parseNotAfter(notAfter);
        try {
            decrypt.verifyNotAfter(notAfterDate);
        } catch (SOPGPException.UnsupportedOption unsupportedOption) {
            throw new SOPGPException.UnsupportedOption("Option '--not-after' not supported.", unsupportedOption);
        }
    }

    private void setNotBefore(String notBefore, Decrypt decrypt) {
        Date notBeforeDate = DateParser.parseNotBefore(notBefore);
        try {
            decrypt.verifyNotBefore(notBeforeDate);
        } catch (SOPGPException.UnsupportedOption unsupportedOption) {
            throw new SOPGPException.UnsupportedOption("Option '--not-before' not supported.", unsupportedOption);
        }
    }
}
