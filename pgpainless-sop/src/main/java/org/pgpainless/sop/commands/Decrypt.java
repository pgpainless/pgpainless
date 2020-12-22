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

import picocli.CommandLine;

import java.io.File;

import static org.pgpainless.sop.Print.err_ln;

@CommandLine.Command(name = "decrypt",
        description = "Decrypt a message from standard input")
public class Decrypt implements Runnable {

    @CommandLine.Option(
            names = {"--session-key-out"},
            description = "Can be used to learn the session key on successful decryption",
            paramLabel = "SESSIONKEY")
    File sessionKeyOut;

    @CommandLine.Option(
            names = {"--with-session-key"},
            description = "Enables decryption of the \"CIPHERTEXT\" using the session key directly against the \"SEIPD\" packet",
            paramLabel = "SESSIONKEY")
    File[] withSessionKey;

    @CommandLine.Option(
            names = {"--with-password"},
            description = "Enables decryption based on any \"SKESK\" packets in the \"CIPHERTEXT\"",
            paramLabel = "PASSWORD")
    String[] withPassword;

    @CommandLine.Option(names = {"--verify-out"},
            description = "Produces signature verification status to the designated file",
            paramLabel = "VERIFICATIONS")
    File verifyOut;

    @CommandLine.Option(names = {"--verify-with"},
            description = "Certificates whose signatures would be acceptable for signatures over this message",
            paramLabel = "CERT")
    File[] certs;

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
    File[] keys;

    @Override
    public void run() {
        if (verifyOut == null ^ certs == null) {
            err_ln("To enable signature verification, both --verify-out and at least one --verify-with argument must be supplied.");
            System.exit(23);
        }
    }
}
