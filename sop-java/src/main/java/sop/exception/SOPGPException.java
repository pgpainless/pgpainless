/*
 * Copyright 2021 Paul Schaub.
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
package sop.exception;

public abstract class SOPGPException extends RuntimeException {

    public SOPGPException() {
        super();
    }

    public SOPGPException(String message) {
        super(message);
    }

    public SOPGPException(Throwable e) {
        super(e);
    }

    public SOPGPException(String message, Throwable cause) {
        super(message, cause);
    }

    public abstract int getExitCode();

    public static class NoSignature extends SOPGPException {

        public static final int EXIT_CODE = 3;

        public NoSignature() {
            super("No verifiable signature found.");
        }

        @Override
        public int getExitCode() {
            return EXIT_CODE;
        }
    }

    public static class UnsupportedAsymmetricAlgo extends SOPGPException {

        public static final int EXIT_CODE = 13;

        public UnsupportedAsymmetricAlgo(String message, Throwable e) {
            super(message, e);
        }

        public UnsupportedAsymmetricAlgo(Throwable e) {
            super(e);
        }

        @Override
        public int getExitCode() {
            return EXIT_CODE;
        }
    }

    public static class CertCannotEncrypt extends SOPGPException {
        public static final int EXIT_CODE = 17;

        public CertCannotEncrypt(String message, Throwable cause) {
            super(message, cause);
        }

        @Override
        public int getExitCode() {
            return EXIT_CODE;
        }
    }

    public static class CertCannotSign extends Exception {

    }

    public static class MissingArg extends SOPGPException {

        public static final int EXIT_CODE = 19;

        public MissingArg(String s) {
            super(s);
        }

        @Override
        public int getExitCode() {
            return EXIT_CODE;
        }
    }

    public static class IncompleteVerification extends SOPGPException {

        public static final int EXIT_CODE = 23;

        public IncompleteVerification(String message) {
            super(message);
        }

        @Override
        public int getExitCode() {
            return EXIT_CODE;
        }
    }

    public static class CannotDecrypt extends SOPGPException {

        public static final int EXIT_CODE = 29;

        @Override
        public int getExitCode() {
            return EXIT_CODE;
        }
    }

    public static class PasswordNotHumanReadable extends SOPGPException {

        public static final int EXIT_CODE = 31;

        @Override
        public int getExitCode() {
            return EXIT_CODE;
        }
    }

    public static class UnsupportedOption extends SOPGPException {

        public static final int EXIT_CODE = 37;

        public UnsupportedOption(String message) {
            super(message);
        }

        public UnsupportedOption(String message, Throwable cause) {
            super(message, cause);
        }

        @Override
        public int getExitCode() {
            return EXIT_CODE;
        }
    }

    public static class BadData extends SOPGPException {

        public static final int EXIT_CODE = 41;

        public BadData(Throwable e) {
            super(e);
        }

        public BadData(String message, BadData badData) {
            super(message, badData);
        }

        @Override
        public int getExitCode() {
            return EXIT_CODE;
        }
    }

    public static class ExpectedText extends SOPGPException {

        public static final int EXIT_CODE = 53;

        @Override
        public int getExitCode() {
            return EXIT_CODE;
        }
    }

    public static class OutputExists extends SOPGPException {

        public static final int EXIT_CODE = 59;

        public OutputExists(String message) {
            super(message);
        }

        @Override
        public int getExitCode() {
            return EXIT_CODE;
        }
    }

    public static class MissingInput extends SOPGPException {

        public static final int EXIT_CODE = 61;

        public MissingInput(String message, Throwable cause) {
            super(message, cause);
        }

        @Override
        public int getExitCode() {
            return EXIT_CODE;
        }
    }

    public static class KeyIsProtected extends SOPGPException {

        public static final int EXIT_CODE = 67;

        public KeyIsProtected() {
            super();
        }

        public KeyIsProtected(String message, Throwable cause) {
            super(message, cause);
        }

        @Override
        public int getExitCode() {
            return EXIT_CODE;
        }
    }

    public static class UnsupportedSubcommand extends SOPGPException {

        public static final int EXIT_CODE = 69;

        public UnsupportedSubcommand(String message) {
            super(message);
        }

        @Override
        public int getExitCode() {
            return EXIT_CODE;
        }
    }

    public static class UnsupportedSpecialPrefix extends SOPGPException {

        public static final int EXIT_CODE = 71;

        @Override
        public int getExitCode() {
            return EXIT_CODE;
        }
    }


    public static class AmbiguousInput extends SOPGPException {

        public static final int EXIT_CODE = 73;

        public AmbiguousInput(String message) {
            super(message);
        }

        @Override
        public int getExitCode() {
            return EXIT_CODE;
        }
    }
}
