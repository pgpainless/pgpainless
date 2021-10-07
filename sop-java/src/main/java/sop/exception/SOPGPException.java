// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

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
