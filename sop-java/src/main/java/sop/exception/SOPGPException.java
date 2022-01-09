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

    /**
     * No acceptable signatures found (sop verify).
     */
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

    /**
     * Asymmetric algorithm unsupported (sop encrypt).
     */
    public static class UnsupportedAsymmetricAlgo extends SOPGPException {

        public static final int EXIT_CODE = 13;

        public UnsupportedAsymmetricAlgo(String message, Throwable e) {
            super(message, e);
        }

        @Override
        public int getExitCode() {
            return EXIT_CODE;
        }
    }

    /**
     * Certificate not encryption capable (e,g, expired, revoked, unacceptable usage).
     */
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

    /**
     * Missing required argument.
     */
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

    /**
     * Incomplete verification instructions (sop decrypt).
     */
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

    /**
     * Unable to decrypt (sop decrypt).
     */
    public static class CannotDecrypt extends SOPGPException {

        public static final int EXIT_CODE = 29;

        @Override
        public int getExitCode() {
            return EXIT_CODE;
        }
    }

    /**
     * Non-UTF-8 or otherwise unreliable password (sop encrypt).
     */
    public static class PasswordNotHumanReadable extends SOPGPException {

        public static final int EXIT_CODE = 31;

        @Override
        public int getExitCode() {
            return EXIT_CODE;
        }
    }

    /**
     * Unsupported option.
     */
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

    /**
     * Invalid data type (no secret key where KEYS expected, etc.).
     */
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

    /**
     * Non-Text input where text expected.
     */
    public static class ExpectedText extends SOPGPException {

        public static final int EXIT_CODE = 53;

        @Override
        public int getExitCode() {
            return EXIT_CODE;
        }
    }

    /**
     * Output file already exists.
     */
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

    /**
     * Input file does not exist.
     */
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

    /**
     * A KEYS input is protected (locked) with a password, and sop cannot unlock it.
     */
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

    /**
     * Unsupported subcommand.
     */
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

    /**
     * An indirect parameter is a special designator (it starts with @), but sop does not know how to handle the prefix.
     */
    public static class UnsupportedSpecialPrefix extends SOPGPException {

        public static final int EXIT_CODE = 71;

        @Override
        public int getExitCode() {
            return EXIT_CODE;
        }
    }

    /**
     * A indirect input parameter is a special designator (it starts with @),
     * and a filename matching the designator is actually present.
     */
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

    /**
     * Key not signature-capable (e.g. expired, revoked, unacceptable usage flags)
     * (sop sign and sop encrypt with --sign-with).
     */
    public static class KeyCannotSign extends SOPGPException {

        public static final int EXIT_CODE = 79;

        public KeyCannotSign() {
            super();
        }

        public KeyCannotSign(String s, KeyCannotSign keyCannotSign) {
            super(s, keyCannotSign);
        }

        @Override
        public int getExitCode() {
            return EXIT_CODE;
        }
    }
}
