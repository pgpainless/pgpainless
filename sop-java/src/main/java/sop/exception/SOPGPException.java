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

public class SOPGPException extends Exception {

    public SOPGPException() {
        super();
    }

    public SOPGPException(String message) {
        super(message);
    }

    public SOPGPException(Throwable e) {
        super(e);
    }

    public static class NoSignature extends SOPGPException {

        public static final int EXIT_CODE = 3;

        public int getExitCode() {
            return EXIT_CODE;
        }
    }

    public static class UnsupportedAsymmetricAlgo extends SOPGPException {

        public static final int EXIT_CODE = 13;

        public UnsupportedAsymmetricAlgo(Throwable e) {
            super(e);
        }

        public int getExitCode() {
            return EXIT_CODE;
        }
    }

    public static class CertCannotEncrypt extends SOPGPException {
        public static final int EXIT_CODE = 17;

        public int getExitCode() {
            return EXIT_CODE;
        }
    }

    public static class CertCannotSign extends SOPGPException {

    }

    public static class MissingArg extends SOPGPException {

        public static final int EXIT_CODE = 19;

        public MissingArg(String s) {
            super(s);
        }

        public int getExitCode() {
            return EXIT_CODE;
        }
    }

    public static class IncompleteVerification extends SOPGPException {

        public static final int EXIT_CODE = 23;

        public int getExitCode() {
            return EXIT_CODE;
        }
    }

    public static class CannotDecrypt extends SOPGPException {

        public static final int EXIT_CODE = 29;

        public int getExitCode() {
            return EXIT_CODE;
        }
    }

    public static class PasswordNotHumanReadable extends SOPGPException {

        public static final int EXIT_CODE = 31;

        public int getExitCode() {
            return EXIT_CODE;
        }
    }

    public static class UnsupportedOption extends SOPGPException {

        public static final int EXIT_CODE = 37;

        public int getExitCode() {
            return EXIT_CODE;
        }
    }

    public static class BadData extends SOPGPException {

        public static final int EXIT_CODE = 41;

        public BadData(Throwable e) {
            super(e);
        }

        public int getExitCode() {
            return EXIT_CODE;
        }
    }

    public static class ExpectedText extends SOPGPException {

        public static final int EXIT_CODE = 53;

        public int getExitCode() {
            return EXIT_CODE;
        }
    }

    public static class OutputExists extends SOPGPException {

    }

    public static class KeyIsProtected extends SOPGPException {

    }

    public static class AmbiguousInput extends SOPGPException {

    }

    public static class NotImplemented extends SOPGPException {

        public static final int EXIT_CODE = 69;

        public int getExitCode() {
            return EXIT_CODE;
        }
    }
}
