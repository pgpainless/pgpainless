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
package sop.cli.picocli;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;

import sop.exception.SOPGPException;

public class FileUtil {

    private static final String ERROR_AMBIGUOUS = "File name '%s' is ambiguous. File with the same name exists on the filesystem.";
    private static final String ERROR_ENV_FOUND = "Environment variable '%s' not set.";
    private static final String ERROR_OUTPUT_EXISTS = "Output file '%s' already exists.";
    private static final String ERROR_INPUT_NOT_EXIST = "File '%s' does not exist.";
    private static final String ERROR_CANNOT_CREATE_FILE = "Output file '%s' cannot be created: %s";

    public static final String PRFX_ENV = "@ENV:";
    public static final String PRFX_FD = "@FD:";

    public static File getFile(String fileName) {
        if (fileName == null) {
            throw new NullPointerException("File name cannot be null.");
        }

        if (fileName.startsWith(PRFX_ENV)) {

            if (new File(fileName).exists()) {
                throw new SOPGPException.AmbiguousInput(String.format(ERROR_AMBIGUOUS, fileName));
            }

            String envName = fileName.substring(PRFX_ENV.length());
            String envValue = System.getenv(envName);
            if (envValue == null) {
                throw new IllegalArgumentException(String.format(ERROR_ENV_FOUND, envName));
            }
            return new File(envValue);
        } else if (fileName.startsWith(PRFX_FD)) {

            if (new File(fileName).exists()) {
                throw new SOPGPException.AmbiguousInput(String.format(ERROR_AMBIGUOUS, fileName));
            }

            throw new IllegalArgumentException("File descriptors not supported.");
        }

        return new File(fileName);
    }

    public static FileInputStream getFileInputStream(String fileName) {
        File file = getFile(fileName);
        try {
            FileInputStream inputStream = new FileInputStream(file);
            return inputStream;
        } catch (FileNotFoundException e) {
            throw new SOPGPException.MissingInput(String.format(ERROR_INPUT_NOT_EXIST, fileName), e);
        }
    }

    public static File createNewFileOrThrow(File file) throws IOException {
        if (file == null) {
            throw new NullPointerException("File cannot be null.");
        }

        try {
            if (!file.createNewFile()) {
                throw new SOPGPException.OutputExists(String.format(ERROR_OUTPUT_EXISTS, file.getAbsolutePath()));
            }
        } catch (IOException e) {
            throw new IOException(String.format(ERROR_CANNOT_CREATE_FILE, file.getAbsolutePath(), e.getMessage()));
        }
        return file;
    }
}
