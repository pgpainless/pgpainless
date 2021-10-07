// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

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

    private static EnvironmentVariableResolver envResolver = System::getenv;

    public static void setEnvironmentVariableResolver(EnvironmentVariableResolver envResolver) {
        if (envResolver == null) {
            throw new NullPointerException("Variable envResolver cannot be null.");
        }
        FileUtil.envResolver = envResolver;
    }

    public interface EnvironmentVariableResolver {
        /**
         * Resolve the value of the given environment variable.
         * Return null if the variable is not present.
         *
         * @param name name of the variable
         * @return variable value or null
         */
        String resolveEnvironmentVariable(String name);
    }

    public static File getFile(String fileName) {
        if (fileName == null) {
            throw new NullPointerException("File name cannot be null.");
        }

        if (fileName.startsWith(PRFX_ENV)) {

            if (new File(fileName).exists()) {
                throw new SOPGPException.AmbiguousInput(String.format(ERROR_AMBIGUOUS, fileName));
            }

            String envName = fileName.substring(PRFX_ENV.length());
            String envValue = envResolver.resolveEnvironmentVariable(envName);
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
