// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package sop.cli.picocli;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Files;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import sop.exception.SOPGPException;

public class FileUtilTest {

    @BeforeAll
    public static void setup() {
        FileUtil.setEnvironmentVariableResolver(new FileUtil.EnvironmentVariableResolver() {
            @Override
            public String resolveEnvironmentVariable(String name) {
                if (name.equals("test123")) {
                    return "test321";
                }
                return null;
            }
        });
    }

    @Test
    public void getFile_ThrowsForNull() {
        assertThrows(NullPointerException.class, () -> FileUtil.getFile(null));
    }

    @Test
    public void getFile_prfxEnvAlreadyExists() throws IOException {
        File tempFile = new File("@ENV:test");
        tempFile.createNewFile();
        tempFile.deleteOnExit();

        assertThrows(SOPGPException.AmbiguousInput.class, () -> FileUtil.getFile("@ENV:test"));
    }

    @Test
    public void getFile_EnvironmentVariable() {
        File file = FileUtil.getFile("@ENV:test123");
        assertEquals("test321", file.getName());
    }

    @Test
    public void getFile_nonExistentEnvVariable() {
        assertThrows(IllegalArgumentException.class, () -> FileUtil.getFile("@ENV:INVALID"));
    }

    @Test
    public void getFile_prfxFdAlreadyExists() throws IOException {
        File tempFile = new File("@FD:1");
        tempFile.createNewFile();
        tempFile.deleteOnExit();

        assertThrows(SOPGPException.AmbiguousInput.class, () -> FileUtil.getFile("@FD:1"));
    }

    @Test
    public void getFile_prfxFdNotSupported() {
        assertThrows(IllegalArgumentException.class, () -> FileUtil.getFile("@FD:2"));
    }

    @Test
    public void createNewFileOrThrow_throwsForNull() {
        assertThrows(NullPointerException.class, () -> FileUtil.createNewFileOrThrow(null));
    }

    @Test
    public void createNewFileOrThrow_success() throws IOException {
        File dir = Files.createTempDirectory("test").toFile();
        dir.deleteOnExit();
        File file = new File(dir, "file");

        assertFalse(file.exists());
        FileUtil.createNewFileOrThrow(file);
        assertTrue(file.exists());
    }

    @Test
    public void createNewFileOrThrow_alreadyExists() throws IOException {
        File dir = Files.createTempDirectory("test").toFile();
        dir.deleteOnExit();
        File file = new File(dir, "file");

        FileUtil.createNewFileOrThrow(file);
        assertTrue(file.exists());
        assertThrows(SOPGPException.OutputExists.class, () -> FileUtil.createNewFileOrThrow(file));
    }

    @Test
    public void getFileInputStream_success() throws IOException {
        File dir = Files.createTempDirectory("test").toFile();
        dir.deleteOnExit();
        File file = new File(dir, "file");

        FileUtil.createNewFileOrThrow(file);
        FileInputStream inputStream = FileUtil.getFileInputStream(file.getAbsolutePath());
        assertNotNull(inputStream);
    }

    @Test
    public void getFileInputStream_fileNotFound() throws IOException {
        File dir = Files.createTempDirectory("test").toFile();
        dir.deleteOnExit();
        File file = new File(dir, "file");

        assertThrows(SOPGPException.MissingInput.class,
                () -> FileUtil.getFileInputStream(file.getAbsolutePath()));
    }
}
