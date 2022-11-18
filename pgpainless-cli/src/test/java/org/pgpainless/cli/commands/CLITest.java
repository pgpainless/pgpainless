// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.cli.commands;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import javax.annotation.Nonnull;

import org.bouncycastle.util.io.Streams;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.opentest4j.TestAbortedException;
import org.pgpainless.cli.TestUtils;
import org.pgpainless.sop.SOPImpl;
import org.slf4j.Logger;
import sop.cli.picocli.SopCLI;

public abstract class CLITest {

    protected File testDirectory;
    protected InputStream stdin;
    protected PrintStream stdout;

    protected final Logger LOGGER;


    public CLITest(@Nonnull Logger logger) {
        LOGGER = logger;
        SopCLI.setSopInstance(new SOPImpl());
    }

    @BeforeEach
    public void setup() throws IOException {
        testDirectory = TestUtils.createTempDirectory();
        testDirectory.deleteOnExit();
        LOGGER.debug(testDirectory.getAbsolutePath());
        stdin = System.in;
        stdout = System.out;
    }

    @AfterEach
    public void cleanup() throws IOException {
        resetStreams();
    }

    public File nonExistentFile(String name) {
        File file = new File(testDirectory, name);
        if (file.exists()) {
            throw new TestAbortedException("File " + file.getAbsolutePath() + " already exists.");
        }
        return file;
    }

    public File pipeStdoutToFile(String name) throws IOException {
        File file = new File(testDirectory, name);
        file.deleteOnExit();
        if (!file.createNewFile()) {
            throw new TestAbortedException("Cannot create new file " + file.getAbsolutePath());
        }
        System.setOut(new PrintStream(Files.newOutputStream(file.toPath())));
        return file;
    }

    public ByteArrayOutputStream pipeStdoutToStream() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        pipeStdoutToStream(out);
        return out;
    }

    public void pipeStdoutToStream(OutputStream stream) {
        System.setOut(new PrintStream(stream));
    }

    public void pipeFileToStdin(File file) throws IOException {
        System.setIn(Files.newInputStream(file.toPath()));
    }

    public void pipeBytesToStdin(byte[] bytes) {
        System.setIn(new ByteArrayInputStream(bytes));
    }

    public void pipeStringToStdin(String string) {
        System.setIn(new ByteArrayInputStream(string.getBytes(StandardCharsets.UTF_8)));
    }

    public void resetStdout() {
        if (System.out != stdout) {
            System.out.flush();
            System.out.close();
        }
        System.setOut(stdout);
    }

    public void resetStdin() throws IOException {
        if (System.in != stdin) {
            System.in.close();
        }
        System.setIn(stdin);
    }

    public void resetStreams() throws IOException {
        resetStdout();
        resetStdin();
    }

    public File writeFile(String name, String data) throws IOException {
        return writeFile(name, data.getBytes(StandardCharsets.UTF_8));
    }

    public File writeFile(String name, byte[] bytes) throws IOException {
        return writeFile(name, new ByteArrayInputStream(bytes));
    }

    public File writeFile(String name, InputStream data) throws IOException {
        File file = new File(testDirectory, name);
        if (!file.createNewFile()) {
            throw new TestAbortedException("Cannot create new file " + file.getAbsolutePath());
        }
        file.deleteOnExit();
        try (FileOutputStream fileOut = new FileOutputStream(file)) {
            Streams.pipeAll(data, fileOut);
            fileOut.flush();
        }
        return file;
    }

    public byte[] readBytesFromFile(File file) {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        try (FileInputStream fileIn = new FileInputStream(file)) {
            Streams.pipeAll(fileIn, buffer);
        } catch (FileNotFoundException e) {
            throw new TestAbortedException("File " + file.getAbsolutePath() + " does not exist!", e);
        } catch (IOException e) {
            throw new TestAbortedException("Cannot read from file " + file.getAbsolutePath(), e);
        }
        return buffer.toByteArray();
    }

    public String readStringFromFile(File file) {
        return new String(readBytesFromFile(file), StandardCharsets.UTF_8);
    }

    public int executeCommand(String... command) throws IOException {
        int exitCode = SopCLI.execute(command);
        resetStreams();
        return exitCode;
    }

    public void assertSuccess(int exitCode) {
        assertEquals(0, exitCode,
                "Expected successful program execution");
    }
}
