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

import static org.pgpainless.sop.Print.print_ln;

import java.io.IOException;
import java.util.Properties;

import picocli.CommandLine;

@CommandLine.Command(name = "version", description = "Display version information about the tool",
        exitCodeOnInvalidInput = 37)
public class Version implements Runnable {

    @Override
    public void run() {
        // See https://stackoverflow.com/a/50119235
        String version;
        try {
            Properties properties = new Properties();
            properties.load(getClass().getResourceAsStream("/version.properties"));
            version = properties.getProperty("version");
        } catch (IOException e) {
            version = "DEVELOPMENT";
        }
        print_ln("PGPainlessCLI " + version);
    }
}
