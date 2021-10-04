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
package org.pgpainless.sop;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

import sop.operation.Version;

public class VersionImpl implements Version {
    @Override
    public String getName() {
        return "PGPainless-SOP";
    }

    @Override
    public String getVersion() {
        // See https://stackoverflow.com/a/50119235
        String version;
        try {
            Properties properties = new Properties();
            InputStream propertiesFileIn = getClass().getResourceAsStream("/version.properties");
            if (propertiesFileIn == null) {
                throw new IOException("File version.properties not found.");
            }
            properties.load(propertiesFileIn);
            version = properties.getProperty("version");
        } catch (IOException e) {
            version = "DEVELOPMENT";
        }
        return version;
    }
}
