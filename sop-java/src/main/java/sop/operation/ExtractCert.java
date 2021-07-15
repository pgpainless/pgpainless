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
package sop.operation;

import java.io.IOException;
import java.io.InputStream;

import sop.Ready;
import sop.exception.SOPGPException;

public interface ExtractCert {

    /**
     * Disable ASCII armor encoding.
     *
     * @return builder instance
     */
    ExtractCert noArmor();

    /**
     * Extract the cert from the provided key.
     *
     * @param keyInputStream input stream containing the encoding of an OpenPGP key
     * @return input stream containing the encoding of the keys cert
     */
    Ready key(InputStream keyInputStream) throws IOException, SOPGPException.BadData;
}
