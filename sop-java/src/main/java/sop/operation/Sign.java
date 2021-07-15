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
import sop.enums.SignAs;
import sop.exception.SOPGPException;

public interface Sign {

    /**
     * Disable ASCII armor encoding.
     *
     * @return builder instance
     */
    Sign noArmor();

    /**
     * Sets the signature mode.
     *
     * @param mode signature mode
     * @return builder instance
     */
    Sign mode(SignAs mode) throws SOPGPException.UnsupportedOption;

    /**
     * Adds the signer key.
     *
     * @param key input stream containing encoded key
     * @return builder instance
     */
    Sign key(InputStream key) throws SOPGPException.KeyIsProtected, SOPGPException.BadData, IOException;

    /**
     * Signs data.
     *
     * @param data input stream containing data
     * @return ready
     */
    Ready data(InputStream data) throws IOException, SOPGPException.ExpectedText;
}
