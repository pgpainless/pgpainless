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

import java.io.InputStream;

import sop.Ready;
import sop.enums.ArmorLabel;
import sop.exception.SOPGPException;

public interface Armor {

    /**
     * Overrides automatic detection of label.
     *
     * @param label armor label
     * @return builder instance
     */
    Armor label(ArmorLabel label) throws SOPGPException.UnsupportedOption;

    /**
     * Allow nested Armoring.
     *
     * @return builder instance
     */
    Armor allowNested() throws SOPGPException.UnsupportedOption;

    /**
     * Armor the provided data.
     *
     * @param data input stream of unarmored OpenPGP data
     * @return armored data
     */
    Ready data(InputStream data) throws SOPGPException.BadData;
}
