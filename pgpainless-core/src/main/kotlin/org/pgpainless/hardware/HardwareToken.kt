// SPDX-FileCopyrightText: 2025 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.hardware

/**
 * Represents a hardware device, holding one or multiple [HardwareKeys][HardwareKey].
 *
 * @param keys cryptographic keys, keyed by label.
 */
data class HardwareToken(val keys: Map<ByteArray, HardwareKey>)
