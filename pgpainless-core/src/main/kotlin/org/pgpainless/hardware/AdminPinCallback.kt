// SPDX-FileCopyrightText: 2025 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.hardware

interface AdminPinCallback {
    fun provideAdminPin(deviceSerialNumber: Int): CharArray?
}
