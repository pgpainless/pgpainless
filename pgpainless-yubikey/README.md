<!--
SPDX-FileCopyrightText: 2025 Paul Schaub <vanitasvitae@fsfe.org>

SPDX-License-Identifier: Apache-2.0
-->

# PGPainless-Yubikey

Platform-agnostic OpenPGP smartcard support for PGPainless tailored towards Yubikey hardware tokens.

This module uses the `com.yubico.yubikit:openpgp` library to integrate support for OpenPGP keys stored on
Yubikeys into PGPainless.

The implementation can be used both on Android and on desktop, but you need to provide
a suitable implementation of the `YubikeyDeviceManager` interface.
On desktop, this is provided via the `DesktopYubikeyDeviceManager` class from the
`org.pgpainless:pgpainless-yubikey-desktop` module.
On Android, you need to create your own implementation using the `YubiKitManager` class from
`com.yubico.yubikit:android`