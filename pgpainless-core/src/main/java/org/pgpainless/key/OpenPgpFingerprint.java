// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key;

import java.nio.charset.Charset;
import javax.annotation.Nonnull;

import org.bouncycastle.openpgp.PGPKeyRing;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.util.encoders.Hex;

/**
 * Abstract super class of different version OpenPGP fingerprints.
 *
 */
public abstract class OpenPgpFingerprint implements CharSequence, Comparable<OpenPgpFingerprint> {
    protected static final Charset utf8 = Charset.forName("UTF-8");
    protected final String fingerprint;

    /**
     * Return the fingerprint of the given key.
     * This method automatically matches key versions to fingerprint implementations.
     *
     * @param key key
     * @return fingerprint
     */
    public static OpenPgpFingerprint of(PGPPublicKey key) {
        if (key.getVersion() == 4) {
            return new OpenPgpV4Fingerprint(key);
        }
        throw new IllegalArgumentException("OpenPGP keys of version " + key.getVersion() + " are not supported.");
    }

    /**
     * Return the fingerprint of the primary key of the given key ring.
     * This method automatically matches key versions to fingerprint implementations.
     *
     * @param ring key ring
     * @return fingerprint
     */
    public static OpenPgpFingerprint of(PGPKeyRing ring) {
        return of(ring.getPublicKey());
    }

    public OpenPgpFingerprint(String fingerprint) {
        String fp = fingerprint.replace(" ", "").trim().toUpperCase();
        if (!isValid(fp)) {
            throw new IllegalArgumentException(
                    String.format("Fingerprint '%s' does not appear to be a valid OpenPGP V%d fingerprint.", fingerprint, getVersion())
            );
        }
        this.fingerprint = fp;
    }

    public OpenPgpFingerprint(@Nonnull byte[] bytes) {
        this(new String(bytes, utf8));
    }

    public OpenPgpFingerprint(PGPPublicKey key) {
        this(Hex.encode(key.getFingerprint()));
        if (key.getVersion() != getVersion()) {
            throw new IllegalArgumentException(String.format("Key is not a v%d OpenPgp key.", getVersion()));
        }
    }

    public OpenPgpFingerprint(@Nonnull PGPPublicKeyRing ring) {
        this(ring.getPublicKey());
    }

    public OpenPgpFingerprint(@Nonnull PGPSecretKeyRing ring) {
        this(ring.getPublicKey());
    }

    public OpenPgpFingerprint(@Nonnull PGPKeyRing ring) {
        this(ring.getPublicKey());
    }

    /**
     * Return the version of the fingerprint.
     *
     * @return version
     */
    public abstract int getVersion();

    /**
     * Check, whether the fingerprint consists of 40 valid hexadecimal characters.
     * @param fp fingerprint to check.
     * @return true if fingerprint is valid.
     */
    protected abstract boolean isValid(@Nonnull String fp);

    /**
     * Return the key id of the OpenPGP public key this {@link OpenPgpFingerprint} belongs to.
     * This method can be implemented for V4 and V5 fingerprints.
     * V3 key-IDs cannot be derived from the fingerprint, but we don't care, since V3 is deprecated.
     *
     * @see <a href="https://tools.ietf.org/html/rfc4880#section-12.2">
     *     RFC-4880 §12.2: Key IDs and Fingerprints</a>
     * @return key id
     */
    public abstract long getKeyId();

    @Override
    public int length() {
        return fingerprint.length();
    }

    @Override
    public char charAt(int i) {
        return fingerprint.charAt(i);
    }

    @Override
    public CharSequence subSequence(int i, int i1) {
        return fingerprint.subSequence(i, i1);
    }

    @Override
    @Nonnull
    public String toString() {
        return fingerprint;
    }

    /**
     * Return a pretty printed representation of the fingerprint.
     *
     * @return pretty printed fingerprint
     */
    public abstract String prettyPrint();
}