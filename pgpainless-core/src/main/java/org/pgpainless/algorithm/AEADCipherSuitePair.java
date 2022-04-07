// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.algorithm;

import javax.annotation.Nonnull;

public class AEADCipherSuitePair {

    private final AEADAlgorithm aeadAlgorithm;
    private final SymmetricKeyAlgorithm symmetricKeyAlgorithm;

    public AEADCipherSuitePair(@Nonnull SymmetricKeyAlgorithm symmetric, @Nonnull AEADAlgorithm aead) {
        this.symmetricKeyAlgorithm = symmetric;
        this.aeadAlgorithm = aead;
    }

    public SymmetricKeyAlgorithm getSymmetricKeyAlgorithm() {
        return symmetricKeyAlgorithm;
    }

    public AEADAlgorithm getAeadAlgorithm() {
        return aeadAlgorithm;
    }

    /**
     * Mandatory-to-implement combination of AES-128 and OCB
     *
     * @return algorithm pair for AES-128 and OCB
     */
    public static AEADCipherSuitePair aes128WithOcb() {
        return new AEADCipherSuitePair(SymmetricKeyAlgorithm.AES_128, AEADAlgorithm.OCB);
    }

    @Override
    public int hashCode() {
        return symmetricKeyAlgorithm.hashCode() * 31 + aeadAlgorithm.hashCode();
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == null) {
            return false;
        }
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof AEADCipherSuitePair)) {
            return false;
        }
        AEADCipherSuitePair other = (AEADCipherSuitePair) obj;
        return getAeadAlgorithm() == other.getAeadAlgorithm()
                && getSymmetricKeyAlgorithm() == other.getSymmetricKeyAlgorithm();
    }
}
