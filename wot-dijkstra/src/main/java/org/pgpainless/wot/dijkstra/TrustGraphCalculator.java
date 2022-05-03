package org.pgpainless.wot.dijkstra;

import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSignature;

import java.util.HashSet;
import java.util.Set;

public class TrustGraphCalculator {

    private final PGPPublicKeyRing trustRoot;

    public TrustGraphCalculator(PGPPublicKeyRing trustRoot) {
        this.trustRoot = trustRoot;
    }

    public Graph calculateTrustGraphFor(Iterable<PGPPublicKeyRing> certificates) {
        for (PGPPublicKeyRing certificate : certificates) {
            Set<PGPSignature> thirdPartySignatures = new HashSet<>();
        }
    }
}
