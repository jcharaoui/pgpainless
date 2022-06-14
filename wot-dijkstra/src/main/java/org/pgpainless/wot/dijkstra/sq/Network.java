package org.pgpainless.wot.dijkstra.sq;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;

import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.KeyFlag;
import org.pgpainless.key.OpenPgpFingerprint;
import org.pgpainless.key.info.KeyRingInfo;
import org.pgpainless.policy.Policy;
import sun.nio.ch.Net;

import javax.annotation.Nonnull;

public class Network {

    private final Map<OpenPgpFingerprint, CertSynopsis> nodes;
    private final Map<OpenPgpFingerprint, List<CertificationSet>> edges;
    private final Map<OpenPgpFingerprint, List<CertificationSet>> reverseEdges;
    private final ReferenceTime referenceTime;

    public Network(Map<OpenPgpFingerprint, CertSynopsis> nodes,
                   Map<OpenPgpFingerprint, List<CertificationSet>> edges,
                   Map<OpenPgpFingerprint, List<CertificationSet>> reverseEdges,
                   ReferenceTime referenceTime) {
        this.nodes = nodes;
        this.edges = edges;
        this.reverseEdges = reverseEdges;
        this.referenceTime = referenceTime;
    }

    public static Network empty(@Nonnull ReferenceTime referenceTime) {
        return new Network(
                new HashMap<>(),
                new HashMap<>(),
                new HashMap<>(),
                referenceTime);
    }

    public static Network fromCertificates(
            Iterable<PGPPublicKeyRing> certificates,
            Policy policy,
            Optional<ReferenceTime> optReferenceTime) {
        ReferenceTime referenceTime = optReferenceTime.isPresent() ? optReferenceTime.get() : ReferenceTime.now();
        List<KeyRingInfo> validCerts = new ArrayList<>();
        for (PGPPublicKeyRing cert : certificates) {
            KeyRingInfo info = PGPainless.inspectKeyRing(cert, referenceTime.getTimestamp());
            if (info.getValidUserIds().isEmpty()) {
                // Ignore invalid cert
            } else {
                validCerts.add(info);
            }
        }

        return fromValidCertificates(
                validCerts,
                referenceTime
        );
    }

    public static Network fromValidCertificates(
            Iterable<KeyRingInfo> validatedCertificates,
            ReferenceTime referenceTime) {

        Map<OpenPgpFingerprint, KeyRingInfo> byFingerprint = new HashMap<>();
        Map<Long, List<KeyRingInfo>> byKeyId = new HashMap<>();

        Map<OpenPgpFingerprint, CertSynopsis> certSynopsisMap = new HashMap<>();

        for (KeyRingInfo cert : validatedCertificates) {
            byFingerprint.put(cert.getFingerprint(), cert);
            List<KeyRingInfo> byKeyIdEntry = byKeyId.get(cert.getKeyId());
            if (byKeyIdEntry == null) {
                byKeyIdEntry = new ArrayList<>();
                byKeyId.put(cert.getKeyId(), byKeyIdEntry);
            }
            byKeyIdEntry.add(cert);

            certSynopsisMap.put(cert.getFingerprint(),
                    new CertSynopsis(cert.getFingerprint(),
                            cert.getExpirationDateForUse(KeyFlag.CERTIFY_OTHER),
                            cert.getRevocationSelfSignature() != null,
                            new HashSet<>(cert.getValidUserIds())));
        }

        Map<OpenPgpFingerprint, List<CertificationSet>> edges = new HashMap<>();
        Map<OpenPgpFingerprint, List<CertificationSet>> reverseEdges = new HashMap<>();

        return new Network(certSynopsisMap, edges, reverseEdges, referenceTime);
    }
}
