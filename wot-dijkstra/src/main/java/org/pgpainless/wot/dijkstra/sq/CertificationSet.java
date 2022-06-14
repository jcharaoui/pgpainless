package org.pgpainless.wot.dijkstra.sq;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.bouncycastle.openpgp.PGPSignature;

public class CertificationSet {

    private final CertSynopsis issuer;
    private final CertSynopsis target;

    private final Map<Optional<String>, List<Certification>> certifications;

    public static CertificationSet empty(CertSynopsis issuer, CertSynopsis target) {
        return new CertificationSet(issuer, target, new HashMap<>());
    }

    public static CertificationSet fromCertification(
            CertSynopsis issuer,
            CertSynopsis target,
            Optional<String> userId,
            PGPSignature signature) {

        Map<Optional<String>, List<Certification>> certificationMap = new HashMap<>();
        List<Certification> certificationList = new ArrayList<>();
        certificationList.add(new Certification(issuer, userId, target, signature));
        certificationMap.put(userId, certificationList);

        return new CertificationSet(issuer, target, certificationMap);
    }

    private CertificationSet(CertSynopsis issuer,
                             CertSynopsis target,
                             Map<Optional<String>, List<Certification>> certifications) {
        this.issuer = issuer;
        this.target = target;
        this.certifications = new HashMap<>(certifications);
    }

    public void merge(CertificationSet other) {
        if (!issuer.getFingerprint().equals(other.issuer.getFingerprint())) {
            throw new IllegalArgumentException("Issuer fingerprint mismatch.");
        }
        if (!target.getFingerprint().equals(other.target.getFingerprint())) {
            throw new IllegalArgumentException("Target fingerprint mismatch.");
        }

        for (Map.Entry<Optional<String>, List<Certification>> entry : other.certifications.entrySet()) {
            for (Certification certification : entry.getValue()) {
                add(certification);
            }
        }
    }

    public void add(Certification certification) {
        if (!issuer.getFingerprint().equals(certification.getIssuer().getFingerprint())) {
            throw new IllegalArgumentException("Issuer fingerprint mismatch.");
        }
        if (!target.getFingerprint().equals(certification.getTarget().getFingerprint())) {
            throw new IllegalArgumentException("Target fingerprint mismatch.");
        }

        List<Certification> certificationsForUserId = certifications.get(certification.getUserId());
        if (certificationsForUserId == null) {
            certificationsForUserId = new ArrayList<>();
            certifications.put(certification.getUserId(), certificationsForUserId);
        }
        // TODO: Prevent duplicates, only keep newest timestamped sig?
        certificationsForUserId.add(certification);
    }
}
