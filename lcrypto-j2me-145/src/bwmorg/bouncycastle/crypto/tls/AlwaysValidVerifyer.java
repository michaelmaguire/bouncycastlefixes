package bwmorg.bouncycastle.crypto.tls;

import bwmorg.bouncycastle.asn1.x509.X509CertificateStructure;

/**
 * A certificate verifyer, that will always return true.
 * <pre>
 * DO NOT USE THIS FILE UNLESS YOU KNOW EXACTLY WHAT YOU ARE DOING.
 * </pre>
 */
public class AlwaysValidVerifyer implements CertificateVerifyer
{

    /**
     * Return true.
     *
     * @see bwmorg.bouncycastle.crypto.tls.CertificateVerifyer#isValid(bwmorg.bouncycastle.asn1.x509.X509CertificateStructure[])
     */
    public boolean isValid(X509CertificateStructure[] certs)
    {
        return true;
    }

}
