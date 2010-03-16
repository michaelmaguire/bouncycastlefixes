package bwmorg.bouncycastle.asn1.x9;


import bwmorg.bouncycastle.asn1.*;
import bwmorg.bouncycastle.math.ec.*;


/**
 * class for describing an ECPoint as a DER object.
 */
public class X9ECPoint
    extends ASN1Encodable
{
    ECPoint p;

    public X9ECPoint(
        ECPoint p)
    {
        this.p = p;
    }

    public X9ECPoint(
        ECCurve          c,
        ASN1OctetString  s)
    {
        this.p = c.decodePoint(s.getOctets());
    }

    public ECPoint getPoint()
    {
        return p;
    }

    /**
     * Produce an object suitable for an ASN1OutputStream.
     * <pre>
     *  ECPoint ::= OCTET STRING
     * </pre>
     * <p>
     * Octet string produced using ECPoint.getEncoded().
     */
    public DERObject toASN1Object()
    {
        return new DEROctetString(p.getEncoded());
    }
}
