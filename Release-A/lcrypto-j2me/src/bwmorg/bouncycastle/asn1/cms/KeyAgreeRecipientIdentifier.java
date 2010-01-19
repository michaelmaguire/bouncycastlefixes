package bwmorg.bouncycastle.asn1.cms;

import bwmorg.bouncycastle.asn1.ASN1Encodable;
import bwmorg.bouncycastle.asn1.ASN1Sequence;
import bwmorg.bouncycastle.asn1.ASN1TaggedObject;
import bwmorg.bouncycastle.asn1.DERObject;
import bwmorg.bouncycastle.asn1.DERTaggedObject;


public class KeyAgreeRecipientIdentifier
    extends ASN1Encodable
{
    private IssuerAndSerialNumber issuerSerial;
    private RecipientKeyIdentifier rKeyID;
    
    private KeyAgreeRecipientIdentifier(
        ASN1Sequence seq)
    {
        issuerSerial = IssuerAndSerialNumber.getInstance(seq);
        rKeyID = null;
    }
    
    /**
     * return an KeyAgreeRecipientIdentifier object from a tagged object.
     *
     * @param obj the tagged object holding the object we want.
     * @param explicit true if the object is meant to be explicitly
     *              tagged false otherwise.
     * @exception IllegalArgumentException if the object held by the
     *          tagged object cannot be converted.
     */
    public static KeyAgreeRecipientIdentifier getInstance(
        ASN1TaggedObject    obj,
        boolean             explicit)
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }
    
    /**
     * return an KeyAgreeRecipientIdentifier object from the given object.
     *
     * @param obj the object we want converted.
     * @exception IllegalArgumentException if the object cannot be converted.
     */
    public static KeyAgreeRecipientIdentifier getInstance(
        Object obj)
    {
        if (obj == null || obj instanceof KeyAgreeRecipientIdentifier)
        {
            return (KeyAgreeRecipientIdentifier)obj;
        }
        
        if (obj instanceof ASN1Sequence)
        {
            return new KeyAgreeRecipientIdentifier((ASN1Sequence)obj);
        }
        
        throw new IllegalArgumentException("Invalid KeyAgreeRecipientIdentifier: " + obj.getClass().getName());
    } 

    public IssuerAndSerialNumber getIssuerAndSerialNumber()
    {
        return issuerSerial;
    }

    public RecipientKeyIdentifier getRKeyID()
    {
        return rKeyID;
    }

    /** 
     * Produce an object suitable for an ASN1OutputStream.
     * <pre>
     * KeyAgreeRecipientIdentifier ::= SEQUENCE {
     *     issuerAndSerialNumber IssuerAndSerialNumber,
     *     rKeyId [0] IMPLICIT RecipientKeyIdentifier
     * }
     * </pre>
     */
    public DERObject toASN1Object()
    {
        if (issuerSerial != null)
        {
            return issuerSerial.toASN1Object();
        }

        return new DERTaggedObject(false, 0, rKeyID);
    }
}
