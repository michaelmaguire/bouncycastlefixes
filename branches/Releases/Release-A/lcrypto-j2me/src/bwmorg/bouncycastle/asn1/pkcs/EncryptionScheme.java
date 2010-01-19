package bwmorg.bouncycastle.asn1.pkcs;

import bwmorg.bouncycastle.asn1.ASN1EncodableVector;
import bwmorg.bouncycastle.asn1.ASN1Sequence;
import bwmorg.bouncycastle.asn1.DERObject;
import bwmorg.bouncycastle.asn1.DERSequence;
import bwmorg.bouncycastle.asn1.x509.AlgorithmIdentifier;

public class EncryptionScheme
    extends AlgorithmIdentifier
{   
    DERObject   objectId;
    DERObject   obj;

    EncryptionScheme(
        ASN1Sequence  seq)
    {   
        super(seq);
        
        objectId = (DERObject)seq.getObjectAt(0);
        obj = (DERObject)seq.getObjectAt(1);
    }

    public DERObject getObject()
    {
        return obj;
    }

    public DERObject getDERObject()
    {
        ASN1EncodableVector  v = new ASN1EncodableVector();

        v.add(objectId);
        v.add(obj);

        return new DERSequence(v);
    }
}
