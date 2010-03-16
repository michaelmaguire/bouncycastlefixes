package bwmorg.bouncycastle.asn1.pkcs;

import bwmorg.bouncycastle.asn1.*;
import bwmorg.bouncycastle.asn1.x509.AlgorithmIdentifier;


public class KeyDerivationFunc
    extends AlgorithmIdentifier
{
    KeyDerivationFunc(
        ASN1Sequence  seq)
    {
        super(seq);
    }
    
    KeyDerivationFunc(
        DERObjectIdentifier id,
        ASN1Encodable       params)
    {
        super(id, params);
    }
}
