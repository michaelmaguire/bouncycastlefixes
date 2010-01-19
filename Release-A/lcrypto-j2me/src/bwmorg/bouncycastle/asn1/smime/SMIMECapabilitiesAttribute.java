package bwmorg.bouncycastle.asn1.smime;

import bwmorg.bouncycastle.asn1.DERSet;
import bwmorg.bouncycastle.asn1.DERSequence;
import bwmorg.bouncycastle.asn1.cms.Attribute;

public class SMIMECapabilitiesAttribute
    extends Attribute
{
    public SMIMECapabilitiesAttribute(
        SMIMECapabilityVector capabilities)
    {
        super(SMIMEAttributes.smimeCapabilities,
                new DERSet(new DERSequence(capabilities.toDEREncodableVector())));
    }
}
