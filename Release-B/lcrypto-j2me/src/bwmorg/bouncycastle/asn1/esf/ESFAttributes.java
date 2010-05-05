package bwmorg.bouncycastle.asn1.esf;

import bwmorg.bouncycastle.asn1.DERObjectIdentifier;
import bwmorg.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;

public interface ESFAttributes
{
    public static final DERObjectIdentifier  sigPolicyId = PKCSObjectIdentifiers.id_aa_sigPolicyId;
    public static final DERObjectIdentifier  commitmentType = PKCSObjectIdentifiers.id_aa_commitmentType;
    public static final DERObjectIdentifier  signerLocation = PKCSObjectIdentifiers.id_aa_signerLocation;
}
