package bwmorg.bouncycastle.crypto.tls;

import bwmorg.bouncycastle.crypto.digests.SHA1Digest;
import bwmorg.bouncycastle.crypto.signers.*;

class TlsDSSSigner
    extends DSADigestSigner
{
    TlsDSSSigner()
    {
        super(new DSASigner(), new SHA1Digest());
    }
}
