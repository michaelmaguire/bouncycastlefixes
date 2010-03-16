package bwmorg.bouncycastle.crypto.tls;

import bwmorg.bouncycastle.crypto.encodings.PKCS1Encoding;
import bwmorg.bouncycastle.crypto.engines.RSABlindedEngine;
import bwmorg.bouncycastle.crypto.signers.GenericSigner;

class TlsRSASigner
    extends GenericSigner
{
    TlsRSASigner()
    {
        super(new PKCS1Encoding(new RSABlindedEngine()), new CombinedHash());
    }
}
