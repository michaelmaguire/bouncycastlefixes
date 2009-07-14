package bwmorg.bouncycastle.crypto.generators;

import bigjava.math.BigInteger;
import bigjava.security.SecureRandom;

import bwmorg.bouncycastle.crypto.AsymmetricCipherKeyPair;
import bwmorg.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import bwmorg.bouncycastle.crypto.KeyGenerationParameters;
import bwmorg.bouncycastle.crypto.params.ECDomainParameters;
import bwmorg.bouncycastle.crypto.params.ECKeyGenerationParameters;
import bwmorg.bouncycastle.crypto.params.ECPrivateKeyParameters;
import bwmorg.bouncycastle.crypto.params.ECPublicKeyParameters;
import bwmorg.bouncycastle.math.ec.ECConstants;
import bwmorg.bouncycastle.math.ec.ECPoint;

public class ECKeyPairGenerator
    implements AsymmetricCipherKeyPairGenerator, ECConstants
{
    ECDomainParameters  params;
    SecureRandom        random;

    public void init(
        KeyGenerationParameters param)
    {
        ECKeyGenerationParameters  ecP = (ECKeyGenerationParameters)param;

        this.random = ecP.getRandom();
        this.params = ecP.getDomainParameters();
    }

    /**
     * Given the domain parameters this routine generates an EC key
     * pair in accordance with X9.62 section 5.2.1 pages 26, 27.
     */
    public AsymmetricCipherKeyPair generateKeyPair()
    {
        BigInteger n = params.getN();
        int        nBitLength = n.bitLength();
        BigInteger d;

        do
        {
            d = new BigInteger(nBitLength, random);
        }
        while (d.equals(ZERO)  || (d.compareTo(n) >= 0));

        ECPoint Q = params.getG().multiply(d);

        return new AsymmetricCipherKeyPair(
            new ECPublicKeyParameters(Q, params),
            new ECPrivateKeyParameters(d, params));
    }
}
