package bwmorg.bouncycastle.crypto.generators;

import bwmorg.bouncycastle.crypto.AsymmetricCipherKeyPair;
import bwmorg.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import bwmorg.bouncycastle.crypto.KeyGenerationParameters;
import bwmorg.bouncycastle.crypto.params.DSAKeyGenerationParameters;
import bwmorg.bouncycastle.crypto.params.DSAParameters;
import bwmorg.bouncycastle.crypto.params.DSAPrivateKeyParameters;
import bwmorg.bouncycastle.crypto.params.DSAPublicKeyParameters;

import bigjava.math.BigInteger;
import bigjava.security.SecureRandom;

/**
 * a DSA key pair generator.
 *
 * This generates DSA keys in line with the method described 
 * in FIPS 186-2.
 */
public class DSAKeyPairGenerator
    implements AsymmetricCipherKeyPairGenerator
{
    private static final BigInteger ZERO = BigInteger.valueOf(0);

    private DSAKeyGenerationParameters param;

    public void init(
        KeyGenerationParameters param)
    {
        this.param = (DSAKeyGenerationParameters)param;
    }

    public AsymmetricCipherKeyPair generateKeyPair()
    {
        BigInteger      p, q, g, x, y;
        DSAParameters   dsaParams = param.getParameters();
        SecureRandom    random = param.getRandom();

        q = dsaParams.getQ();
        p = dsaParams.getP();
        g = dsaParams.getG();

        do
        {
            x = new BigInteger(160, random);
        }
        while (x.equals(ZERO)  || x.compareTo(q) >= 0);

        //
        // calculate the public key.
        //
        y = g.modPow(x, p);

        return new AsymmetricCipherKeyPair(
                new DSAPublicKeyParameters(y, dsaParams),
                new DSAPrivateKeyParameters(x, dsaParams));
    }
}
