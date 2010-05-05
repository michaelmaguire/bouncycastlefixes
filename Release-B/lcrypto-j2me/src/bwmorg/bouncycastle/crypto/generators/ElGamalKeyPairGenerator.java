package bwmorg.bouncycastle.crypto.generators;

import bigjava.math.BigInteger;

import bwmorg.bouncycastle.crypto.AsymmetricCipherKeyPair;
import bwmorg.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import bwmorg.bouncycastle.crypto.KeyGenerationParameters;
import bwmorg.bouncycastle.crypto.params.ElGamalKeyGenerationParameters;
import bwmorg.bouncycastle.crypto.params.ElGamalParameters;
import bwmorg.bouncycastle.crypto.params.ElGamalPrivateKeyParameters;
import bwmorg.bouncycastle.crypto.params.ElGamalPublicKeyParameters;

/**
 * a ElGamal key pair generator.
 * <p>
 * This generates keys consistent for use with ElGamal as described in
 * page 164 of "Handbook of Applied Cryptography".
 */
public class ElGamalKeyPairGenerator
    implements AsymmetricCipherKeyPairGenerator
{
    private DHKeyGeneratorHelper helper = DHKeyGeneratorHelper.INSTANCE;
    
    private ElGamalKeyGenerationParameters param;

    public void init(
        KeyGenerationParameters param)
    {
        this.param = (ElGamalKeyGenerationParameters)param;
    }

    public AsymmetricCipherKeyPair generateKeyPair()
    {
        BigInteger           p, x, y;
        ElGamalParameters    elParams = param.getParameters();

        p = elParams.getP();
 
        x = helper.calculatePrivate(p, param.getRandom(), elParams.getL()); 
        y = helper.calculatePublic(p, elParams.getG(), x);

        return new AsymmetricCipherKeyPair(
                new ElGamalPublicKeyParameters(y, elParams),
                new ElGamalPrivateKeyParameters(x, elParams));
    }
}
