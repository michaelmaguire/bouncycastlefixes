package bwmorg.bouncycastle.crypto.generators;

import bigjava.math.BigInteger;

import bwmorg.bouncycastle.crypto.AsymmetricCipherKeyPair;
import bwmorg.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import bwmorg.bouncycastle.crypto.KeyGenerationParameters;
import bwmorg.bouncycastle.crypto.params.DHKeyGenerationParameters;
import bwmorg.bouncycastle.crypto.params.DHParameters;
import bwmorg.bouncycastle.crypto.params.DHPrivateKeyParameters;
import bwmorg.bouncycastle.crypto.params.DHPublicKeyParameters;

/**
 * a basic Diffie-Helman key pair generator.
 *
 * This generates keys consistent for use with the basic algorithm for
 * Diffie-Helman.
 */
public class DHBasicKeyPairGenerator
    implements AsymmetricCipherKeyPairGenerator
{
    private DHKeyGeneratorHelper helper = DHKeyGeneratorHelper.INSTANCE;
    private DHKeyGenerationParameters param;

    public void init(
        KeyGenerationParameters param)
    {
        this.param = (DHKeyGenerationParameters)param;
    }

    public AsymmetricCipherKeyPair generateKeyPair()
    {
        BigInteger      p, x, y;
        DHParameters    dhParams = param.getParameters();

        p = dhParams.getP();
        x = helper.calculatePrivate(p, param.getRandom(), dhParams.getJ()); 
        y = helper.calculatePublic(p, dhParams.getG(), x);

        return new AsymmetricCipherKeyPair(
                new DHPublicKeyParameters(y, dhParams),
                new DHPrivateKeyParameters(x, dhParams));
    }
}
