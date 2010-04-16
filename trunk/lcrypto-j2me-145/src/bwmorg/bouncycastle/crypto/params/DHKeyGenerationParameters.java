package bwmorg.bouncycastle.crypto.params;



import bigjava.security.SecureRandom;
import bwmorg.bouncycastle.crypto.KeyGenerationParameters;

public class DHKeyGenerationParameters
    extends KeyGenerationParameters
{
    private DHParameters    params;

    public DHKeyGenerationParameters(
        SecureRandom    random,
        DHParameters    params)
    {
        super(random, getStrength(params));

        this.params = params;
    }

    public DHParameters getParameters()
    {
        return params;
    }

    static int getStrength(DHParameters params)
    {
        return params.getL() != 0 ? params.getL() : params.getP().bitLength();
    }
}