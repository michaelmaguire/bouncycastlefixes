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
        super(random, params.getP().bitLength());

        this.params = params;
    }

    public DHParameters getParameters()
    {
        return params;
    }
}
