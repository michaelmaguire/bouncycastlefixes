package bwmorg.bouncycastle.crypto.params;

import bigjava.security.SecureRandom;

import bwmorg.bouncycastle.crypto.KeyGenerationParameters;

public class ElGamalKeyGenerationParameters
    extends KeyGenerationParameters
{
    private ElGamalParameters    params;

    public ElGamalKeyGenerationParameters(
        SecureRandom        random,
        ElGamalParameters   params)
    {
        super(random, params.getP().bitLength());

        this.params = params;
    }

    public ElGamalParameters getParameters()
    {
        return params;
    }
}
