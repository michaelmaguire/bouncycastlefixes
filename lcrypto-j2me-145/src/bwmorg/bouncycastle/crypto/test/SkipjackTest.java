package bwmorg.bouncycastle.crypto.test;


import bwmorg.bouncycastle.crypto.engines.SkipjackEngine;
import bwmorg.bouncycastle.crypto.params.KeyParameter;
import bwmorg.bouncycastle.util.encoders.Hex;
import bwmorg.bouncycastle.util.test.SimpleTest;

/**
 */
public class SkipjackTest
    extends CipherTest
{
    static SimpleTest[]  tests = 
            {
                new BlockCipherVectorTest(0, new SkipjackEngine(),
                        new KeyParameter(Hex.decode("00998877665544332211")),
                        "33221100ddccbbaa", "2587cae27a12d300")
            };

    SkipjackTest()
    {
        super(tests, new SkipjackEngine(), new KeyParameter(Hex.decode("00998877665544332211")));
    }

    public String getName()
    {
        return "SKIPJACK";
    }

    public static void main(
        String[]    args)
    {
        runTest(new SkipjackTest());
    }
}
