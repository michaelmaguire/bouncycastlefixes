package bwmorg.bouncycastle.crypto.test;

import bwmorg.bouncycastle.crypto.BlockCipher;
import bwmorg.bouncycastle.crypto.engines.DESEngine;
import bwmorg.bouncycastle.crypto.modes.CFBBlockCipher;
import bwmorg.bouncycastle.crypto.modes.OFBBlockCipher;
import bwmorg.bouncycastle.crypto.params.KeyParameter;
import bwmorg.bouncycastle.crypto.params.ParametersWithIV;
import bwmorg.bouncycastle.util.encoders.Hex;
import bwmorg.bouncycastle.util.test.SimpleTestResult;
import bwmorg.bouncycastle.util.test.Test;
import bwmorg.bouncycastle.util.test.TestResult;

/**
 * CFB/OFB Mode test of IV padding.
 */
public class ModeTest
    implements Test
{
    public ModeTest()
    {
    }

    private boolean isEqualTo(
        byte[]  a,
        byte[]  b)
    {
        for (int i = 0; i != a.length; i++)
        {
            if (a[i] != b[i])
            {
                return false;
            }
        }

        return true;
    }

    public TestResult perform()
    {
        KeyParameter    key = new KeyParameter(Hex.decode("0011223344556677"));
        byte[]          input = Hex.decode("4e6f7720");
        byte[]          out1 = new byte[4];
        byte[]          out2 = new byte[4];


        BlockCipher ofb = new OFBBlockCipher(new DESEngine(), 32);

        ofb.init(true, new ParametersWithIV(key, Hex.decode("1122334455667788")));

        ofb.processBlock(input, 0, out1, 0);

        ofb.init(false, new ParametersWithIV(key, Hex.decode("1122334455667788")));
        ofb.processBlock(out1, 0, out2, 0);

        if (!isEqualTo(out2, input))
        {
            return new SimpleTestResult(false, getName() + ": test 1 - in != out");
        }

        ofb.init(true, new ParametersWithIV(key, Hex.decode("11223344")));

        ofb.processBlock(input, 0, out1, 0);

        ofb.init(false, new ParametersWithIV(key, Hex.decode("0000000011223344")));
        ofb.processBlock(out1, 0, out2, 0);

        if (!isEqualTo(out2, input))
        {
            return new SimpleTestResult(false, getName() + ": test 2 - in != out");
        }

        BlockCipher cfb = new CFBBlockCipher(new DESEngine(), 32);

        cfb.init(true, new ParametersWithIV(key, Hex.decode("1122334455667788")));

        cfb.processBlock(input, 0, out1, 0);

        cfb.init(false, new ParametersWithIV(key, Hex.decode("1122334455667788")));
        cfb.processBlock(out1, 0, out2, 0);

        if (!isEqualTo(out2, input))
        {
            return new SimpleTestResult(false, getName() + ": test 3 - in != out");
        }

        cfb.init(true, new ParametersWithIV(key, Hex.decode("11223344")));

        cfb.processBlock(input, 0, out1, 0);

        cfb.init(false, new ParametersWithIV(key, Hex.decode("0000000011223344")));
        cfb.processBlock(out1, 0, out2, 0);

        if (!isEqualTo(out2, input))
        {
            return new SimpleTestResult(false, getName() + ": test 4 - in != out");
        }

        return new SimpleTestResult(true, getName() + ": Okay");
    }

    public String getName()
    {
        return "ModeTest";
    }

    public static void main(
        String[]    args)
    {
        ModeTest    test = new ModeTest();
        TestResult result = test.perform();

        System.out.println(result);
    }
}
