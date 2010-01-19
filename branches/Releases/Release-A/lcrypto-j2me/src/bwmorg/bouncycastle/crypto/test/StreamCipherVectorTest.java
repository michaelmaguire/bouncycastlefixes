package bwmorg.bouncycastle.crypto.test;

import bwmorg.bouncycastle.crypto.CipherParameters;
import bwmorg.bouncycastle.crypto.StreamCipher;
import bwmorg.bouncycastle.util.encoders.Hex;
import bwmorg.bouncycastle.util.test.SimpleTest;

/**
 * a basic test that takes a stream cipher, key parameter, and an input
 * and output string.
 */
public class StreamCipherVectorTest
    extends SimpleTest
{
    int                 id;
    StreamCipher        cipher;
    CipherParameters    param;
    byte[]              input;
    byte[]              output;

    public StreamCipherVectorTest(
        int                 id,
        StreamCipher        cipher,
        CipherParameters    param,
        String              input,
        String              output)
    {
        this.id = id;
        this.cipher = cipher;
        this.param = param;
        this.input = Hex.decode(input);
        this.output = Hex.decode(output);
    }

    public String getName()
    {
        return cipher.getAlgorithmName() + " Vector Test " + id;
    }

    public void performTest()
    {
        cipher.init(true, param);

        byte[]  out = new byte[input.length];

        cipher.processBytes(input, 0, input.length, out, 0);

        if (!areEqual(out, output))
        {
            fail("failed.", new String(Hex.encode(output)) , new String(Hex.encode(out)));
        }

        cipher.init(false, param);

        cipher.processBytes(output, 0, output.length, out, 0);

        if (!areEqual(input, out))
        {
            fail("failed reversal");
        }
    }
}
