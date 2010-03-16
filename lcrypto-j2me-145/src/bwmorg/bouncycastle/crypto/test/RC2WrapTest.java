package bwmorg.bouncycastle.crypto.test;



import bigjava.security.SecureRandom;
import bwmorg.bouncycastle.crypto.*;
import bwmorg.bouncycastle.crypto.engines.RC2WrapEngine;
import bwmorg.bouncycastle.crypto.params.*;
import bwmorg.bouncycastle.util.Arrays;
import bwmorg.bouncycastle.util.encoders.Hex;
import bwmorg.bouncycastle.util.test.*;

/**
 * RC2 wrap tester
 */
public class RC2WrapTest
    implements Test
{
    private class RFCRandom
        extends SecureRandom
    {
        public void nextBytes(
            byte[] nextBytes)
        {
            System.arraycopy(Hex.decode("4845cce7fd1250"), 0, nextBytes, 0, nextBytes.length);
        }
    }
    
    private TestResult wrapTest(
        int     id,
        CipherParameters paramsWrap,
        CipherParameters paramsUnwrap,
        byte[]  in,
        byte[]  out)
    {
        Wrapper wrapper = new RC2WrapEngine();

        wrapper.init(true, paramsWrap);

        try
        {
            byte[]  cText = wrapper.wrap(in, 0, in.length);
            if (!Arrays.areEqual(cText, out))
            {
                return new SimpleTestResult(false, getName() + ": failed wrap test " + id  + " expected " + new String(Hex.encode(out)) + " got " + new String(Hex.encode(cText)));
            }
        }
        catch (Exception e)
        {
            return new SimpleTestResult(false, getName() + ": failed wrap test exception " + e.toString(), e);
        }

        wrapper.init(false, paramsUnwrap);

        try
        {
            byte[]  pText = wrapper.unwrap(out, 0, out.length);
            if (!Arrays.areEqual(pText, in))
            {
                return new SimpleTestResult(false, getName() + ": failed unwrap test " + id  + " expected " + new String(Hex.encode(in)) + " got " + new String(Hex.encode(pText)));
            }
        }
        catch (Exception e)
        {
            return new SimpleTestResult(false, getName() + ": failed unwrap test exception " + e.toString(), e);
        }

        return new SimpleTestResult(true, getName() + ": Okay");
    }

    public TestResult perform()
    {
        byte[]  kek1 = Hex.decode("fd04fd08060707fb0003fefffd02fe05");
        byte[]  iv1 = Hex.decode("c7d90059b29e97f7");
        byte[]  in1 = Hex.decode("b70a25fbc9d86a86050ce0d711ead4d9");
        byte[]  out1 = Hex.decode("70e699fb5701f7833330fb71e87c85a420bdc99af05d22af5a0e48d35f3138986cbaafb4b28d4f35");
        // 
        // note the RFC 3217 test specifies a key to be used with an effective key size of
        // 40 bits which is why it is done here - in practice nothing less than 128 bits should be used.
        //
        CipherParameters paramWrap = new ParametersWithRandom(new ParametersWithIV(new RC2Parameters(kek1, 40), iv1), new RFCRandom());
        CipherParameters paramUnwrap = new RC2Parameters(kek1, 40);
        
        TestResult result = wrapTest(1, paramWrap, paramUnwrap, in1, out1);
        
        if (!result.isSuccessful())
        {
            return result;
        }

        return new SimpleTestResult(true, getName() + ": Okay");
    }

    public String getName()
    {
        return "RC2Wrap";
    }

    public static void main(
        String[]    args)
    {
        RC2WrapTest test = new RC2WrapTest();
        TestResult result = test.perform();

        System.out.println(result);
    }
}
