/*
 * Created on 6/05/2006
 *
 * To change the template for this generated file go to
 * Window&gt;Preferences&gt;Java&gt;Code Generation&gt;Code and Comments
 */
package bwmorg.bouncycastle.crypto.test;


import bwmorg.bouncycastle.crypto.ExtendedDigest;
import bwmorg.bouncycastle.crypto.digests.*;
import bwmorg.bouncycastle.util.test.SimpleTest;

public class ShortenedDigestTest
    extends SimpleTest
{
    public void performTest()
    {
        ExtendedDigest  d = new SHA1Digest();
        ShortenedDigest sd = new ShortenedDigest(new SHA1Digest(), 10);
        
        if (sd.getDigestSize() != 10)
        {
            fail("size check wrong for SHA-1");
        }
        
        if (sd.getByteLength() != d.getByteLength())
        {
            fail("byte length check wrong for SHA-1");
        }
        
        //
        // check output fits
        //
        sd.doFinal(new byte[10], 0);
        
        d = new SHA512Digest();
        sd = new ShortenedDigest(new SHA512Digest(), 20);
        
        if (sd.getDigestSize() != 20)
        {
            fail("size check wrong for SHA-512");
        }
        
        if (sd.getByteLength() != d.getByteLength())
        {
            fail("byte length check wrong for SHA-512");
        }
        
        //
        // check output fits
        //
        sd.doFinal(new byte[20], 0);
        
        try
        {
            new ShortenedDigest(null, 20);
            
            fail("null parameter not caught");
        }
        catch (IllegalArgumentException e)
        {
            // expected
        }
        
        try
        {
            new ShortenedDigest(new SHA1Digest(), 50);
            
            fail("short digest not caught");
        }
        catch (IllegalArgumentException e)
        {
            // expected
        }
    }
    
    public String getName()
    {
        return "ShortenedDigest";
    }

    public static void main(
        String[]    args)
    {
        runTest(new ShortenedDigestTest());
    }
}
