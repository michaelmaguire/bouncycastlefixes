package bwmorg.bouncycastle.crypto.macs;

import java.util.Hashtable;

import bwmorg.bouncycastle.crypto.CipherParameters;
import bwmorg.bouncycastle.crypto.Digest;
import bwmorg.bouncycastle.crypto.ExtendedDigest;
import bwmorg.bouncycastle.crypto.Mac;
import bwmorg.bouncycastle.crypto.params.KeyParameter;

/**
 * HMAC implementation based on RFC2104
 *
 * H(K XOR opad, H(K XOR ipad, text))
 */
public class HMac
    implements Mac
{
    private final static byte IPAD = (byte)0x36;
    private final static byte OPAD = (byte)0x5C;

    private Digest digest;
    private int digestSize;
    private int blockLength;
    
    private byte[] inputPad;
    private byte[] outputPad;

    /**
     * BlueWhaleSystems fix: Ramesh Nair - 04 Dec 2007 
     * 
     * Got rid of the static initializer block as it won't get called  
     * if the code is running within a Java applet and the browser page 
     * containing the applet is refreshed.
     */
    private Hashtable blockLengths = null;
    
    /**
     * BlueWhaleSystems fix: Ramesh Nair - 04 Dec 2007 
     * 
     * Got rid of the static initializer block as it won't get called  
     * if the code is running within a Java applet and the browser page 
     * containing the applet is refreshed.
     */
    private Hashtable getBlockLengths()
    {
        if (null == blockLengths)
        {
            blockLengths = new Hashtable();
            
            blockLengths.put("GOST3411", new Integer(32));
            
            blockLengths.put("MD2", new Integer(16));
            blockLengths.put("MD4", new Integer(64));
            blockLengths.put("MD5", new Integer(64));
            
            blockLengths.put("RIPEMD128", new Integer(64));
            blockLengths.put("RIPEMD160", new Integer(64));
            
            blockLengths.put("SHA-1", new Integer(64));
            blockLengths.put("SHA-224", new Integer(64));
            blockLengths.put("SHA-256", new Integer(64));
            blockLengths.put("SHA-384", new Integer(128));
            blockLengths.put("SHA-512", new Integer(128));
            
            blockLengths.put("Tiger", new Integer(64));
            blockLengths.put("Whirlpool", new Integer(64));
        }
        
        return blockLengths;
    }
    
    /**
     * BlueWhaleSystems fix: Ramesh Nair - 04 Dec 2007 
     * 
     * Got rid of the static initializer block as it won't get called  
     * if the code is running within a Java applet and the browser page 
     * containing the applet is refreshed.
     */
    private int getByteLength(
        Digest digest)
    {
        if (digest instanceof ExtendedDigest)
        {
            return ((ExtendedDigest)digest).getByteLength();
        }
        
	    /**
	     * BlueWhaleSystems fix: Ramesh Nair - 04 Dec 2007 
	     * 
	     * Got rid of the static initializer block as it won't get called  
	     * if the code is running within a Java applet and the browser page 
    	 * containing the applet is refreshed.
	     */
        Integer  b = (Integer)getBlockLengths().get(digest.getAlgorithmName());
        
        if (b == null)
        {       
            throw new IllegalArgumentException("unknown digest passed: " + digest.getAlgorithmName());
        }
        
        return b.intValue();
    }
    
    /**
     * Base constructor for one of the standard digest algorithms that the 
     * byteLength of the algorithm is know for.
     * 
     * @param digest the digest.
     */
    public HMac(
        Digest digest)
    {
	    /**
	     * BlueWhaleSystems fix: Ramesh Nair - 04 Dec 2007 
	     * 
	     * Got rid of the static initializer block as it won't get called  
	     * if the code is running within a Java applet and the browser page 
	     * containing the applet is refreshed.
	     */
        init(digest, getByteLength(digest));
    }

    /**
     * BlueWhaleSystems fix: Ramesh Nair - 04 Dec 2007 
     * 
     * Got rid of the static initializer block as it won't get called  
     * if the code is running within a Java applet and the browser page 
     * containing the applet is refreshed.
     */
    private void init(
        Digest digest,
        int    byteLength)
    {
        this.digest = digest;
        digestSize = digest.getDigestSize();

        this.blockLength = byteLength;

        inputPad = new byte[blockLength];
        outputPad = new byte[blockLength];
    }
    
    public String getAlgorithmName()
    {
        return digest.getAlgorithmName() + "/HMAC";
    }

    public Digest getUnderlyingDigest()
    {
        return digest;
    }

    public void init(
        CipherParameters params)
    {
        digest.reset();

        byte[] key = ((KeyParameter)params).getKey();

        if (key.length > blockLength)
        {
            digest.update(key, 0, key.length);
            digest.doFinal(inputPad, 0);
            for (int i = digestSize; i < inputPad.length; i++)
            {
                inputPad[i] = 0;
            }
        }
        else
        {
            System.arraycopy(key, 0, inputPad, 0, key.length);
            for (int i = key.length; i < inputPad.length; i++)
            {
                inputPad[i] = 0;
            }
        }

        outputPad = new byte[inputPad.length];
        System.arraycopy(inputPad, 0, outputPad, 0, inputPad.length);

        for (int i = 0; i < inputPad.length; i++)
        {
            inputPad[i] ^= IPAD;
        }

        for (int i = 0; i < outputPad.length; i++)
        {
            outputPad[i] ^= OPAD;
        }

        digest.update(inputPad, 0, inputPad.length);
    }

    public int getMacSize()
    {
        return digestSize;
    }

    public void update(
        byte in)
    {
        digest.update(in);
    }

    public void update(
        byte[] in,
        int inOff,
        int len)
    {
        digest.update(in, inOff, len);
    }

    public int doFinal(
        byte[] out,
        int outOff)
    {
        byte[] tmp = new byte[digestSize];
        digest.doFinal(tmp, 0);

        digest.update(outputPad, 0, outputPad.length);
        digest.update(tmp, 0, tmp.length);

        int     len = digest.doFinal(out, outOff);

        reset();

        return len;
    }

    /**
     * Reset the mac generator.
     */
    public void reset()
    {
        /*
         * reset the underlying digest.
         */
        digest.reset();

        /*
         * reinitialize the digest.
         */
        digest.update(inputPad, 0, inputPad.length);
    }
}
