package bwmorg.bouncycastle.bcpg;

import java.io.*;

/**
 * base class for a PGP object.
 */
public abstract class BCPGObject 
{
    public byte[] getEncoded() 
        throws IOException
    {
        ByteArrayOutputStream    bOut = new ByteArrayOutputStream();
        BCPGOutputStream         pOut = new BCPGOutputStream(bOut);
        
        pOut.writeObject(this);
        
        return bOut.toByteArray();
    }
    
    public abstract void encode(BCPGOutputStream out)
        throws IOException;
}
