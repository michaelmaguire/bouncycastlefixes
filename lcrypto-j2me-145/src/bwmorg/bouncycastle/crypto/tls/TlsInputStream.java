package bwmorg.bouncycastle.crypto.tls;

import java.io.*;

/**
 * An InputStream for an TLS 1.0 connection.
 */
public class TlsInputStream
    extends InputStream
{
    private byte[] buf = new byte[1];
    private TlsProtocolHandler handler = null;

    TlsInputStream (TlsProtocolHandler handler)
    {
        this.handler = handler;
    }

    public int read(byte[] buf, int offset, int len)
        throws IOException
    {
        return this.handler.readApplicationData(buf, offset, len);
    }
    
    public int read()
        throws IOException
    {
        if (this.read(buf) < 0)
        {
            return -1;
        }
        return buf[0] & 0xff;
    }
    
    public void close()
        throws IOException
    {
       /**
        * BlueWhaleSystems fix: Michael Maguire - 10 Aug 2007
        *
        * Make sure we null out on close.
        */
       try
       {
           handler.close();
       }
       finally
       {
           handler = null;
       }
    }
    
    /**
     * BlueWhaleSystems fix: Tatiana Rybak - 02 Mar 2007
     * 
     * Added a method to return available bytes in the data stream.
     */
    public int available() throws IOException {

        try {
            return this.handler.availableData();
        } catch (Exception e) {         
            e.printStackTrace();
            throw new IOException();
        }

    }
}
