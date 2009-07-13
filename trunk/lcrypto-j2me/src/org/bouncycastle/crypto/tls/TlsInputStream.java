package org.bouncycastle.crypto.tls;

import java.io.IOException;
import java.io.InputStream;

/**
 * An InputStream for an TLS 1.0 connection.
 */
public class TlsInputStream
    extends InputStream
{
    private TlsProtocolHandler handler = null;
    
    protected TlsInputStream (TlsProtocolHandler handler)
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
        byte[] buf = new byte[1];
        if (this.read(buf) < 0)
        {
            return -1;
        }
        return buf[0];
    }
    
    public void close()
        throws IOException
    {
        handler.close();
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
