package bwmorg.bouncycastle.crypto.tls;

import java.io.IOException;
import java.io.InputStream;

/**
 * An InputStream for an TLS 1.0 connection.
 */
public class TlsInputStream
    extends InputStream
{
    private TlsProtocolHandler handler = null;

    protected TlsInputStream( TlsProtocolHandler handler )
    {
        this.handler = handler;
    }

    public int read(byte[] buf, int offset, int len)
        throws IOException
    {
        return this.handler.readApplicationData( buf, offset, len );
    }

    public int read()
        throws IOException
    {
        byte[] buf = new byte[1];
        if( this.read( buf ) < 0 )
        {
            return -1;
        }

        /**
         * BlueWhaleSystems fix: Michael Maguire - 23 Apr 2008
         *
         * Properly promote signed byte to int.
         */
        return 0xFF & buf[0];
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
