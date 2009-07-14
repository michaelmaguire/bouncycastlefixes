package org.bouncycastle.crypto.tls;

import java.io.IOException;
import java.io.OutputStream;

/**
 * An OutputStream for an TLS connection.
 */
public class TlsOuputStream extends OutputStream
{
    /**
     * BlueWhaleSystems fix: Tatiana Rybak - 02 July 2007
     * 
     * Added buffering to TLSOutputStream
     */
    private static final int   GROW_SIZE = 256;
    private static final int   NEW_SIZE  = 1024;
    private byte[]             bufferedData;
    private int                size;
    private int                position;

    private TlsProtocolHandler handler;

    protected TlsOuputStream( TlsProtocolHandler handler )
    {
        this.handler = handler;

        /**
         * BlueWhaleSystems fix: Tatiana Rybak - 02 July 2007
         * 
         * Added buffering to TLSOutputStream
         */
        size = GROW_SIZE;
        position = 0;
        this.bufferedData = new byte[NEW_SIZE];
    }

    public void write( byte buf[], int offset, int len ) throws IOException
    {
        // DO NOT write the data immediately! TLS will encode the data and send it right away.
        // For 1 byte of data it would send 37 bytes. Instead, accumulate until there is a flush call.
        // Original code:
        // this.handler.writeData(buf, offset, len);

        /**
         * BlueWhaleSystems fix: Tatiana Rybak - 02 July 2007
         * 
         * Added buffering to TLSOutputStream
         */
        // check that we have enough room to write out the data
        int available = size - position;
        if( available < len )
        {
            int growBy = Math.max( len, GROW_SIZE );
            byte[] newArray = new byte[size + growBy];
            System.arraycopy( bufferedData, 0, newArray, 0, position );
            bufferedData = newArray;
            size += growBy;
        }

        System.arraycopy( buf, 0, bufferedData, position, len );
        position += len;

    }

    public void write( int arg0 ) throws IOException
    {
        /**
         * BlueWhaleSystems fix: Tatiana Rybak - 02 July 2007
         * 
         * Added buffering to TLSOutputStream
         */
        // if there is no more room, grow the buffer 
        if( size == position )
        {
            byte[] newArray = new byte[size + GROW_SIZE];
            System.arraycopy( bufferedData, 0, newArray, 0, position );
            bufferedData = newArray;
            size += GROW_SIZE;
        }
        bufferedData[position] = (byte) arg0;
        position++;

        // Original code:
        //byte[] buf = new byte[1];
        //buf[0] = (byte) arg0;
        //this.write( buf, 0, 1 );
    }

    /**
     * BlueWhaleSystems fix: Tatiana Rybak - 25 June 2007
     * 
     * Fixed typo cose to be close.
     */
    public void close() throws IOException
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

    public void flush() throws IOException
    {
        /**
         * BlueWhaleSystems fix: Tatiana Rybak - 02 July 2007
         * 
         * Added buffering to TLSOutputStream
         */
        // write out the data we have accumulated so far
        this.handler.writeData( bufferedData, 0, position );
        handler.flush();

        // reset the buffer
        size = NEW_SIZE;
        position = 0;
        this.bufferedData = new byte[size];
    }
}
