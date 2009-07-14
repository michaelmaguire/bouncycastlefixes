package bwmorg.bouncycastle.crypto.tls;

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
    private static final int   DEFAULT_BUFFER_SIZE = 32768; // 32KB

    private final byte[]       bufferedData;
    private int                position;

    private TlsProtocolHandler handler;

    /**
     * BlueWhaleSystems fix: Tatiana Rybak - 07 Jan 2009
     *  
     * For testing only.
     *  
     **/
    public TlsOuputStream( TlsProtocolHandler handler, int size )
    {
        this.handler = handler;

        position = 0;
        bufferedData = new byte[size];
    }

    protected TlsOuputStream( TlsProtocolHandler handler )
    {
        this.handler = handler;

        /**
         * BlueWhaleSystems fix: Tatiana Rybak - 07 Jan 2009
         */
        position = 0;
        bufferedData = new byte[DEFAULT_BUFFER_SIZE];
    }

    public void write( byte buf[], int offset, int len ) throws IOException
    {
        /**
         * BlueWhaleSystems fix: Tatiana Rybak - 07 Jan 2009
         * 
         * 
         * The original code simply wrote the data out without any buffering in place. In the extreme case of
         * data length being 1 (a single byte being written out) the actual amount of data sent was 38 bytes,
         * i.e., there were 37 bytes added as a wrapper by the TLS logic.
         *
         * tickets: 572 BouncyCastle does not use buffering for outgoing data.
         * ticket:  2815 Client attachments: Attempting to send a message with an added attachment freezes 
         * UI for a long time (and doesn't appear to have sent anything).
         *
         * So, instead we have a 32 kb buffer that is written out conditionally. If the amount of data passed
         * in to this function exceeds the buffer size it is all written out immediately. If it fits in the
         * buffer is it cached until the next flush (or possibly write) operation.
         */

        // Original code:
        // this.handler.writeData(buf, offset, len);
        int available = bufferedData.length - position;
        if( available < len )
        {
            flush();

            if( bufferedData.length < len )
            {
                handler.writeData( buf, offset, len );
            }
            else
            {
                System.arraycopy( buf, offset, bufferedData, position, len );
                position += len;
            }
        }
        else
        {
            System.arraycopy( buf, offset, bufferedData, position, len );
            position += len;
        }
    }

    public void write( int arg0 ) throws IOException
    {
        /**
         * BlueWhaleSystems fix: Tatiana Rybak - 07 Jan 2009
         * 
         * See comments above in void write( byte buf[], int offset, int len ) throws IOException
         */

        if( bufferedData.length == position )
        {
            flush();
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
         * BlueWhaleSystems fix: Tatiana Rybak - 07 Jan 2009
         * 
         * See comments above in void write( byte buf[], int offset, int len ) throws IOException
         */
        handler.writeData( bufferedData, 0, position );
        handler.flush();
        position = 0;
    }
}
