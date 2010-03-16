package bwmorg.bouncycastle.crypto.tls;

import java.io.*;

/**
 * An implementation of the TLS 1.0 record layer.
 */
public class RecordStream
{

    private TlsProtocolHandler handler;
    private InputStream        is;
    private OutputStream       os;
    protected CombinedHash     hash1;
    protected CombinedHash     hash2;
    protected TlsCipherSuite   readSuite  = null;
    protected TlsCipherSuite   writeSuite = null;

    protected RecordStream( TlsProtocolHandler handler, InputStream is, OutputStream os )
    {
        this.handler = handler;
        this.is = is;
        this.os = os;
        hash1 = new CombinedHash();
        hash2 = new CombinedHash();
        this.readSuite = new TlsNullCipherSuite();
        this.writeSuite = this.readSuite;
    }

    public void readData() throws IOException
    {
        /**
         * BlueWhaleSystems fix: Tatiana Rybak - 18 Jul 2007
         *
         * Added debug statements for BouncyCastle.
         */
        //bwmorg.LOG.trace( "Tls RecordStream --> readData()." );
        short type = TlsUtils.readUint8( is );
        TlsUtils.checkVersion( is, handler );
        int size = TlsUtils.readUint16( is );

        byte[] buf = decodeAndVerify( type, is, size );
        handler.processData( type, buf, 0, buf.length );

        /**
         * BlueWhaleSystems fix: Tatiana Rybak - 18 Jul 2007
         *
         * Added debug statements for BouncyCastle.
         */
        //bwmorg.LOG.trace( "Tls RecordStream <-- done readData()" );
    }

    protected byte[] decodeAndVerify( short type, InputStream is, int len ) throws IOException
    {
        byte[] buf = new byte[len];
        TlsUtils.readFully( buf, is );
        byte[] result = readSuite.decodeCiphertext( type, buf, 0, buf.length, handler );
        return result;
    }

    protected void writeMessage( short type, byte[] message, int offset, int len ) throws IOException
    {
        /**
         * BlueWhaleSystems fix: Tatiana Rybak - 18 Jul 2007
         *
         * Added debug statements for BouncyCastle.
         */
        //bwmorg.LOG.trace( "Tls RecordStream --> writeMessage()." );
        if( type == 22 ) // TlsProtocolHandler.RL_HANDSHAKE
        {
            hash1.update( message, offset, len );
            hash2.update( message, offset, len );
        }
        byte[] ciphertext = writeSuite.encodePlaintext( type, message, offset, len );
        byte[] writeMessage = new byte[ciphertext.length + 5];
        TlsUtils.writeUint8( type, writeMessage, 0 );
        TlsUtils.writeUint8( (short) 3, writeMessage, 1 );
        TlsUtils.writeUint8( (short) 1, writeMessage, 2 );
        TlsUtils.writeUint16( ciphertext.length, writeMessage, 3 );
        System.arraycopy( ciphertext, 0, writeMessage, 5, ciphertext.length );
        os.write( writeMessage );
        os.flush();

        /**
         * BlueWhaleSystems fix: Tatiana Rybak - 18 Jul 2007
         *
         * Added debug statements for BouncyCastle.
         */
        //bwmorg.LOG.trace( "Tls RecordStream <-- done writeMessage()." );
    }

    protected void close() throws IOException
    {
        IOException e = null;
        try
        {
            is.close();
        }
        catch( IOException ex )
        {
            e = ex;
        }
        /**
         * BlueWhaleSystems fix: Michael Maguire - 10 Aug 2007
         *
         * Make sure we null out on close.
         */
        finally
        {
            is = null;
        }

        try
        {
            os.close();
        }
        catch( IOException ex )
        {
            e = ex;
        }
        /**
         * BlueWhaleSystems fix: Michael Maguire - 10 Aug 2007
         *
         * Make sure we null out on close.
         */
        finally
        {
            os = null;
        }

        if( e != null )
        {
            throw e;
        }
    }

    protected void flush() throws IOException
    {
        os.flush();
    }

    /**
     * BlueWhaleSystems fix: Tatiana Rybak - 02 Mar 2007
     * 
     * Added a method to return available bytes in the data stream.
     */
    protected int available() throws IOException
    {
        return is.available();
    }
}
