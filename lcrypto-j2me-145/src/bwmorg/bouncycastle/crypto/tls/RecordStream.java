package bwmorg.bouncycastle.crypto.tls;

import java.io.*;

import bwmorg.LOG;

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

    /**
     * BlueWhaleSystems fix: Tatiana Rybak - 08 Aug 2007
     */
    private boolean isValidRecordType( int type )
    {

        return ( type == TlsProtocolHandler.RL_CHANGE_CIPHER_SPEC || type == TlsProtocolHandler.RL_ALERT || type == TlsProtocolHandler.RL_APPLICATION_DATA || type == TlsProtocolHandler.RL_HANDSHAKE );
    }

    /*    private int tryReadByte() throws IOException{
     
     if (is.available() > 0) {
     return is.read();
     
     } else {
     synchronized (this) {
     try {                    
     wait(2000);
     } catch (InterruptedException iException) {
     
     }
     }
     if (is.available() > 0) {
     return is.read();
     } 
     }  
     
     // couldn't read any data
     throw new IOException("No data available to read");
     }*/

    /**
     * BlueWhaleSystems fix: Tatiana Rybak - 08 Aug 2007
     *
     * This is a HACK to have TLS working with Microsoft Exchange using DES-CBC3-SHA cipher.
     * The cipher is broken on the exchange side and sends garbage data at the end of valid data.
     * Try to skip this junk bytes and find valid data that does appear sometimes. 
     * 
     * This implementation has major 2 issues that need to be fixed:
     * 
     * 1. It heavily relies on available(), therefore any delay in the network might cause this code to break.
     * Ideally, we would use some buffering or wait for data before bailing.
     * 
     * 2. While scanning for valid data, only the first 3 bytes are checked for validity. Once it finds what
     * looks like a valid record and valid version (3 bytes), it reads the size and provided it is positive the code
     * will then try to read the data in. I.e. no error checking is done once the first 5 bytes look OK.
     * It is possible that the garbage data will have the first 3-5 bytes that <look> like a valid record, but in 
     * reality is just garbage. This code does not currently recover from this failure.
     * 
     * The code recoveres the scanning if the failure occures within the first 3 bytes or 5 if byte 4 or 5 are negative.
     * 
     * Ideally, once the data size has been read in we would compare that the two byte in the data size do not look like
     *  a start of a valid record. If it doesn't then we try to read the data and if it fails we restart from byte 6. 
     * (Read data needs to be buffered, since we want to rescan it. Here we could possibly run into a problem of reading
     * too much data, if this is actaully not a valid record)
     *  If either one of the two bytes for the size look like it could be a start of the valid record. Here we can try 
     *  seeing if the next two bytes after a potential valid record type are valid version. If there are not - read the 
     *  size of the record that we found originally. If the next 2 bytes do look like a version.. UGH! take the smallest 
     *  size of the two datas and read and try to decode that first. If that fails, try the second one. Of course, both can fail. 
     *  Also, we have to make sure that the data is actually available when we try to read it. 
     */
    private boolean scanForValidData() throws IOException, UnknownDataException
    {
        boolean skipReadingRecordtype = false;
        short type;
        int i = 0;

        // try to find valid data
        while( is.available() > 0 )
        {

            if( !skipReadingRecordtype )
            {
                type = TlsUtils.readUint8( is );
            }
            else
            {
                // we might be restarting the scan when version or size check failed,
                // but the value read in looked like a valid type
                type = (short) i;
            }

            // keep on skipping until we find a valid record type
            if( !isValidRecordType( type ) )
            {
                //bwmorg.LOG.trace( "Tls RecordStream.scanForValidData() --> Invalid type: " + type );
                continue;
            }

            //bwmorg.LOG.trace( "Tls RecordStream.scanForValidData() --> Found a valid type: " + type );

            // found valid type, check version                               
            if( is.available() > 0 )
            {
                i = is.read();
                if( i != 3 )
                {
                    //bwmorg.LOG.trace( "Tls RecordStream.scanForValidData() --> First byte of the version doesn't match: " + i );

                    // the first byte is not a version byte. Try to see maybe it is record type. If that's the case,
                    // restart the scan but skip reading the record type in.
                    // happens in cases like ... 22 23 03 01 ...
                    skipReadingRecordtype = isValidRecordType( i );
                    continue;
                }
            }
            else
            {
                //bwmorg.LOG.trace( "Tls RecordStream.scanForValidData() --> No more data available. Bailing... " );
                return false;
            }

            if( is.available() > 0 )
            {
                i = is.read();
                if( i != 1 )
                {
                    //bwmorg.LOG.trace( "Tls RecordStream.scanForValidData() --> Second byte of the version doesn't match: " + i );

                    // the second byte is not a version byte. Try to see maybe it is record type. If that's the case,
                    // restart the scan but skip reading the record type in.
                    // happens in cases like ... 22 03 23 03 01 ...
                    skipReadingRecordtype = isValidRecordType( i );
                    continue;
                }
            }
            else
            {
                //bwmorg.LOG.trace( "Tls RecordStream.scanForValidData() --> No more data available. Bailing... " );
                return false;
            }

            // version OK, now try reading the size of the data
            try
            {
                int size = 0;

                // read the first byte of the size
                if( is.available() > 0 )
                {
                    i = is.read();
                    if( i < 0 )
                    {
                        //bwmorg.LOG.trace( "Tls RecordStream.scanForValidData() --> First byte of the size is negative: " + i );
                        continue;
                    }
                    size = i << 8;
                }

                // read the second byte of the size
                if( is.available() > 0 )
                {
                    i = is.read();
                    if( i < 0 )
                    {
                        //bwmorg.LOG.trace( "Tls RecordStream.scanForValidData() --> Second byte of the size is negative: " + i );
                        continue;
                    }

                    size = size | i;
                }

                //bwmorg.LOG.trace( "Tls RecordStream.scanForValidData() --> Looks like we found data of " + size + " length." );

                byte[] buf = decodeAndVerify( type, is, size );
                //bwmorg.LOG.trace( "Tls RecordStream.scanForValidData() --> Read, decoded and verified data OK." );

                handler.processData( type, buf, 0, buf.length );
                //bwmorg.LOG.trace( "Tls RecordStream.scanForValidData() --> Processed data OK." );

                // if we got here, we actually found valid data. Return true.
                return true;
            }
            catch( IOException e )
            {
                continue;
            }
        }

        // if we got here, we couldn't find valid data in the extra bytes. Return false.
        //bwmorg.LOG.trace( "Tls RecordStream.scanForValidData() --> No data found." );
        return false;
    }
    
    public void readData() throws IOException, UnknownDataException
    {
        /**
         * BlueWhaleSystems fix: Tatiana Rybak - 18 Jul 2007
         *
         * Added debug statements for BouncyCastle.
         */
        //bwmorg.LOG.trace( "Tls RecordStream --> readData()." );
        short type = TlsUtils.readUint8( is );
        
        /**
         * BlueWhaleSystems fix: Tatiana Rybak - 18 Jul 2007
         *
         * Exchange fix. Skip unknown/extra and try to see if we encounter valid data there too.
         * This kinda works. (See comments for the scanForValidData() method) but has a few issues.
         * Also, when dealing with exchange this hack will only work if the FIRST byte of the garbage data is 
         * not one of the 4 valid bytes. The odds of first byte being one of the valid bytes are 4/255,
         * and it does happen. What happens in this case, the read fails later in this method.
         * This is bad. The only good news is that the next time we connect to the server, odds are this will
         * not happen and the client will work. One thing to do is to set a flag if we are dealing with Exchange 
         * and DES-CBC3-SHA cipher. If that's the case, we can add extra checks in the code below (like checking that
         * the data is available, etc)
         */
        if( !isValidRecordType( type ) )
        {
            //bwmorg.LOG.trace( "Tls RecordStream.readData() --> Unknown record type: " + type );

            // skip unknown bytes, while looking for valid data
            try
            {
                if( scanForValidData() )
                {
                    return;
                }
            }
            catch( Exception e )
            {
            }

            throw new UnknownDataException();
        }
        
        TlsUtils.checkVersion( is, handler );
        int size = TlsUtils.readUint16( is );

        LOG.trace( "Tls RecordStream: size: " + size + ", type: " + type );
        
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

/**
 * BlueWhaleSystems fix: Tatiana Rybak - 08 Aug 2007
 */
class UnknownDataException extends Exception
{

}
