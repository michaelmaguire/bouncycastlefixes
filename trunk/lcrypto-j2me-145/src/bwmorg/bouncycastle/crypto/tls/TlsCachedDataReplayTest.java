package bwmorg.bouncycastle.crypto.tls;

import java.io.*;

import junit.framework.TestCase;
import bigjava.security.SecureRandom;

public class TlsCachedDataReplayTest extends TestCase
{
    public void testNone() {
        
    }
    
    public void xtestCached_TLS_RSA_WITH_3DES_EDE_CBC_SHA()
    {
        System.out.println( "Test 1: Testing TLS_RSA_WITH_3DES_EDE_CBC_SHA cipher." );

        // write out all the ciphers 
        playBackTLSConversation( 0xffffff, TlsCachedDataTest.TLS_RSA_WITH_3DES_EDE_CBC_SHA_CACHED, "+OK Hello there.\r\n" );
    }

    public void xtestCached_TLS_DHE_RSA_WITH_AES_128_CBC_SHA()
    {
        System.out.println( "Test 2: Testing TLS_DHE_RSA_WITH_AES_128_CBC_SHA cipher." );

        playBackTLSConversation( TlsCipherSuiteManager.TLS_DHE_RSA_WITH_AES_128_CBC_SHA_MASK, TlsCachedDataTest.TLS_DHE_RSA_WITH_AES_128_CBC_SHA_CACHED, "* OK EON-IMAP on pop05 Welcomes You\r\n" );
    }

    public void xtestCached_TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA()
    {
        System.out.println( "Test 3: Testing TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA cipher." );

        playBackTLSConversation( TlsCipherSuiteManager.TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA_MASK, TlsCachedDataTest.TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA_CACHED, "* OK EON-IMAP on pop04 Welcomes You\r\n" );
    }

    public void xtestExchange()
    {
        System.out.println( "Test 3: Testing TLS_RSA_WITH_3DES_EDE_CBC_SHA cipher." );

        playBackTLSConversation( /*TlsCipherSuiteManager.TLS_RSA_WITH_3DES_EDE_CBC_SHA_MASK*/0xffffff, TlsCachedDataTest.TLS_EXCHANGE_EXTRA_BYTES_CACHED,
                "* OK Microsoft Exchange Server 2003 IMAP4rev1 server version 6.5.7226.0 (test3.BlueWhale.local) ready.\r\n" );
    }

    void playBackTLSConversation( int cipherMask, byte[] cachedInputData, String expectedString )
    {

        try
        {
            // create input/output streams. Use precached input stream. TLS ProtocolHandler will write
            // to the output stream, but this will be be checked against expected output. 
            ByteArrayInputStream inputStream = new ByteArrayInputStream( cachedInputData );
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

            // use cached random seed
            SecureRandom random = new SecureRandom( TlsProtocolHandler.CACHED_RANDOM_SEED );
            TlsProtocolHandler handler = new TlsProtocolHandler( inputStream, outputStream, random );

            // make sure we use cached random int as well
            // during the connect the handshake part is processed, sometime this will include alerts
            // and change cipher spec commands
            handler.connect( new AlwaysValidVerifyer(), cipherMask, TlsProtocolHandler.CACHED_RANDOM_INT );

            // after the connect is done, 
            // read the first line of the application data, to make sure that we decode the text
            // negotiation can be successful, but the decoding could fail still if we use
            // incorrect cipher suite etc.
            InputStream in = handler.getTlsInputStream();
            int pos = 0;
            //int length = expectedString.length();
            char[] buffer = new char[1000];

            // read while data available or we read enough bytes
            while( in.available() > 0 )// && pos < length )
            {
                int i = in.read();
                if( i != -1 )
                {
                    buffer[pos++] = (char)i;
                }
            }

            // compare decoded strings
            String readString = new String( buffer, 0, pos );
            System.out.println( "Expecting a string: " + expectedString + " Got: " + readString );
            if( readString.equals( expectedString ) )
            {
                assertTrue( true );
            }
            else
            {
                assertTrue( false );
            }

        }
        catch( IOException e )
        {
            System.out.println( "Test failed: unexpected exception occured." );
            e.printStackTrace();
            fail();
        }
    }
}
