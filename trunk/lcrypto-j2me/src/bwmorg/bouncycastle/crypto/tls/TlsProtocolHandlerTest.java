package bwmorg.bouncycastle.crypto.tls;

import java.io.IOException;
import java.io.InputStream;
import java.net.Socket;
import java.net.UnknownHostException;

import junit.framework.TestCase;

public class TlsProtocolHandlerTest extends TestCase
{
    public void testTLS_RSA_WITH_AES_256_CBC_SHA_electric_inbound()
    {
        //runTlsTest( "inbound.electric.net", 995, TlsCipherSuiteManager.TLS_RSA_WITH_AES_256_CBC_SHA_MASK, "+OK" );
    }

    public void testTLS_RSA_WITH_AES_256_CBC_SHA_electric()
    {
        runTlsTest( "outbound.electric.net", 465, TlsCipherSuiteManager.TLS_RSA_WITH_AES_256_CBC_SHA_MASK, "220" );
    }

    public void BROKENtestTLS_RSA_WITH_AES_256_CBC_SHA_yahoo()
    {
        runTlsTest( "smtp.mail.yahoo.co.uk", 465, TlsCipherSuiteManager.TLS_RSA_WITH_AES_256_CBC_SHA_MASK, "220" );
    }

    public void testTLS_RSA_WITH_AES_256_CBC_SHA_fastmail()
    {
        runTlsTest( "fastmail.fm", 465, TlsCipherSuiteManager.TLS_RSA_WITH_AES_256_CBC_SHA_MASK, "220" );        
    }
    
    public void testTLS_RSA_WITH_AES_128_CBC_SHA_electric ()
    {
        runTlsTest( "outbound.electric.net", 465, TlsCipherSuiteManager.TLS_RSA_WITH_AES_128_CBC_SHA_MASK, "220" );
    }

    public void BROKENtestTLS_RSA_WITH_AES_128_CBC_SHA_yahoo ()
    {
        runTlsTest( "smtp.mail.yahoo.co.uk", 465, TlsCipherSuiteManager.TLS_RSA_WITH_AES_128_CBC_SHA_MASK, "220" );
    }
    
    public void testTLS_RSA_WITH_AES_128_CBC_SHA_fastmail ()
    {
        runTlsTest( "fastmail.fm", 465, TlsCipherSuiteManager.TLS_RSA_WITH_AES_128_CBC_SHA_MASK, "220" );
    }
    
    
    public void testTLS_RSA_WITH_3DES_EDE_CBC_SHA_electric  ()
    {
        runTlsTest( "outbound.electric.net", 465, TlsCipherSuiteManager.TLS_RSA_WITH_3DES_EDE_CBC_SHA_MASK, "220" );
    }

    public void BROKENtestTLS_RSA_WITH_3DES_EDE_CBC_SHA_yahoo  ()
    {
        runTlsTest( "smtp.mail.yahoo.co.uk", 465, TlsCipherSuiteManager.TLS_RSA_WITH_3DES_EDE_CBC_SHA_MASK, "220" );
    }
    
    public void testTLS_RSA_WITH_3DES_EDE_CBC_SHA_gmail  ()
    {
        runTlsTest( "smtp.gmail.com", 465, TlsCipherSuiteManager.TLS_RSA_WITH_3DES_EDE_CBC_SHA_MASK, "220" );
    }
    
    // TODO: We should change this to hit our own test Exchange server.
    // Not really an appropriate thing to do with a customer's own mail server.
    //public void FAILStestTLS_RSA_WITH_3DES_EDE_CBC_SHA_moorcrofts_exchange ()
    //{
    //    runTlsTest( "moorcroftsllp.plus.com", 993, TlsCipherSuiteManager.TLS_RSA_WITH_3DES_EDE_CBC_SHA_MASK, "* OK" );
    //}   
    
    public void testTLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA_everyone ()
    {
        runTlsTest( "smtp.everyone.net", 465, TlsCipherSuiteManager.TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA_MASK, "220" );
    }
    
    public void testTLS_DHE_RSA_WITH_AES_128_CBC_SHA_everyone  ()
    {
        runTlsTest( "smtp.everyone.net", 465, TlsCipherSuiteManager.TLS_DHE_RSA_WITH_AES_128_CBC_SHA_MASK, "220" );
    }
    private void runTlsTest(String server, int port, int cipherMask, String expectedResultStartsWith)
    {
        try
        {
            Socket iSocket = new Socket( server, port );
            TlsProtocolHandler handler = new TlsProtocolHandler( iSocket.getInputStream(), iSocket.getOutputStream() );
            handler.connect( new AlwaysValidVerifyer(), cipherMask, (int) ( System.currentTimeMillis() / 1000 ) );
            System.out.println( "Connected to " + server + ": " + port );
            InputStream iInputStream = handler.getTlsInputStream();

            // read the first line of the server connect
            int expectedResultStartsWithLength = expectedResultStartsWith.length();
            int length = expectedResultStartsWithLength > 1000 ? expectedResultStartsWithLength : 1000;

            int pos = 0;
            char[] buffer = new char[length];
            
            if (iInputStream.available() == 0) {
                System.out.println("Nothing available. Waiting...");
                synchronized( this )
                {
                    try
                    {
                        wait( 15000 );
                    }
                    catch( InterruptedException e )
                    {
                        // do nothing                        
                    }
                }
            }
            
            while( iInputStream.available() > 0 && pos < length )
            {
                char ch = (char) iInputStream.read();
                buffer[pos++] = ch;
            }
            
            String readString = new String( buffer, 0, pos );
            System.out.println( "Expecting a string that starts with: " + expectedResultStartsWith + ". Got: " + readString );
            if (readString.startsWith( expectedResultStartsWith )) {
                assertTrue( true );
            } else {
                assertTrue( false );
            
            }
        }
        catch( UnknownHostException e )
        {
            System.out.println( "UnknownHostException is thrown: " + e.getMessage() );
            fail();
        }
        catch( IOException e )
        {
            System.out.println( "IOException is thrown: " + e.getMessage() );
            fail();
        }
    }
    
}
