package bwmorg.bouncycastle.crypto.tls;

import java.io.*;
import java.util.Arrays;

import junit.framework.TestCase;

/**
 * These tests are meant to test the correctness of data buffering in TlsOutputStream. 
 * 
 * For simplicity's sake, TlsProtocolHandlerDummy is a handler that does not encrypt byte data writen to it, and writes it to the 
 * output stream as such. This makes it possible to verify that the bytes are writen out as expected. 
 */
public class TLSOutputStreamTest extends TestCase
{
    private static final int TEST_BUFFER_SIZE = 128;

    /**
     * Normal case - write out less than BUFFER_SIZE.
     */
    public void testWrite1() throws IOException
    {
        System.out.println( "Running TLSOutputStreamTest #1 ... " );
        ByteArrayOutputStream arrayOutputStream = new ByteArrayOutputStream();
        TlsProtocolHandlerDummy tlsProtocolHandler = new TlsProtocolHandlerDummy( arrayOutputStream );
        TlsOuputStream outputStream = new TlsOuputStream( tlsProtocolHandler, TEST_BUFFER_SIZE );

        byte[] inputData = new byte[TEST_BUFFER_SIZE - 10];
        for( int i = 0; i < inputData.length; i++ )
        {
            inputData[i] = (byte) i;
        }

        outputStream.write( inputData, 0, inputData.length );
        outputStream.flush();

        if( Arrays.equals( tlsProtocolHandler.getResultArray(), inputData ) )
        {
            System.out.println( "TLSOutputStreamTest 1 PASSED " );
        }
        else
        {
            System.out.println( "TLSOutputStreamTest 1 failed " );
            fail();
        }
    }

    /**
     * Boundary case 1 - write out exactly BUFFER_SIZE, one byte at a time
     */
    public void testWrite2() throws IOException
    {
        System.out.println( "Running TLSOutputStreamTest #2 ... " );

        ByteArrayOutputStream arrayOutputStream = new ByteArrayOutputStream();
        TlsProtocolHandlerDummy tlsProtocolHandler = new TlsProtocolHandlerDummy( arrayOutputStream );
        TlsOuputStream outputStream = new TlsOuputStream( tlsProtocolHandler, TEST_BUFFER_SIZE );
        byte[] inputData = new byte[TEST_BUFFER_SIZE];

        for( int i = 0; i < TEST_BUFFER_SIZE; i++ )
        {
            inputData[i] = (byte) i;
            outputStream.write( i );
        }

        outputStream.flush();
        if( Arrays.equals( tlsProtocolHandler.getResultArray(), inputData ) )
        {
            System.out.println( "TLSOutputStreamTest 2 PASSED " );
        }
        else
        {
            System.out.println( "TLSOutputStreamTest 2 FAILED " );
            fail();
        }

    }

    /**
     * Boundary case 3 - Write out BUFFER_SIZE + 1 bytes (one byte at a time)
     * 
     */
    public void testWrite3() throws IOException
    {
        System.out.println( "Running TLSOutputStreamTest #3 ... " );

        ByteArrayOutputStream arrayOutputStream = new ByteArrayOutputStream();
        TlsProtocolHandlerDummy tlsProtocolHandler = new TlsProtocolHandlerDummy( arrayOutputStream );
        TlsOuputStream outputStream = new TlsOuputStream( tlsProtocolHandler, TEST_BUFFER_SIZE );
        byte[] inputData = new byte[TEST_BUFFER_SIZE + 1];

        for( int i = 0; i < TEST_BUFFER_SIZE + 1; i++ )
        {
            inputData[i] = (byte) i;
            outputStream.write( i );
        }

        outputStream.flush();

        if( Arrays.equals( tlsProtocolHandler.getResultArray(), inputData ) )
        {
            System.out.println( "TLSOutputStreamTest 3 PASSED " );
        }
        else
        {
            System.out.println( "TLSOutputStreamTest 3 FAILED " );
            fail();
        }

    }

    /**
     * Boundary case 4 -
     * 1. Write out exactly BUFFER_SIZE (as one array)
     * 2. Write out 1 more byte
     */
    public void testWrite4() throws IOException
    {
        System.out.println( "Running TLSOutputStreamTest #4 ... " );

        ByteArrayOutputStream arrayOutputStream = new ByteArrayOutputStream();
        TlsProtocolHandlerDummy tlsProtocolHandler = new TlsProtocolHandlerDummy( arrayOutputStream );
        TlsOuputStream outputStream = new TlsOuputStream( tlsProtocolHandler, TEST_BUFFER_SIZE );
        byte[] inputData = new byte[TEST_BUFFER_SIZE + 1];

        for( int i = 0; i < TEST_BUFFER_SIZE + 1; i++ )
        {
            inputData[i] = (byte) i;
        }
        outputStream.write( inputData, 0, TEST_BUFFER_SIZE );
        outputStream.write( inputData[TEST_BUFFER_SIZE] );
        outputStream.flush();

        if( Arrays.equals( tlsProtocolHandler.getResultArray(), inputData ) )
        {
            System.out.println( "TLSOutputStreamTest 4 PASSED " );
        }
        else
        {
            System.out.println( "TLSOutputStreamTest 4 FAILED " );
            fail();
        }
    }

    /**
     * Boundary case 5 -
     * 1. Write out exactly BUFFER_SIZE - 1 (as one array)
     * 2. Write out 2 byte array
     */
    public void testWrite5() throws IOException
    {
        System.out.println( "Running TLSOutputStreamTest #5 ... " );

        ByteArrayOutputStream arrayOutputStream = new ByteArrayOutputStream();
        TlsProtocolHandlerDummy tlsProtocolHandler = new TlsProtocolHandlerDummy( arrayOutputStream );
        TlsOuputStream outputStream = new TlsOuputStream( tlsProtocolHandler, TEST_BUFFER_SIZE );
        byte[] inputData = new byte[TEST_BUFFER_SIZE + 1];

        for( int i = 0; i < TEST_BUFFER_SIZE + 1; i++ )
        {
            inputData[i] = (byte) i;
        }
        outputStream.write( inputData, 0, TEST_BUFFER_SIZE - 1 );
        outputStream.write( inputData, TEST_BUFFER_SIZE - 1, 2 );
        outputStream.flush();

        if( Arrays.equals( tlsProtocolHandler.getResultArray(), inputData ) )
        {
            System.out.println( "TLSOutputStreamTest 5 PASSED " );
        }
        else
        {
            System.out.println( "TLSOutputStreamTest 5 FAILED " );
            fail();
        }
    }

    /**
     * Case 6 -
     * 1. Write out BUFFER_SIZE - 1 (as one array)
     * 2. Write out BUFFER_SIZE + 1 (as one array)
     */
    public void testWrite6() throws IOException
    {
        System.out.println( "Running TLSOutputStreamTest #6 ... " );

        ByteArrayOutputStream arrayOutputStream = new ByteArrayOutputStream();
        TlsProtocolHandlerDummy tlsProtocolHandler = new TlsProtocolHandlerDummy( arrayOutputStream );
        TlsOuputStream outputStream = new TlsOuputStream( tlsProtocolHandler, TEST_BUFFER_SIZE );
        byte[] inputData = new byte[TEST_BUFFER_SIZE * 2];

        for( int i = 0; i < inputData.length; i++ )
        {
            inputData[i] = (byte) i;
        }
        outputStream.write( inputData, 0, TEST_BUFFER_SIZE - 1 );
        outputStream.write( inputData, TEST_BUFFER_SIZE - 1, TEST_BUFFER_SIZE + 1 );
        outputStream.flush();

        if( Arrays.equals( tlsProtocolHandler.getResultArray(), inputData ) )
        {
            System.out.println( "TLSOutputStreamTest 6 PASSED " );
        }
        else
        {
            System.out.println( "TLSOutputStreamTest 6 FAILED " );
            fail();
        }
    }

    class TlsProtocolHandlerDummy extends TlsProtocolHandler
    {
        ByteArrayOutputStream anArrayOutputStream;

        public TlsProtocolHandlerDummy( ByteArrayOutputStream arrayOutputStream )
        {
            super( null, null );
            anArrayOutputStream = arrayOutputStream;
        }

        protected void writeData( byte[] buf, int offset, int len ) throws IOException
        {
            anArrayOutputStream.write( buf, offset, len );
        }

        protected void flush() throws IOException
        {

        }

        byte[] getResultArray()
        {
            return anArrayOutputStream.toByteArray();
        }
    }

}
