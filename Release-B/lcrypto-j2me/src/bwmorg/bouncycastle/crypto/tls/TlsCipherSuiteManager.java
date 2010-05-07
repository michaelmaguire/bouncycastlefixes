package bwmorg.bouncycastle.crypto.tls;

import java.io.IOException;
import java.io.OutputStream;

import bwmorg.bouncycastle.crypto.digests.SHA1Digest;
//#ifdef USE_AESFASTENGINE
import bwmorg.bouncycastle.crypto.engines.AESFastEngine;
//#else
import bwmorg.bouncycastle.crypto.engines.AESLightEngine;
//#endif
import bwmorg.bouncycastle.crypto.engines.DESedeEngine;
import bwmorg.bouncycastle.crypto.modes.CBCBlockCipher;

/**
 * A manager for ciphersuite. This class does manage all ciphersuites
 * which are used by MicroTLS.
 */
public class TlsCipherSuiteManager
{
    /**
     * BlueWhaleSystems fix: Tatiana Rybak - 15 July 2007
     *
     * Added ability to set which ciphers to report during tls negotiation.
     */
    public static final int  TLS_RSA_WITH_3DES_EDE_CBC_SHA_MASK     = 1 << 0;
    public static final int  TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA_MASK = 1 << 1;
    public static final int  TLS_RSA_WITH_AES_128_CBC_SHA_MASK      = 1 << 2;
    public static final int  TLS_DHE_RSA_WITH_AES_128_CBC_SHA_MASK  = 1 << 3;
    public static final int  TLS_RSA_WITH_AES_256_CBC_SHA_MASK      = 1 << 4;
    public static final int  TLS_DHE_RSA_WITH_AES_256_CBC_SHA_MASK  = 1 << 5;

    private static final int TLS_RSA_WITH_3DES_EDE_CBC_SHA          = 0x000a;
    private static final int TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA      = 0x0016;
    private static final int TLS_RSA_WITH_AES_128_CBC_SHA           = 0x002f;
    private static final int TLS_DHE_RSA_WITH_AES_128_CBC_SHA       = 0x0033;
    private static final int TLS_RSA_WITH_AES_256_CBC_SHA           = 0x0035;
    private static final int TLS_DHE_RSA_WITH_AES_256_CBC_SHA       = 0x0039;

    /**
     * BlueWhaleSystems fix: Tatiana Rybak - 15 July 2007
     *
     * Added ability to set which ciphers to report during tls negotiation.
     */
    protected static void writeCipherSuites( OutputStream os, int cipherMask ) throws IOException
    {
        int numberOfCiphers = 0;

        // calculate number of ciphers that we are writing out
        numberOfCiphers += ( cipherMask & TLS_RSA_WITH_3DES_EDE_CBC_SHA_MASK ) != 0 ? 1 : 0;
        numberOfCiphers += ( cipherMask & TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA_MASK ) != 0 ? 1 : 0;
        numberOfCiphers += ( cipherMask & TLS_RSA_WITH_AES_128_CBC_SHA_MASK ) != 0 ? 1 : 0;
        numberOfCiphers += ( cipherMask & TLS_DHE_RSA_WITH_AES_128_CBC_SHA_MASK ) != 0 ? 1 : 0;
        numberOfCiphers += ( cipherMask & TLS_RSA_WITH_AES_256_CBC_SHA_MASK ) != 0 ? 1 : 0;
        numberOfCiphers += ( cipherMask & TLS_DHE_RSA_WITH_AES_256_CBC_SHA_MASK ) != 0 ? 1 : 0;

        TlsUtils.writeUint16( 2 * numberOfCiphers, os );

        if( ( cipherMask & TLS_RSA_WITH_3DES_EDE_CBC_SHA_MASK ) != 0 )
        {
            TlsUtils.writeUint16( TLS_RSA_WITH_3DES_EDE_CBC_SHA, os );
        }

        if( ( cipherMask & TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA_MASK ) != 0 )
        {
            TlsUtils.writeUint16( TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA, os );
        }

        if( ( cipherMask & TLS_RSA_WITH_AES_128_CBC_SHA_MASK ) != 0 )
        {
            TlsUtils.writeUint16( TLS_RSA_WITH_AES_128_CBC_SHA, os );
        }
        
        if( ( cipherMask & TLS_DHE_RSA_WITH_AES_128_CBC_SHA_MASK ) != 0 )
        {
            TlsUtils.writeUint16( TLS_DHE_RSA_WITH_AES_128_CBC_SHA, os );
        }
        
        if( ( cipherMask & TLS_RSA_WITH_AES_256_CBC_SHA_MASK ) != 0 )
        {
            TlsUtils.writeUint16( TLS_RSA_WITH_AES_256_CBC_SHA, os );
        }
        
        if( ( cipherMask & TLS_DHE_RSA_WITH_AES_256_CBC_SHA_MASK ) != 0 )
        {
            TlsUtils.writeUint16( TLS_DHE_RSA_WITH_AES_256_CBC_SHA, os );
        }

    }

    protected static TlsCipherSuite getCipherSuite( int number, TlsProtocolHandler handler ) throws IOException
    {
        /**
         * BlueWhaleSystems fix: Tatiana Rybak - 18 Jul 2007
         *
         * Added debug statements for BouncyCastle.
         */               
        switch( number )
        {
            case TLS_RSA_WITH_3DES_EDE_CBC_SHA:
                bwmorg.LOG.debug( "TlsCipherSuite: getCipherSuite() - Selected cipher suite: TLS_RSA_WITH_3DES_EDE_CBC_SHA (" + number + ")." );
                return new TlsBlockCipherCipherSuite( new CBCBlockCipher( new DESedeEngine() ), new CBCBlockCipher( new DESedeEngine() ), new SHA1Digest(), new SHA1Digest(), 24, TlsCipherSuite.KE_RSA );

            case TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA:
                bwmorg.LOG.debug( "TlsCipherSuite: getCipherSuite() - Selected cipher suite: TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA (" + number + ")." );
                return new TlsBlockCipherCipherSuite( new CBCBlockCipher( new DESedeEngine() ), new CBCBlockCipher( new DESedeEngine() ), new SHA1Digest(), new SHA1Digest(), 24,
                        TlsCipherSuite.KE_DHE_RSA );

            case TLS_RSA_WITH_AES_128_CBC_SHA:
                bwmorg.LOG.debug( "TlsCipherSuite: getCipherSuite() - Selected cipher suite: TLS_RSA_WITH_AES_128_CBC_SHA (" + number + ")." );
                //#ifdef USE_AESFASTENGINE
                return new TlsBlockCipherCipherSuite( new CBCBlockCipher( new AESFastEngine() ), new CBCBlockCipher( new AESFastEngine() ), new SHA1Digest(), new SHA1Digest(), 16,
                        TlsCipherSuite.KE_RSA );
                //#else
                return new TlsBlockCipherCipherSuite( new CBCBlockCipher( new AESLightEngine() ), new CBCBlockCipher( new AESLightEngine() ), new SHA1Digest(), new SHA1Digest(), 16,
                        TlsCipherSuite.KE_RSA );
                //#endif

            case TLS_DHE_RSA_WITH_AES_128_CBC_SHA:
                bwmorg.LOG.debug( "TlsCipherSuite: getCipherSuite() - Selected cipher suite: TLS_DHE_RSA_WITH_AES_128_CBC_SHA (" + number + ")." );
                //#ifdef USE_AESFASTENGINE
                return new TlsBlockCipherCipherSuite( new CBCBlockCipher( new AESFastEngine() ), new CBCBlockCipher( new AESFastEngine() ), new SHA1Digest(), new SHA1Digest(), 16,
                        TlsCipherSuite.KE_DHE_RSA );
                //#else
                return new TlsBlockCipherCipherSuite( new CBCBlockCipher( new AESLightEngine() ), new CBCBlockCipher( new AESLightEngine() ), new SHA1Digest(), new SHA1Digest(), 16,
                        TlsCipherSuite.KE_DHE_RSA );
                //#endif
            case TLS_RSA_WITH_AES_256_CBC_SHA:
                bwmorg.LOG.debug( "TlsCipherSuite: getCipherSuite() - Selected cipher suite: TLS_RSA_WITH_AES_256_CBC_SHA (" + number + ")." );
                //#ifdef USE_AESFASTENGINE
                return new TlsBlockCipherCipherSuite( new CBCBlockCipher( new AESFastEngine() ), new CBCBlockCipher( new AESFastEngine() ), new SHA1Digest(), new SHA1Digest(), 32,
                        TlsCipherSuite.KE_RSA );
                //#else
                return new TlsBlockCipherCipherSuite( new CBCBlockCipher( new AESLightEngine() ), new CBCBlockCipher( new AESLightEngine() ), new SHA1Digest(), new SHA1Digest(), 32,
                        TlsCipherSuite.KE_RSA );
                //#endif
            case TLS_DHE_RSA_WITH_AES_256_CBC_SHA:
                bwmorg.LOG.debug( "TlsCipherSuite: getCipherSuite() - Selected cipher suite: TLS_DHE_RSA_WITH_AES_256_CBC_SHA (" + number + ")." );
                //#ifdef USE_AESFASTENGINE
                return new TlsBlockCipherCipherSuite( new CBCBlockCipher( new AESFastEngine() ), new CBCBlockCipher( new AESFastEngine() ), new SHA1Digest(), new SHA1Digest(), 32,
                        TlsCipherSuite.KE_DHE_RSA );
                //#else
                return new TlsBlockCipherCipherSuite( new CBCBlockCipher( new AESLightEngine() ), new CBCBlockCipher( new AESLightEngine() ), new SHA1Digest(), new SHA1Digest(), 32,
                        TlsCipherSuite.KE_DHE_RSA );

                //#endif
            default:
                
                bwmorg.LOG.info( "TlsCipherSuite: getCipherSuite() - Unsupported cipher suite." );
                handler.failWithError( TlsProtocolHandler.AL_fatal, TlsProtocolHandler.AP_handshake_failure );

                /*
                 * Unreachable Code, failWithError will always throw an exception!
                 */
                return null;

        }
    }

}
