package bwmorg.bouncycastle.crypto.tls;

import java.io.*;

import bwmorg.bouncycastle.crypto.digests.SHA1Digest;
import bwmorg.bouncycastle.crypto.engines.*;
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
    public static final int  TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA_MASK = 1 << 1;
    public static final int  TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA_MASK = 1 << 2;
    public static final int  TLS_RSA_WITH_AES_128_CBC_SHA_MASK      = 1 << 3;    
    public static final int  TLS_DHE_DSS_WITH_AES_128_CBC_SHA_MASK  = 1 << 4;
    public static final int  TLS_DHE_RSA_WITH_AES_128_CBC_SHA_MASK  = 1 << 5;
    public static final int  TLS_RSA_WITH_AES_256_CBC_SHA_MASK      = 1 << 6;
    public static final int  TLS_DHE_DSS_WITH_AES_256_CBC_SHA_MASK  = 1 << 7;
    public static final int  TLS_DHE_RSA_WITH_AES_256_CBC_SHA_MASK  = 1 << 8;
    
    private static final int TLS_RSA_WITH_3DES_EDE_CBC_SHA = 0x000a;
    private static final int TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA = 0x0013;
    private static final int TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA = 0x0016;
    private static final int TLS_RSA_WITH_AES_128_CBC_SHA = 0x002f;
    private static final int TLS_DHE_DSS_WITH_AES_128_CBC_SHA = 0x0032;
    private static final int TLS_DHE_RSA_WITH_AES_128_CBC_SHA = 0x0033;
    private static final int TLS_RSA_WITH_AES_256_CBC_SHA = 0x0035;
    private static final int TLS_DHE_DSS_WITH_AES_256_CBC_SHA = 0x0038;
    private static final int TLS_DHE_RSA_WITH_AES_256_CBC_SHA = 0x0039;

//    private static final int TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA = 0xC01A;    
//    private static final int TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA = 0xC01B;
//    private static final int TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA = 0xC01C;
//    private static final int TLS_SRP_SHA_WITH_AES_128_CBC_SHA = 0xC01D;
//    private static final int TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA = 0xC01E;
//    private static final int TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA = 0xC01F;
//    private static final int TLS_SRP_SHA_WITH_AES_256_CBC_SHA = 0xC020;
//    private static final int TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA = 0xC021;
//    private static final int TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA = 0xC022;

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
        numberOfCiphers += ( cipherMask & TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA_MASK ) != 0 ? 1 : 0;
        numberOfCiphers += ( cipherMask & TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA_MASK ) != 0 ? 1 : 0;
        numberOfCiphers += ( cipherMask & TLS_RSA_WITH_AES_128_CBC_SHA_MASK ) != 0 ? 1 : 0;
        numberOfCiphers += ( cipherMask & TLS_DHE_DSS_WITH_AES_128_CBC_SHA_MASK ) != 0 ? 1 : 0;
        numberOfCiphers += ( cipherMask & TLS_DHE_RSA_WITH_AES_128_CBC_SHA_MASK ) != 0 ? 1 : 0;
        numberOfCiphers += ( cipherMask & TLS_RSA_WITH_AES_256_CBC_SHA_MASK ) != 0 ? 1 : 0;       
        numberOfCiphers += ( cipherMask & TLS_DHE_DSS_WITH_AES_256_CBC_SHA_MASK ) != 0 ? 1 : 0;
        numberOfCiphers += ( cipherMask & TLS_DHE_RSA_WITH_AES_256_CBC_SHA_MASK ) != 0 ? 1 : 0;

        TlsUtils.writeUint16( 2 * numberOfCiphers, os );

        if( ( cipherMask & TLS_RSA_WITH_3DES_EDE_CBC_SHA_MASK ) != 0 )
        {
            TlsUtils.writeUint16( TLS_RSA_WITH_3DES_EDE_CBC_SHA, os );
        }       
        
        if( ( cipherMask & TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA_MASK ) != 0 )
        {
            TlsUtils.writeUint16( TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA, os );
        }
        
        if( ( cipherMask & TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA_MASK ) != 0 )
        {
            TlsUtils.writeUint16( TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA, os );
        }

        if( ( cipherMask & TLS_RSA_WITH_AES_128_CBC_SHA_MASK ) != 0 )
        {
            TlsUtils.writeUint16( TLS_RSA_WITH_AES_128_CBC_SHA, os );
        }
                      
        if( ( cipherMask & TLS_DHE_DSS_WITH_AES_128_CBC_SHA_MASK ) != 0 )
        {
            TlsUtils.writeUint16( TLS_DHE_DSS_WITH_AES_128_CBC_SHA, os );
        }
        
        if( ( cipherMask & TLS_DHE_RSA_WITH_AES_128_CBC_SHA_MASK ) != 0 )
        {
            TlsUtils.writeUint16( TLS_DHE_RSA_WITH_AES_128_CBC_SHA, os );
        }
        
        if( ( cipherMask & TLS_RSA_WITH_AES_256_CBC_SHA_MASK ) != 0 )
        {
            TlsUtils.writeUint16( TLS_RSA_WITH_AES_256_CBC_SHA, os );
        }
                               
        if( ( cipherMask & TLS_DHE_DSS_WITH_AES_256_CBC_SHA_MASK ) != 0 )
        {
            TlsUtils.writeUint16( TLS_DHE_DSS_WITH_AES_256_CBC_SHA, os );
        }
        
        if( ( cipherMask & TLS_DHE_RSA_WITH_AES_256_CBC_SHA_MASK ) != 0 )
        {
            TlsUtils.writeUint16( TLS_DHE_RSA_WITH_AES_256_CBC_SHA, os );
        }
        
    }

    protected static TlsCipherSuite getCipherSuite(int number, TlsProtocolHandler handler) throws IOException
    {
        switch (number)
        {
            case TLS_RSA_WITH_3DES_EDE_CBC_SHA:
                bwmorg.LOG.debug( "TlsCipherSuite: getCipherSuite() - Selected cipher suite: TLS_RSA_WITH_3DES_EDE_CBC_SHA (" + number + ")." );
                return createDESedeCipherSuite(24, TlsCipherSuite.KE_RSA);

            case TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA:
                bwmorg.LOG.debug( "TlsCipherSuite: getCipherSuite() - Selected cipher suite: TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA (" + number + ")." );
                return createDESedeCipherSuite(24, TlsCipherSuite.KE_DHE_DSS);

            case TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA:
                bwmorg.LOG.debug( "TlsCipherSuite: getCipherSuite() - Selected cipher suite: TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA (" + number + ")." );
                return createDESedeCipherSuite(24, TlsCipherSuite.KE_DHE_RSA);

            case TLS_RSA_WITH_AES_128_CBC_SHA:
                bwmorg.LOG.debug( "TlsCipherSuite: getCipherSuite() - Selected cipher suite: TLS_RSA_WITH_AES_128_CBC_SHA (" + number + ")." );
                return createAESCipherSuite(16, TlsCipherSuite.KE_RSA);

            case TLS_DHE_DSS_WITH_AES_128_CBC_SHA:
                bwmorg.LOG.debug( "TlsCipherSuite: getCipherSuite() - Selected cipher suite: TLS_DHE_DSS_WITH_AES_128_CBC_SHA (" + number + ")." );
                return createAESCipherSuite(16, TlsCipherSuite.KE_DHE_DSS);

            case TLS_DHE_RSA_WITH_AES_128_CBC_SHA:
                bwmorg.LOG.debug( "TlsCipherSuite: getCipherSuite() - Selected cipher suite: TLS_DHE_RSA_WITH_AES_128_CBC_SHA (" + number + ")." );
                return createAESCipherSuite(16, TlsCipherSuite.KE_DHE_RSA);

            case TLS_RSA_WITH_AES_256_CBC_SHA:
                bwmorg.LOG.debug( "TlsCipherSuite: getCipherSuite() - Selected cipher suite: TLS_RSA_WITH_AES_256_CBC_SHA (" + number + ")." );
                return createAESCipherSuite(32, TlsCipherSuite.KE_RSA);

            case TLS_DHE_DSS_WITH_AES_256_CBC_SHA:
                bwmorg.LOG.debug( "TlsCipherSuite: getCipherSuite() - Selected cipher suite: TLS_DHE_DSS_WITH_AES_256_CBC_SHA (" + number + ")." );
                return createAESCipherSuite(32, TlsCipherSuite.KE_DHE_DSS);

            case TLS_DHE_RSA_WITH_AES_256_CBC_SHA:
                bwmorg.LOG.debug( "TlsCipherSuite: getCipherSuite() - Selected cipher suite: TLS_DHE_RSA_WITH_AES_256_CBC_SHA (" + number + ")." );
                return createAESCipherSuite(32, TlsCipherSuite.KE_DHE_RSA);

//            case TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA:
//                return createDESedeCipherSuite(24, TlsCipherSuite.KE_SRP);
//
//            case TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA:
//                return createDESedeCipherSuite(24, TlsCipherSuite.KE_SRP_RSA);
//
//            case TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA:
//                return createDESedeCipherSuite(24, TlsCipherSuite.KE_SRP_DSS);
//
//            case TLS_SRP_SHA_WITH_AES_128_CBC_SHA:
//                return createAESCipherSuite(16, TlsCipherSuite.KE_SRP);
//
//            case TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA:
//                return createAESCipherSuite(16, TlsCipherSuite.KE_SRP_RSA);
//
//            case TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA:
//                return createAESCipherSuite(16, TlsCipherSuite.KE_SRP_DSS);
//
//            case TLS_SRP_SHA_WITH_AES_256_CBC_SHA:
//                return createAESCipherSuite(32, TlsCipherSuite.KE_SRP);
//
//            case TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA:
//                return createAESCipherSuite(32, TlsCipherSuite.KE_SRP_RSA);
//
//            case TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA:
//                return createAESCipherSuite(32, TlsCipherSuite.KE_SRP_DSS);

            default:
                handler.failWithError(TlsProtocolHandler.AL_fatal, TlsProtocolHandler.AP_handshake_failure);

                /*
                * Unreachable Code, failWithError will always throw an exception!
                */
                return null;
        }
    }

    private static TlsCipherSuite createAESCipherSuite(int cipherKeySize, short keyExchange)
    {
        return new TlsBlockCipherCipherSuite(createAESCipher(), createAESCipher(),
            new SHA1Digest(), new SHA1Digest(), cipherKeySize, keyExchange);
    }

    private static TlsCipherSuite createDESedeCipherSuite(int cipherKeySize, short keyExchange)
    {
        return new TlsBlockCipherCipherSuite(createDESedeCipher(), createDESedeCipher(),
            new SHA1Digest(), new SHA1Digest(), cipherKeySize, keyExchange);
    }

    private static CBCBlockCipher createAESCipher()
    {
        return new CBCBlockCipher(new AESFastEngine());
    }
    
    private static CBCBlockCipher createDESedeCipher()
    {
        return new CBCBlockCipher(new DESedeEngine());
    }
}
