package bwmorg.bouncycastle.crypto.prng;

/**
 * A thread based seed generator - one source of randomness.
 * <p>
 * Based on an idea from Marcus Lippert.
 * </p>
 */
public class ThreadedSeedGenerator
{
    private class SeedGenerator
        implements Runnable
    {
        private int              counter = 0;

        /**
         * BlueWhaleSystems fix: Michael Maguire - 10 Aug 2007
         * 
         * Should be volatile.
         */
        private volatile boolean stop    = false;

        public void run()
        {
            /**
             * BlueWhaleSystems fix: Michael Maguire - 30 Apr 2009
             * 
             * Make sure in all run() methods we have an outermost catch(Throwable)
             * so we catch all possible exceptions in Runnables to avoid app exits.
             */
            try
            {
                /**
                 * BlueWhaleSystems fix: Michael Maguire - 10 Aug 2007
                 * 
                 * LOG thread startup.
                 */
                bwmorg.LOG.debug( "ThreadedSeedGenerator.run NEW THREAD" );

                while( !this.stop )
                {
                    this.counter++;
                }
            }
            catch( Throwable t )
            {
                /**
                 * BlueWhaleSystems fix: Michael Maguire - 30 Apr 2009
                 * 
                 * Make sure in all run() methods we have an outermost catch(Throwable)
                 * so we catch all possible exceptions in Runnables to avoid app exits.
                 */
            }

        }

        public byte[] generateSeed(
            int numbytes,
            boolean fast)
        {
            /**
             * BlueWhaleSystems fix -- Michael Maguire -- 24 Jun 2009
             * 
             * See ticket:3328 Client: Debugging help -- name all threads used in the app
             */
            Thread t = new Thread( this, "ThreadedSeedGenerator.generateSeed" );

            /**
             * BlueWhaleSystems fix: Michael Maguire - 11 Mar 2008
             * 
             * Lower priority for all background threads.
             */
            t.setPriority( Thread.MIN_PRIORITY );

            byte[] result = new byte[numbytes];
            this.counter = 0;
            this.stop = false;
            int last = 0;
            int end;

            t.start();
            if( fast )
            {
                end = numbytes;
            }
            else
            {
                end = numbytes * 8;
            }
            for( int i = 0; i < end; i++ )
            {
                while( this.counter == last )
                {
                    try
                    {
                        Thread.sleep( 1 );
                    }
                    catch( InterruptedException e )
                    {
                        // ignore
                    }
                }
                last = this.counter;
                if( fast )
                {
                    result[i] = (byte) ( last & 0xff );
                }
                else
                {
                    int bytepos = i / 8;
                    result[bytepos] = (byte) ( ( result[bytepos] << 1 ) | ( last & 1 ) );
                }

            }
            stop = true;
            return result;
        }
    }

    /**
     * Generate seed bytes. Set fast to false for best quality.
     * <p>
     * If fast is set to true, the code should be round about 8 times faster when
     * generating a long sequence of random bytes. 20 bytes of random values using
     * the fast mode take less than half a second on a Nokia e70. If fast is set to false,
     * it takes round about 2500 ms.
     * </p>
     * @param numBytes the number of bytes to generate
     * @param fast true if fast mode should be used
     */
    public byte[] generateSeed(
        int numBytes,
        boolean fast)
    {
        SeedGenerator gen = new SeedGenerator();

        return gen.generateSeed( numBytes, fast );
    }
}
