/**
 * 
 * License
 *
 * Copyright (c) 2000 - 2006 The Legion Of The Bouncy Castle (http://www.bouncycastle.org)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software 
 * and associated documentation files (the "Software"), to deal in the Software without restriction, 
 * including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do
 * so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all copies or substantial
 * portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT 
 * LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. 
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 */
package bwmorg.bouncycastle.crypto.prng;

import com.bluewhalesystems.client.logger.*;

/**
 * A thread based seed generator - one source of randomness.
 * <p>
 * Based on an idea from Marcus Lippert.
 * </p>
 */
public class ThreadedSeedGenerator
{
    private class SeedGenerator implements Runnable
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
            try
            {
                /**
                 * BlueWhaleSystems fix: Michael Maguire - 10 Aug 2007
                 * 
                 * LOG thread startup.
                 */
                LOG.debug( "ThreadedSeedGenerator.run NEW THREAD" );

                while( !this.stop )
                {
                    this.counter++;
                }
            }
            catch( Throwable t )
            {
                // Catch all possible exceptions in Runnables to avoid app exits.
            }

        }

        public byte[] generateSeed( int numbytes, boolean fast )
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
    public byte[] generateSeed( int numBytes, boolean fast )
    {
        SeedGenerator gen = new SeedGenerator();

        return gen.generateSeed( numBytes, fast );
    }
}
