package bwmorg.bouncycastle.crypto.test;

import bwmorg.bouncycastle.crypto.BlockCipher;
import bwmorg.bouncycastle.crypto.DataLengthException;
import bwmorg.bouncycastle.crypto.params.KeyParameter;
import bwmorg.bouncycastle.util.test.SimpleTest;

public abstract class CipherTest
    extends SimpleTest
{
    private SimpleTest[]      _tests;
    private BlockCipher _engine;
    private KeyParameter _validKey;

//    protected CipherTest(
//        SimpleTest[]  tests)
//    {
//        _tests = tests;
//    }

    protected CipherTest(
        SimpleTest[]   tests,
        BlockCipher  engine,
        KeyParameter validKey)
    {
        _tests = tests;
        _engine = engine;
        _validKey = validKey;
    }
    
    public abstract String getName();

    public void performTest()
        throws Exception
    {
        for (int i = 0; i != _tests.length; i++)
        {
            _tests[i].performTest();
        }

        if (_engine != null)
        {
            //
            // state tests
            //
            byte[]      buf = new byte[16];
            
            try
            {   
                _engine.processBlock(buf, 0, buf, 0);
                
                fail("failed initialisation check");
            }
            catch (IllegalStateException e)
            {
                // expected 
            }
            
            bufferSizeCheck((_engine));
        }
    }
    
    private void bufferSizeCheck(
        BlockCipher engine)
    {
        byte[] correctBuf = new byte[engine.getBlockSize()];
        byte[] shortBuf = new byte[correctBuf.length / 2];
        
        engine.init(true, _validKey);
        
        try
        {   
            engine.processBlock(shortBuf, 0, correctBuf, 0);
            
            fail("failed short input check");
        }
        catch (DataLengthException e)
        {
            // expected 
        }
        
        try
        {   
            engine.processBlock(correctBuf, 0, shortBuf, 0);
            
            fail("failed short output check");
        }
        catch (DataLengthException e)
        {
            // expected 
        }
        
        engine.init(false, _validKey);
        
        try
        {   
            engine.processBlock(shortBuf, 0, correctBuf, 0);
            
            fail("failed short input check");
        }
        catch (DataLengthException e)
        {
            // expected 
        }
        
        try
        {   
            engine.processBlock(correctBuf, 0, shortBuf, 0);
            
            fail("failed short output check");
        }
        catch (DataLengthException e)
        {
            // expected 
        }
    }
}
