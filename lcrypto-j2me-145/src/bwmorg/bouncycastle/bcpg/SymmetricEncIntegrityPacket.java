package bwmorg.bouncycastle.bcpg;

import java.io.IOException;

import bigjava.io.*;

/**
 */
public class SymmetricEncIntegrityPacket 
    extends InputStreamPacket
{    
    int        version;
    
    SymmetricEncIntegrityPacket(
        BCPGInputStream    in)
        throws IOException
    {
        super(in);
        
        version = in.read();
    }
}
