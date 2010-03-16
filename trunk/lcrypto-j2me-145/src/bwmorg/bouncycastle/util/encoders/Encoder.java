package bwmorg.bouncycastle.util.encoders;

import java.io.*;

/**
 * Encode and decode byte arrays (typically from binary to 7-bit ASCII 
 * encodings).
 */
public interface Encoder
{
    int encode(byte[] data, int off, int length, OutputStream out) throws IOException;
    
    int decode(byte[] data, int off, int length, OutputStream out) throws IOException;

    int decode(String data, OutputStream out) throws IOException;
}
