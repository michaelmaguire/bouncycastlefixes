package bwmorg.bouncycastle.crypto.io;

import java.io.*;

import bigjava.io.FilterInputStream;
import bwmorg.bouncycastle.crypto.Signer;

public class SignerInputStream
    extends FilterInputStream
{
    protected Signer signer;

    public SignerInputStream(
        InputStream stream,
        Signer      signer)
    {
        super(stream);
        this.signer = signer;
    }

    public int read()
        throws IOException
    {
        int b = in.read();

        if (b >= 0)
        {
            signer.update((byte)b);
        }
        return b;
    }

    public int read(
        byte[] b,
        int off,
        int len)
        throws IOException
    {
        int n = in.read(b, off, len);
        if (n > 0)
        {
            signer.update(b, off, n);
        }
        return n;
    }

    public Signer getSigner()
    {
        return signer;
    }
}
