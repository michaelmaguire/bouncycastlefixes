package org.bouncycastle.crypto.io;

import java.io.IOException;
import java.io.OutputStream;

import org.bouncycastle.crypto.Digest;

import bigjava.io.FilterOutputStream;

public class DigestOutputStream
    extends FilterOutputStream
{
    protected Digest digest;

    public DigestOutputStream(
        OutputStream    stream,
        Digest          digest)
    {
        super(stream);
        this.digest = digest;
    }

    public void write(int b)
        throws IOException
    {
        digest.update((byte)b);
        out.write(b);
    }

    public void write(
        byte[] b,
        int off,
        int len)
        throws IOException
    {
        digest.update(b, off, len);
        out.write(b, off, len);
    }

    public Digest getDigest()
    {
        return digest;
    }
}
