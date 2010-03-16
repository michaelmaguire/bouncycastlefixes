package bwmorg.bouncycastle.asn1;

import java.io.*;

public class DERSequenceGenerator
    extends DERGenerator
{
    private final ByteArrayOutputStream _bOut = new ByteArrayOutputStream();

    public DERSequenceGenerator(
        OutputStream out)
        throws IOException
    {
        super(out);
    }

    public DERSequenceGenerator(
        OutputStream out,
        int          tagNo,
        boolean      isExplicit)
        throws IOException
    {
        super(out, tagNo, isExplicit);
    }

    public void addObject(
        DEREncodable object) 
        throws IOException
    {
        object.getDERObject().encode(new DEROutputStream(_bOut));
    }
    
    public OutputStream getRawOutputStream()
    {
        return _bOut;
    }
    
    public void close() 
        throws IOException
    {
        writeDEREncoded(DERTags.CONSTRUCTED | DERTags.SEQUENCE, _bOut.toByteArray());
    }
}
