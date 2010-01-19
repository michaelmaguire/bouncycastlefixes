package bwmorg.bouncycastle.asn1.test;

import bwmorg.bouncycastle.asn1.ASN1EncodableVector;
import bwmorg.bouncycastle.asn1.ASN1Set;
import bwmorg.bouncycastle.asn1.ASN1TaggedObject;
import bwmorg.bouncycastle.asn1.BERSet;
import bwmorg.bouncycastle.asn1.DERBitString;
import bwmorg.bouncycastle.asn1.DERBoolean;
import bwmorg.bouncycastle.asn1.DERInteger;
import bwmorg.bouncycastle.asn1.DEROctetString;
import bwmorg.bouncycastle.asn1.DERSequence;
import bwmorg.bouncycastle.asn1.DERSet;
import bwmorg.bouncycastle.asn1.DERTaggedObject;
import bwmorg.bouncycastle.util.test.SimpleTestResult;
import bwmorg.bouncycastle.util.test.Test;
import bwmorg.bouncycastle.util.test.TestResult;

/**
 * Set sorting test example
 */
public class SetTest
    implements Test
{

    public String getName()
    {
        return "Set";
    }
    
    public TestResult perform()
    {
        try
        {
            ASN1EncodableVector v = new ASN1EncodableVector();
            byte[] data = new byte[10];
         
            v.add(new DEROctetString(data));
            v.add(new DERBitString(data));
            v.add(new DERInteger(100)); 
            v.add(new DERBoolean(true));
            
            ASN1Set s = new DERSet(v);
            
            if (!(s.getObjectAt(0) instanceof DERBoolean))
            {
                return new SimpleTestResult(false, getName() + ": sorting failed.");
            }

            s = new BERSet(v);
            
            if (!(s.getObjectAt(0) instanceof DEROctetString))
            {
                return new SimpleTestResult(false, getName() + ": BER set sort order changed.");
            }
            
            // create an implicitly tagged "set" without sorting
            ASN1TaggedObject tag = new DERTaggedObject(false, 1, new DERSequence(v));
            s = ASN1Set.getInstance(tag, false);
            
            if (s.getObjectAt(0) instanceof DERBoolean)
            {
                return new SimpleTestResult(false, getName() + ": sorted when shouldn't be.");
            }

            // equality test
            v = new ASN1EncodableVector();

            v.add(new DERBoolean(true));
            v.add(new DERBoolean(true));
            v.add(new DERBoolean(true));

            s = new DERSet(v);
            
            return new SimpleTestResult(true, getName() + ": Okay");
        }
        catch (Exception e)
        {
            return new SimpleTestResult(false, getName() + ": Exception - " + e.toString(), e);
        }
    }

    public static void main(
        String[]    args)
    {
        Test    test = new SetTest();

        TestResult  result = test.perform();

        System.out.println(result);
    }
}
