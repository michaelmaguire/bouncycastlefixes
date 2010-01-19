package bwmorg.bouncycastle.util.test;

public interface Test
{
    String getName();

    TestResult perform();
}
