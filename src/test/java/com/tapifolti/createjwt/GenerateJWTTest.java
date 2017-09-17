package com.tapifolti.createjwt;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

/**
 * Unit test for simple GenerateJWT.
 */
public class GenerateJWTTest
    extends TestCase
{
    public void testGenerate() {
        GenerateJWT gen = new GenerateJWT();
        String token = gen.generate("keys\\jwttestprivkey.pem", "SelectSpecs", "OrderId1234", "test@gmail.com", true);
        assertTrue( token != null && !token.isEmpty());
        assertTrue( gen.verify("keys\\jwttestpubkey.pem", token));
        System.out.println("token tampered");
        token = token.substring(0, token.length()-1) + "=";
        assertFalse( gen.verify("keys\\jwttestpubkey.pem", token));
    }
}
