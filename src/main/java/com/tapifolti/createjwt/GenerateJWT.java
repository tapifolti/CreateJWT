package com.tapifolti.createjwt;


/*
Generate private key with self signed certificate:
openssl req -x509 -newkey rsa:2048 -keyout jwttestprivkey.pem -out jwttestcert.pem -days 365 -nodes -subj "/C=HU/ST=Hungary/L=Hungary/O=Lateral/OU=Org/CN=www.lateral.hu"
Extract public key from certificate:
openssl x509 -pubkey -noout -in jwttestcert.pem  > jwttestpubkey.pem
*/

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.nio.file.Files;
import java.security.Key;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Collection;
import java.util.Date;
import java.util.Map;
import java.util.Set;

public class GenerateJWT
{
    // TODO
    // generates a JWT token:
    // 1. sign by specified private key
    // 2. JSON params from command prompt
    // using jjwt API

    public static void main( String[] args ) {
        // parameters:
        // 1. private key
        // 2. issuer
        // 3. OrderId
        // 4. user
        // 5. fast
    }

    private String generate(String keyFile, String issuer, String orderId, String user, boolean isFast) {

        try {
            SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.RS256;

            long nowMillis = System.currentTimeMillis();
            Date now = new Date(nowMillis);

            Key signingKey = getPrivate(keyFile);

            //Let's set the JWT Claims
            JwtBuilder builder = Jwts.builder()
                    .claim("ver", "1.0")
                    .setIssuer(issuer)
                    .setIssuedAt(now)
                    .setSubject("glass")
                    .claim("oid", orderId)
                    .claim("user", user)
                    .claim("fast", Boolean.toString(isFast))
                    .signWith(signatureAlgorithm, signingKey);

            return builder.compact();
        } catch (Exception ex) {
            System.out.println(ex.getMessage());
            System.out.println(ex.getStackTrace());
            return null;
        }
    }

    public PrivateKey getPrivate(String filename) throws Exception {
        byte[] keyBytes = Files.readAllBytes(new File(filename).toPath());
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(spec);
    }
}
