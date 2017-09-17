package com.tapifolti.createjwt;


/*
Generate private key with self signed certificate:
openssl req -x509 -newkey rsa:2048 -keyout jwttestprivkey.pem -out jwttestcert.pem -days 365 -nodes -subj "/C=HU/ST=Hungary/L=Hungary/O=Lateral/OU=Org/CN=www.lateral.hu"
Extract public key from certificate:
openssl x509 -pubkey -noout -in jwttestcert.pem  > jwttestpubkey.pem
*/

import io.jsonwebtoken.*;

import javax.xml.bind.DatatypeConverter;
import java.io.BufferedReader;
import java.io.FileReader;
import java.security.Key;
import java.security.KeyFactory;


import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Date;

public class GenerateJWT
{
    // TODO
    // generates a JWT token:
    // 1. sign by specified private key
    // 2. JSON params from command prompt
    // using jjwt API
    // verify token with public key

    public static void main( String[] args ) {
        // parameters:
        // 1. private key filename
        // 2. issuer
        // 3. OrderId
        // 4. user
        // 5. fast
        if (args.length != 6) {
            System.out.println("Parameters:");
            System.out.println("<private_key_filename> <public_key_filename> <issuer> <orderid> <user> <isFast>");
        }
        GenerateJWT generateJWT = new GenerateJWT();
        String token = generateJWT.generate(args[0], args[2], args[3], args[4], Boolean.parseBoolean(args[5]));
        generateJWT.verify(args[1], token);
    }

    public boolean verify(String keyFile, String token) {
        try {
            Key pubKey = getKey(false, keyFile);

            Claims claims = Jwts.parser().setSigningKey(pubKey).parseClaimsJws(token).getBody();

            System.out.println("Verified");
            System.out.println("Body content:");
            claims.forEach((x,y) -> System.out.println(x + " : " + ((x.equals("iat"))? claims.getIssuedAt().toString() : y.toString())));
            System.out.println();
            return true;
        } catch (SignatureException e) {
            System.out.println("Not Valid");
            System.out.println(e.getMessage());
            e.printStackTrace();
        } catch (Exception ex) {
            System.out.println(ex.getMessage());
            ex.printStackTrace();
        }
        return false;
    }

    public String generate(String keyFile, String issuer, String orderId, String user, boolean isFast) {

        try {
            SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.RS256;

            long nowMillis = System.currentTimeMillis();
            Date now = new Date(nowMillis);

            Key signingKey = getKey(true, keyFile);

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

            String token = builder.compact();
            System.out.println("Token:");
            System.out.println(token);
            System.out.println();
            return token;
        } catch (Exception ex) {
            System.out.println(ex.getMessage());
            ex.printStackTrace();
            return null;
        }
    }

    public Key getKey(boolean isPrivate, String filename) throws Exception {
        BufferedReader br = new BufferedReader(new FileReader(filename));
        StringBuilder builder = new StringBuilder();
        for (String line = br.readLine(); line != null; line = br.readLine()) {
            if (!line.startsWith("-----BEGIN ") && !line.startsWith("-----END")) {
                builder.append(line);
            }
        }
        byte[] decoded = DatatypeConverter.parseBase64Binary(builder.toString());
        KeyFactory kf = KeyFactory.getInstance("RSA");
        if (!isPrivate) {
            X509EncodedKeySpec spec = new X509EncodedKeySpec(decoded);
            return kf.generatePublic(spec);
        } else {
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(decoded);
            return kf.generatePrivate(spec);
        }
    }
}
