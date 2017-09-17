# CreateJWT
Creates signed JWT token

1. Run `mvn clean install` to build application
1. Start application with `java -jar target/CreateJWT-1.0-SNAPSHOT.jar <private_key_filename> <public_key_filename> <issuer> <orderid> <user> <isFast>`
   For example: `java -jar target/CreateJWT-1.0-SNAPSHOT.jar keys\jwttestprivkey.pem keys\jwttestpubkey.pem Selectspecs OrderId9876 test@gmail.com false`