# rsa

to build project run: go build -o encrypt.exe

# flags

-genKeys      generates keys
-decrypt      decrypts your file  
-i            specifies path to input file  
-o            specifies path to output file  
-public       path to public key
-private      path to private key


# examples of usage

keys generation:  
./encrypt.exe -genkeys -o key

usage:

./encrypt.exe -i sample.txt -o encrypted.txt -private key_private.bson

./encrypt.exe -i encrypted.txt -o decrypted.txt -private key_private.bson -decrypt
