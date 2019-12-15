#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

//*******************************************************
//convert given hex character to ascii character
//helper funcitons, idea for functions credired to Arunbalaji Sivakumar
int hex_to_int(char c){
        int first = c / 16 - 3;
        int second = c % 16;
        int result = first*10 + second;
        if(result > 9) result--;
        return result;
}

//*******************************************************
//convert given hex character to ascii character
int hex_to_ascii(char c, char d){
        int high = hex_to_int(c) * 16;
        int low = hex_to_int(d);
        return high+low;
}

//*******************************************************


int main(int arc, char *argv[])
{	
	//initialize buffer variables
        unsigned char outbuf[1024];
        unsigned char cipher[1024];
        unsigned char temp, key[16];
	
	//initialize integer variabels
        int outlen, tmplen, l, i, length, count, found =0, k = 0;
        size_t nread, len;
        FILE *in;
        unsigned char iv[17];
	
	//fill the IV zeros
        for(i = 0; i < 17; i++){
           iv[i] = 0;
	}
	
	//termination character
        iv[16] = '\0';
	
	//provided input text 
        char intext[] = "This is a top secret.";
	
	//provided output cupher text
        char st[] = "8d20e5056a8d24d0462ce74e4904c1b513e10d1df4a2ef2ad4540fae1ca0aaf9";
        i = 0;
	
	//look for aphabetic characters
        while(i < 64)
        {
		//shift characters           
		if(st[i] >= 'a' && st[i] <= 'z')
                 st[i] = st[i] - 32;
           i++;
        }

        length = strlen(st);
        char buf = 0;
	
        //iterate through the cipher text and convert to ascii cahracters
        for(i = 0; i < length; i++){
           if(i % 2 != 0)
           {             
              cipher[k] = hex_to_ascii(buf, st[i]);
              k++;
           }
           else
              buf = st[i];
        }
	
	//open the words text file 
        cipher[k] = '\0';
        in = fopen("/home/seed/Desktop/program/words.txt", "r");

        EVP_CIPHER_CTX ctx;       
        EVP_CIPHER_CTX_init(&ctx);
	

	//get the key from the list
	//compare the cipher text produced from this key to
	//the expected cypher text
  //reffered to code by Arunbalaji Sivakumar for the fucntionality of this section 
        while(fgets(key, sizeof(key), in) != NULL)
        {
            l = 0;
            if(strlen(key) < 16){
                l = strlen(key)-1;
                while(l < 16){
                     key[l] = ' ';
                     l++;
                }
                key[l] = '\0';
            }
            else{
                key[16] = '\0';
		}
		
		
	    //call the evp encryption funcitons
            EVP_EncryptInit_ex(&ctx, EVP_aes_128_cbc(), NULL, key, iv);

           outlen += tmplen;
           EVP_CIPHER_CTX_cleanup(&ctx);

           count = 0;
           for(i = 0; i < 32; i++)
           {
              if(cipher[i] == outbuf[i])
                   count++;
           }

        //print the key
        if(count == 32)
           {
              printf("\n Encryption key has been found: ",key);
              found = 1;
              break;
           }
       }

  
        fclose(in);

        return 0;
    }

      
