#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>

//This funciton is used to generate a 24bit mesasge digest
//for the message passed to it
//Credit to kevinxw for function reference
void getHash(char * hashname, char *msg, unsigned char *md_value) {
	
	//Initialize digest parameters
	EVP_MD_CTX *mdctx;
	const EVP_MD *md;
	int md_len, i;
	
	//Add all digests to the program
	// credit to John Dorman for this suggestion
	OpenSSL_add_all_digests();
	
	//Throw an error if we are given a bad hash
	//taken from example program
	md = EVP_get_digestbyname(hashname);
	if(!md) {
		printf("Unknown message digest %s\n", hashname);
		exit(1);
	}

	//generate and return hash
	//hash generation taken from sample program
	mdctx = EVP_MD_CTX_create();
	EVP_DigestInit_ex(mdctx, md, NULL);
	EVP_DigestUpdate(mdctx, msg, strlen(msg));
	EVP_DigestFinal_ex(mdctx, md_value, &md_len);
	EVP_MD_CTX_destroy(mdctx);
}

//this function is used to create random strings for purposes 
//hash collision detection 
void randomMessage(char *msg) {
	int i;
	for (i=0;i<11;i++)
		msg[i] = rand()%256-128;
}

//This funciton takes an already provided hash
//attempts to find a message that will create the same digest
int crackHash(char * hashname) {
	//Initialize message parameters
	char msg1[11], msg2[11];
	unsigned char digt1[EVP_MAX_MD_SIZE], digt2[EVP_MAX_MD_SIZE];
	int count=0, i;
	
	//Get the hash that we will try to be cracking
	//This is the hash that will be cmpared in every iteraton of the
	//test
	randomMessage(msg1);
	getHash(hashname, msg1, digt1);
	// run the crack
	do {
		//generate random message and hash 
		randomMessage(msg2);
		getHash(hashname, msg2, digt2);
		count++;
		//compare the 2 hashes
	} while (strncmp(digt1, digt2, 3)!=0);
	printf("hash cracked: %d tries, digest =", count, msg1, msg2);
	for(i = 0; i < 3; i++) printf("%02x", digt1[i]);
	printf("\n");
	return count;
}

//Function used to check file hashes for collisions
//Referred to github.com/kevinxw for function construction
int crackCollision(char * hashname) {
	//Initilize our message inputs
	char msg1[11], msg2[11];
	unsigned char digt1[EVP_MAX_MD_SIZE], digt2[EVP_MAX_MD_SIZE];
	int count=0, i;
	//generate random hashes
	//check if the hashes are equal until there are 2 equal values
	do {
		//Genreate random message and has1 
		randomMessage(msg1);
		getHash(hashname, msg1, digt1);
		//Generate random message and hash2
		randomMessage(msg2);
		getHash(hashname, msg2, digt2);
		count++;

		//Compare the 2 hashes
	} while (strncmp(digt1, digt2, 3)!=0);
	//printf("\n cracked after %d tries! %s and %s has same digest ", count, msg1, msg2);
	printf("hash cracked: %d tries, digest = ", count);
	for(i = 0; i < 3; i++) printf("%02x", digt1[i]);
	printf("\n");
	return count;
}

main(int argc, char *argv[])
{
	//will be testing using md5 for simplicity sake
	char *hashname;
	hashname = "md5";
	
	//create a random seed
	srand((int)time(0));	
	
	//initialize counter variables
	int i;
	int count;

	//Run through the collision detection checker 15 times and 
	//output the average of each of these times
	for (i=0,count=0;i<10;i++){
		count+=crackCollision(hashname);
	}
	printf("collision-free cracking average: %d \n", count/10);
	
	//Run through the one-way hash collision detection checker 5 times and 
	//output the average of each of these times
	for (i=0,count=0;i<5;i++){
		count+=crackHash(hashname);
	}
	printf("one-way cracking average: %d \n", count/5);
}