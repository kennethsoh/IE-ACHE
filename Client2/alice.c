#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>
#include <stdio.h>
#include <iostream>
#include <iomanip>
#include <string>
#include <sstream>
#include <bitset>
#include <fstream>
#include <sys/time.h>
#include <time.h>
using namespace std;
ifstream read;

int main()
{
   // generate a keyset
   const int minimum_lambda = 110;
   TFheGateBootstrappingParameterSet* params = new_default_gate_bootstrapping_parameters(minimum_lambda);

   // generate a keyset
   const int minimum_lambda2 = 110;
   TFheGateBootstrappingParameterSet* nbitparams = new_default_gate_bootstrapping_parameters(minimum_lambda2);

   // generate a random key
   uint32_t seed[] = { 314, 1592, 657 };
   tfhe_random_generator_setSeed(seed,3);
   TFheGateBootstrappingSecretKeySet* key = new_random_gate_bootstrapping_secret_keyset(params);

   uint32_t bitseed[] = { 314, 1592, 888 };
   tfhe_random_generator_setSeed(bitseed,3);
   TFheGateBootstrappingSecretKeySet* nbitkey = new_random_gate_bootstrapping_secret_keyset(nbitparams);

   

   struct timeval start, end;
   double get_time;
   gettimeofday(&start, NULL);
   
   int number;  
   int line_no = 0;

   string sLine = "";
   read.open("values.txt");
   
   getline(read, sLine);
   unsigned long long negative = std::bitset<32>(sLine).to_ullong(); // Convert 32 bits to integer (Negativity code)
   std::cout << "Negativity: " << negative << "\n";
   
   ++line_no;
   getline(read, sLine); 
   unsigned long long bitcount = std::bitset<32>(sLine).to_ullong(); // Convert 32 bits to integer (Bit Count)

   LweSample* ciphertextnegative = new_gate_bootstrapping_ciphertext_array(32, nbitparams);
   
   std::cout << "Number of bits for calculation: " << bitcount << "\n"; // Print bit count (converted from binary to integer)

   if (bitcount == 256)
   {
	// Initialise sixteen 32-bit chunks
	int32_t chunk1; int32_t chunk2; int32_t chunk3; int32_t chunk4; int32_t chunk5; int32_t chunk6; int32_t chunk7; int32_t chunk8;
	while (line_no != 10) { // Loop for lines 3 to 9
	getline(read, sLine);
	++line_no;
	unsigned long long value = std::bitset<32>(sLine).to_ullong(); // Convert 32 bits on line 3 to 18 to integer and pass into "value" variable

	if (line_no == 2){
	    	chunk1 = value;
	}else if (line_no == 3){
	    	chunk2 = value;
	}else if (line_no == 4){
	    	chunk3 = value;
	}else if (line_no == 5){
	    	chunk4 = value;
	}else if (line_no == 6){
	    	chunk5 = value;
	}else if (line_no == 7){
	    	chunk6 = value;
	}else if (line_no == 8){
	    	chunk7 = value;
	}else if (line_no == 9){
	    	chunk8 = value;
	}
    }

    read.close();

    // Create 10 ciphertext blocks of 32 bits each
    LweSample* ciphertextbit = new_gate_bootstrapping_ciphertext_array(32, nbitparams);
    LweSample* ciphertext1 = new_gate_bootstrapping_ciphertext_array(32, params);
    LweSample* ciphertext2 = new_gate_bootstrapping_ciphertext_array(32, params);
    LweSample* ciphertext3 = new_gate_bootstrapping_ciphertext_array(32, params);
    LweSample* ciphertext4 = new_gate_bootstrapping_ciphertext_array(32, params);
    LweSample* ciphertext5 = new_gate_bootstrapping_ciphertext_array(32, params);
    LweSample* ciphertext6 = new_gate_bootstrapping_ciphertext_array(32, params);
    LweSample* ciphertext7 = new_gate_bootstrapping_ciphertext_array(32, params);
    LweSample* ciphertext8 = new_gate_bootstrapping_ciphertext_array(32, params);
    LweSample* ciphertext9 = new_gate_bootstrapping_ciphertext_array(32, params);

   int32_t plaintext3 = 0;
   
    for (int i=0; i<32; i++) { // line 0 negtivity
	bootsSymEncrypt(&ciphertextnegative[i], (negative>>i)&1, nbitkey);
    }
   	std::cout << "Negativity: " << negative << "\n";
    for (int i=0; i<32; i++) { // line 1 bit size
	bootsSymEncrypt(&ciphertextbit[i], (bitcount>>i)&1, nbitkey);
    }
    for (int i=0; i<32; i++) { // line 2 value1
	bootsSymEncrypt(&ciphertext1[i], (chunk1>>i)&1, key);
    }
    for (int i=0; i<32; i++) { // line 3 value2
	bootsSymEncrypt(&ciphertext2[i], (chunk2>>i)&1, key);
    }
    for (int i=0; i<32; i++) { // line 4 value3
	bootsSymEncrypt(&ciphertext3[i], (chunk3>>i)&1, key);
    }
    for (int i=0; i<32; i++) { // line 5 value4
	bootsSymEncrypt(&ciphertext4[i], (chunk4>>i)&1, key);
    }
    for (int i=0; i<32; i++) { // line 6 value5
	bootsSymEncrypt(&ciphertext5[i], (chunk5>>i)&1, key);
    }
    for (int i=0; i<32; i++) { // line 7 value6
	bootsSymEncrypt(&ciphertext6[i], (chunk6>>i)&1, key);
    }
    for (int i=0; i<32; i++) { // line 8 value7
	bootsSymEncrypt(&ciphertext7[i], (chunk7>>i)&1, key);
    }
    for (int i=0; i<32; i++) { // line 9 value8
	bootsSymEncrypt(&ciphertext8[i], (chunk8>>i)&1, key);
    }
    for (int i=0; i<32; i++) { // line 10 carry
	bootsSymEncrypt(&ciphertext9[i], (plaintext3>>i)&1, key);
    }
   
    // export the secret key to file for later use
    FILE* secret_key = fopen("secret.key","wb");
    export_tfheGateBootstrappingSecretKeySet_toFile(secret_key, key);
    fclose(secret_key);

    // export the cloud key to a file (for the cloud)
    FILE* cloud_key = fopen("cloud.key","wb");
    export_tfheGateBootstrappingCloudKeySet_toFile(cloud_key, &key->cloud);
    fclose(cloud_key);

    // export the bit key to file for later use
    FILE* nbit_key = fopen("nbit.key","wb");
    export_tfheGateBootstrappingSecretKeySet_toFile(nbit_key, nbitkey);
    fclose(nbit_key);

    // export the 64 ciphertexts to a file (for the cloud)
    FILE* cloud_data = fopen("cloud.data","ab");
    for (int i=0; i<32; i++) // negative
    export_gate_bootstrapping_ciphertext_toFile(cloud_data, &ciphertextnegative[i], nbitparams);
    for (int i = 0; i<32; i++) // bit
    export_gate_bootstrapping_ciphertext_toFile(cloud_data, &ciphertextbit[i], nbitparams);
    for (int i=0; i<32; i++) // 1
	export_gate_bootstrapping_ciphertext_toFile(cloud_data, &ciphertext1[i], params);
    for (int i=0; i<32; i++) // 2
	export_gate_bootstrapping_ciphertext_toFile(cloud_data, &ciphertext2[i], params);
    for (int i = 0; i<32; i++) // 3
	export_gate_bootstrapping_ciphertext_toFile(cloud_data, &ciphertext3[i], params);
    for (int i = 0; i<32; i++) // 4
	export_gate_bootstrapping_ciphertext_toFile(cloud_data, &ciphertext4[i], params);
    for (int i = 0; i<32; i++) // 5
	export_gate_bootstrapping_ciphertext_toFile(cloud_data, &ciphertext5[i], params);
    for (int i = 0; i<32; i++) // 6
	export_gate_bootstrapping_ciphertext_toFile(cloud_data, &ciphertext6[i], params);
    for (int i = 0; i<32; i++) // 7
	export_gate_bootstrapping_ciphertext_toFile(cloud_data, &ciphertext7[i], params);
    for (int i = 0; i<32; i++) // 8
	export_gate_bootstrapping_ciphertext_toFile(cloud_data, &ciphertext8[i], params);
    for (int i = 0; i<32; i++) // 9
	export_gate_bootstrapping_ciphertext_toFile(cloud_data, &ciphertext9[i], params);
	
    fclose(cloud_data);

    // clean up all pointers
    delete_gate_bootstrapping_ciphertext_array(32, ciphertextnegative);
    delete_gate_bootstrapping_ciphertext_array(32, ciphertextbit);
    delete_gate_bootstrapping_ciphertext_array(32, ciphertext1);
    delete_gate_bootstrapping_ciphertext_array(32, ciphertext2);
    delete_gate_bootstrapping_ciphertext_array(32, ciphertext3);
    delete_gate_bootstrapping_ciphertext_array(32, ciphertext4);
    delete_gate_bootstrapping_ciphertext_array(32, ciphertext5);
    delete_gate_bootstrapping_ciphertext_array(32, ciphertext6);
    delete_gate_bootstrapping_ciphertext_array(32, ciphertext7);
    delete_gate_bootstrapping_ciphertext_array(32, ciphertext8);
    delete_gate_bootstrapping_ciphertext_array(32, ciphertext9);
    
    delete_gate_bootstrapping_secret_keyset(key);
    delete_gate_bootstrapping_parameters(params);
   }
   
   if (bitcount == 128) // If bitcount is 128, only need to use up to line 14 as value 2 only needs half of full space (4 lines)
   {
	int32_t chunk1; int32_t chunk2; int32_t chunk3; int32_t chunk4;
	while (line_no != 6) {
	getline(read, sLine);
	++line_no;
	unsigned long long value = std::bitset<32>(sLine).to_ullong();
	if (line_no == 2){
	    	chunk1 = value;
	}else if (line_no == 3){
	    	chunk2 = value;
	}else if (line_no == 4){
	    	chunk3 = value;
	}else if (line_no == 5){
	    	chunk4 = value;
	}
    }
    

    read.close();
    
    LweSample* ciphertextbit = new_gate_bootstrapping_ciphertext_array(32, nbitparams);
    LweSample* ciphertext1 = new_gate_bootstrapping_ciphertext_array(32, params);
    LweSample* ciphertext2 = new_gate_bootstrapping_ciphertext_array(32, params);
    LweSample* ciphertext3 = new_gate_bootstrapping_ciphertext_array(32, params);
    LweSample* ciphertext4 = new_gate_bootstrapping_ciphertext_array(32, params);
    LweSample* ciphertext5 = new_gate_bootstrapping_ciphertext_array(32, params);
    LweSample* ciphertext6 = new_gate_bootstrapping_ciphertext_array(32, params);
    LweSample* ciphertext7 = new_gate_bootstrapping_ciphertext_array(32, params);
    LweSample* ciphertext8 = new_gate_bootstrapping_ciphertext_array(32, params);
    LweSample* ciphertext9 = new_gate_bootstrapping_ciphertext_array(32, params);
    
   int32_t plaintext3 = 0;
   
   for (int i=0; i<32; i++) {
	bootsSymEncrypt(&ciphertextnegative[i], (negative>>i)&1, nbitkey);
    }
    for (int i=0; i<32; i++) {
	bootsSymEncrypt(&ciphertextbit[i], (bitcount>>i)&1, nbitkey);
    }
    for (int i=0; i<32; i++) {
	bootsSymEncrypt(&ciphertext1[i], (chunk1>>i)&1, key);
    }
    for (int i=0; i<32; i++) {
	bootsSymEncrypt(&ciphertext2[i], (chunk2>>i)&1, key);
    }
    for (int i=0; i<32; i++) {
	bootsSymEncrypt(&ciphertext3[i], (chunk3>>i)&1, key);
    }
    for (int i=0; i<32; i++) {
	bootsSymEncrypt(&ciphertext4[i], (chunk4>>i)&1, key);
    }
    for (int i=0; i<32; i++) {
	bootsSymEncrypt(&ciphertext5[i], (plaintext3>>i)&1, key);
    }
    for (int i=0; i<32; i++) {
	bootsSymEncrypt(&ciphertext6[i], (plaintext3>>i)&1, key);
    }
    for (int i=0; i<32; i++) {
	bootsSymEncrypt(&ciphertext7[i], (plaintext3>>i)&1, key);
    }
    for (int i=0; i<32; i++) {
	bootsSymEncrypt(&ciphertext8[i], (plaintext3>>i)&1, key);
    }
    for (int i=0; i<32; i++) {
	bootsSymEncrypt(&ciphertext9[i], (plaintext3>>i)&1, key);
    }
   
    // export the secret key to file for later use
    FILE* secret_key = fopen("secret.key","wb");
    export_tfheGateBootstrappingSecretKeySet_toFile(secret_key, key);
    fclose(secret_key);

    // export the cloud key to a file (for the cloud)
    FILE* cloud_key = fopen("cloud.key","wb");
    export_tfheGateBootstrappingCloudKeySet_toFile(cloud_key, &key->cloud);
    fclose(cloud_key);

    // export the bit key to file for later use
    FILE* nbit_key = fopen("nbit.key","wb");
    export_tfheGateBootstrappingSecretKeySet_toFile(nbit_key, nbitkey);
    fclose(nbit_key);

    // export the 64 ciphertexts to a file (for the cloud)
    FILE* cloud_data = fopen("cloud.data","ab");
    for (int i=0; i<32; i++)
    export_gate_bootstrapping_ciphertext_toFile(cloud_data, &ciphertextnegative[i], nbitparams);
    for (int i = 0; i<32; i++)
    export_gate_bootstrapping_ciphertext_toFile(cloud_data, &ciphertextbit[i], nbitparams);
    for (int i=0; i<32; i++)
	export_gate_bootstrapping_ciphertext_toFile(cloud_data, &ciphertext1[i], params);
    for (int i=0; i<32; i++)
	export_gate_bootstrapping_ciphertext_toFile(cloud_data, &ciphertext2[i], params);
    for (int i = 0; i<32; i++)
	export_gate_bootstrapping_ciphertext_toFile(cloud_data, &ciphertext3[i], params);
    for (int i = 0; i<32; i++)
	export_gate_bootstrapping_ciphertext_toFile(cloud_data, &ciphertext4[i], params);
    for (int i = 0; i<32; i++)
	export_gate_bootstrapping_ciphertext_toFile(cloud_data, &ciphertext5[i], params);
    for (int i = 0; i<32; i++) // 6
	export_gate_bootstrapping_ciphertext_toFile(cloud_data, &ciphertext6[i], params);
    for (int i = 0; i<32; i++) // 7
	export_gate_bootstrapping_ciphertext_toFile(cloud_data, &ciphertext7[i], params);
    for (int i = 0; i<32; i++) // 8
	export_gate_bootstrapping_ciphertext_toFile(cloud_data, &ciphertext8[i], params);
    for (int i = 0; i<32; i++) // 9
	export_gate_bootstrapping_ciphertext_toFile(cloud_data, &ciphertext9[i], params);
    fclose(cloud_data);

    // clean up all pointers
    delete_gate_bootstrapping_ciphertext_array(32, ciphertextnegative);
    delete_gate_bootstrapping_ciphertext_array(32, ciphertextbit);
    delete_gate_bootstrapping_ciphertext_array(32, ciphertext1);
    delete_gate_bootstrapping_ciphertext_array(32, ciphertext2);
    delete_gate_bootstrapping_ciphertext_array(32, ciphertext3);
    delete_gate_bootstrapping_ciphertext_array(32, ciphertext4);
    delete_gate_bootstrapping_ciphertext_array(32, ciphertext5);
    delete_gate_bootstrapping_ciphertext_array(32, ciphertext6);
    delete_gate_bootstrapping_ciphertext_array(32, ciphertext7);
    delete_gate_bootstrapping_ciphertext_array(32, ciphertext8);
    delete_gate_bootstrapping_ciphertext_array(32, ciphertext9);
    
    delete_gate_bootstrapping_secret_keyset(key);
    delete_gate_bootstrapping_parameters(params);
   }
   
   if (bitcount == 64){
   int32_t chunk1;
   int32_t chunk2;
   while (line_no != 4) {
	getline(read, sLine);
	++line_no;
	unsigned long long value = std::bitset<32>(sLine).to_ullong();
	if (line_no == 2){
	    	chunk1 = value;
	}else if (line_no == 3){
	    	chunk2 = value;
	}
    }
    
    read.close();
   
    LweSample* ciphertextbit = new_gate_bootstrapping_ciphertext_array(32, nbitparams);
    LweSample* ciphertext1 = new_gate_bootstrapping_ciphertext_array(32, params);
    LweSample* ciphertext2 = new_gate_bootstrapping_ciphertext_array(32, params);
    LweSample* ciphertext3 = new_gate_bootstrapping_ciphertext_array(32, params);
    LweSample* ciphertext4 = new_gate_bootstrapping_ciphertext_array(32, params);
    LweSample* ciphertext5 = new_gate_bootstrapping_ciphertext_array(32, params);
    LweSample* ciphertext6 = new_gate_bootstrapping_ciphertext_array(32, params);
    LweSample* ciphertext7 = new_gate_bootstrapping_ciphertext_array(32, params);
    LweSample* ciphertext8 = new_gate_bootstrapping_ciphertext_array(32, params);
    LweSample* ciphertext9 = new_gate_bootstrapping_ciphertext_array(32, params);
    
   int32_t plaintext3 = 0;
   for (int i=0; i<32; i++) {
	bootsSymEncrypt(&ciphertextnegative[i], (negative>>i)&1, nbitkey);
    }
    for (int i=0; i<32; i++) {
	bootsSymEncrypt(&ciphertextbit[i], (bitcount>>i)&1, nbitkey);
    }
    for (int i=0; i<32; i++) {
	bootsSymEncrypt(&ciphertext1[i], (chunk1>>i)&1, key);
    }
    for (int i=0; i<32; i++) {
	bootsSymEncrypt(&ciphertext2[i], (chunk2>>i)&1, key);
    }
    for (int i=0; i<32; i++) {
	bootsSymEncrypt(&ciphertext3[i], (plaintext3>>i)&1, key);
    }
    for (int i=0; i<32; i++) {
	bootsSymEncrypt(&ciphertext4[i], (plaintext3>>i)&1, key);
    }
    for (int i=0; i<32; i++) {
	bootsSymEncrypt(&ciphertext5[i], (plaintext3>>i)&1, key);
    }
    for (int i=0; i<32; i++) {
	bootsSymEncrypt(&ciphertext6[i], (plaintext3>>i)&1, key);
    }
    for (int i=0; i<32; i++) {
	bootsSymEncrypt(&ciphertext7[i], (plaintext3>>i)&1, key);
    }
    for (int i=0; i<32; i++) {
	bootsSymEncrypt(&ciphertext8[i], (plaintext3>>i)&1, key);
    }
    for (int i=0; i<32; i++) {
	bootsSymEncrypt(&ciphertext9[i], (plaintext3>>i)&1, key);
    }
    
   
    // export the secret key to file for later use
    FILE* secret_key = fopen("secret.key","wb");
    export_tfheGateBootstrappingSecretKeySet_toFile(secret_key, key);
    fclose(secret_key);

    // export the cloud key to a file (for the cloud)
    FILE* cloud_key = fopen("cloud.key","wb");
    export_tfheGateBootstrappingCloudKeySet_toFile(cloud_key, &key->cloud);
    fclose(cloud_key);

    // export the bit key to file for later use
    FILE* nbit_key = fopen("nbit.key","wb");
    export_tfheGateBootstrappingSecretKeySet_toFile(nbit_key, nbitkey);
    fclose(nbit_key);

    // export the 64 ciphertexts to a file (for the cloud)
    FILE* cloud_data = fopen("cloud.data","ab");
    for (int i=0; i<32; i++)
    export_gate_bootstrapping_ciphertext_toFile(cloud_data, &ciphertextnegative[i], nbitparams);
    for (int i = 0; i<32; i++)
    export_gate_bootstrapping_ciphertext_toFile(cloud_data, &ciphertextbit[i], nbitparams);
    for (int i=0; i<32; i++)  // 1
	export_gate_bootstrapping_ciphertext_toFile(cloud_data, &ciphertext1[i], params);
    for (int i=0; i<32; i++)  // 2
	export_gate_bootstrapping_ciphertext_toFile(cloud_data, &ciphertext2[i], params);
    for (int i = 0; i<32; i++) // 3
	export_gate_bootstrapping_ciphertext_toFile(cloud_data, &ciphertext3[i], params);
    for (int i = 0; i<32; i++) // 4
	export_gate_bootstrapping_ciphertext_toFile(cloud_data, &ciphertext4[i], params);
    for (int i = 0; i<32; i++) // 5
	export_gate_bootstrapping_ciphertext_toFile(cloud_data, &ciphertext5[i], params);
    for (int i = 0; i<32; i++) // 6
	export_gate_bootstrapping_ciphertext_toFile(cloud_data, &ciphertext6[i], params);
    for (int i = 0; i<32; i++) // 7
	export_gate_bootstrapping_ciphertext_toFile(cloud_data, &ciphertext7[i], params);
    for (int i = 0; i<32; i++) // 8
	export_gate_bootstrapping_ciphertext_toFile(cloud_data, &ciphertext8[i], params);
    for (int i = 0; i<32; i++) // 9
	export_gate_bootstrapping_ciphertext_toFile(cloud_data, &ciphertext9[i], params);
    
    fclose(cloud_data);

    // clean up all pointers
    delete_gate_bootstrapping_ciphertext_array(32, ciphertextnegative);
    delete_gate_bootstrapping_ciphertext_array(32, ciphertextbit);
    delete_gate_bootstrapping_ciphertext_array(32, ciphertext1);
    delete_gate_bootstrapping_ciphertext_array(32, ciphertext2);
    delete_gate_bootstrapping_ciphertext_array(32, ciphertext3);
    delete_gate_bootstrapping_ciphertext_array(32, ciphertext4);
    delete_gate_bootstrapping_ciphertext_array(32, ciphertext5);
    delete_gate_bootstrapping_ciphertext_array(32, ciphertext6);
    delete_gate_bootstrapping_ciphertext_array(32, ciphertext7);
    delete_gate_bootstrapping_ciphertext_array(32, ciphertext8);
    delete_gate_bootstrapping_ciphertext_array(32, ciphertext9);
    
    delete_gate_bootstrapping_secret_keyset(key);
    delete_gate_bootstrapping_parameters(params);
    
    }
   else if (bitcount == 32){
	int32_t chunk1;
	while (line_no != 4) {
	    getline(read, sLine);
	    ++line_no;
	    unsigned long long value = std::bitset<32>(sLine).to_ullong();
	    if (line_no == 2){
		chunk1 = value;
	    }
	}
	    
	read.close();
	 
    LweSample* ciphertextbit = new_gate_bootstrapping_ciphertext_array(32, nbitparams);
    LweSample* ciphertext1 = new_gate_bootstrapping_ciphertext_array(32, params);
    LweSample* ciphertext2 = new_gate_bootstrapping_ciphertext_array(32, params);
    LweSample* ciphertext3 = new_gate_bootstrapping_ciphertext_array(32, params);
    LweSample* ciphertext4 = new_gate_bootstrapping_ciphertext_array(32, params);
    LweSample* ciphertext5 = new_gate_bootstrapping_ciphertext_array(32, params);
    LweSample* ciphertext6 = new_gate_bootstrapping_ciphertext_array(32, params);
    LweSample* ciphertext7 = new_gate_bootstrapping_ciphertext_array(32, params);
    LweSample* ciphertext8 = new_gate_bootstrapping_ciphertext_array(32, params);
    LweSample* ciphertext9 = new_gate_bootstrapping_ciphertext_array(32, params);
	 
	int32_t plaintext3 = 0;
	
	for (int i=0; i<32; i++) {
		bootsSymEncrypt(&ciphertextnegative[i], (negative>>i)&1, nbitkey);
	}
	for (int i=0; i<32; i++) {
		bootsSymEncrypt(&ciphertextbit[i], (bitcount>>i)&1, nbitkey);
	}
	for (int i=0; i<32; i++) {
		bootsSymEncrypt(&ciphertext1[i], (chunk1>>i)&1, key);
	}
	for (int i=0; i<32; i++) {
		bootsSymEncrypt(&ciphertext2[i], (plaintext3>>i)&1, key);
	}
	for (int i=0; i<32; i++) {
		bootsSymEncrypt(&ciphertext3[i], (plaintext3>>i)&1, key);
	}
	for (int i=0; i<32; i++) {
		bootsSymEncrypt(&ciphertext4[i], (plaintext3>>i)&1, key);
	}
	for (int i=0; i<32; i++) {
		bootsSymEncrypt(&ciphertext5[i], (plaintext3>>i)&1, key);
	}
	for (int i=0; i<32; i++) {
		bootsSymEncrypt(&ciphertext6[i], (plaintext3>>i)&1, key);
	}
	for (int i=0; i<32; i++) {
		bootsSymEncrypt(&ciphertext7[i], (plaintext3>>i)&1, key);
	}
	for (int i=0; i<32; i++) {
		bootsSymEncrypt(&ciphertext8[i], (plaintext3>>i)&1, key);
	}
	for (int i=0; i<32; i++) {
		bootsSymEncrypt(&ciphertext9[i], (plaintext3>>i)&1, key);
	}
		
	    // export the secret key to file for later use
	   FILE* secret_key = fopen("secret.key","wb");
	   export_tfheGateBootstrappingSecretKeySet_toFile(secret_key, key);
	   fclose(secret_key);

	   // export the cloud key to a file (for the cloud)
	   FILE* cloud_key = fopen("cloud.key","wb");
	   export_tfheGateBootstrappingCloudKeySet_toFile(cloud_key, &key->cloud);
	   fclose(cloud_key);

       // export the bit key to file for later use
       FILE* nbit_key = fopen("nbit.key","wb");
       export_tfheGateBootstrappingSecretKeySet_toFile(nbit_key, nbitkey);
       fclose(nbit_key);

	   // export the 64 ciphertexts to a file (for the cloud)
	   FILE* cloud_data = fopen("cloud.data","ab"); // TODO change to wb
	   for (int i=0; i<32; i++)
        export_gate_bootstrapping_ciphertext_toFile(cloud_data, &ciphertextnegative[i], nbitparams);
	   for (int i=0; i<32; i++)
		export_gate_bootstrapping_ciphertext_toFile(cloud_data, &ciphertextbit[i], nbitparams);
	   for (int i = 0; i<32; i++) // 1
		export_gate_bootstrapping_ciphertext_toFile(cloud_data, &ciphertext1[i], params);
	   for (int i = 0; i<32; i++) // 2
		export_gate_bootstrapping_ciphertext_toFile(cloud_data, &ciphertext2[i], params);
	   for (int i = 0; i<32; i++) // 3
		export_gate_bootstrapping_ciphertext_toFile(cloud_data, &ciphertext3[i], params);
	   for (int i = 0; i<32; i++) // 4
		export_gate_bootstrapping_ciphertext_toFile(cloud_data, &ciphertext4[i], params);
	   for (int i = 0; i<32; i++) // 5
		export_gate_bootstrapping_ciphertext_toFile(cloud_data, &ciphertext5[i], params);
	   for (int i = 0; i<32; i++) // 6
		export_gate_bootstrapping_ciphertext_toFile(cloud_data, &ciphertext6[i], params);
	   for (int i = 0; i<32; i++) // 7
		export_gate_bootstrapping_ciphertext_toFile(cloud_data, &ciphertext7[i], params);
	   for (int i = 0; i<32; i++) // 8
		export_gate_bootstrapping_ciphertext_toFile(cloud_data, &ciphertext8[i], params);
	   for (int i = 0; i<32; i++) // 9
		export_gate_bootstrapping_ciphertext_toFile(cloud_data, &ciphertext9[i], params);
	   fclose(cloud_data);

	   // clean up all pointers
	   delete_gate_bootstrapping_ciphertext_array(32, ciphertextnegative);
	   delete_gate_bootstrapping_ciphertext_array(32, ciphertextbit);

	   delete_gate_bootstrapping_ciphertext_array(32, ciphertext1);
	   delete_gate_bootstrapping_ciphertext_array(32, ciphertext2);
	   delete_gate_bootstrapping_ciphertext_array(32, ciphertext3);
	   delete_gate_bootstrapping_ciphertext_array(32, ciphertext4);
	   delete_gate_bootstrapping_ciphertext_array(32, ciphertext5);
	   delete_gate_bootstrapping_ciphertext_array(32, ciphertext6);
	   delete_gate_bootstrapping_ciphertext_array(32, ciphertext7);
	   delete_gate_bootstrapping_ciphertext_array(32, ciphertext8);
	   delete_gate_bootstrapping_ciphertext_array(32, ciphertext9);

	   delete_gate_bootstrapping_secret_keyset(key);
	   delete_gate_bootstrapping_parameters(params);
    }
    // Timings
    gettimeofday(&end, NULL);
    get_time = (end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec) * 1.0E-6;
    printf("Computation Time: %lf[sec]\n", get_time);
    
    return 0; // status code 0 -- success
}
