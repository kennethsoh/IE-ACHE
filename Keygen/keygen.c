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
   struct timeval start, end;
   double get_time;
   gettimeofday(&start, NULL);
   
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
   
    // Timings
    gettimeofday(&end, NULL);
    get_time = (end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec) * 1.0E-6;
    printf("Computation Time: %lf[sec]\n", get_time);
    
    return 0; // status code 0 -- success
}
