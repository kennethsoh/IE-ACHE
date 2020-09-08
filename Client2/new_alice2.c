#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>
#include <stdio.h>

int main() {

    // generate a keyset
    const int minimum_lambda = 110;
    TFheGateBootstrappingParameterSet* params = new_default_gate_bootstrapping_parameters(minimum_lambda);

    // generate a random key
    uint32_t seed[] = { 314, 1592, 657 };
    tfhe_random_generator_setSeed(seed,3);
    TFheGateBootstrappingSecretKeySet* key = new_random_gate_bootstrapping_secret_keyset(params);

    // generate encrypt for the 32 bits
    int32_t plaintext1 = 2222;
	/*
    int32_t plaintext1;
    int32_t a = 1;
    while (a == 1){
            printf("Please enter a 32 bit number: ");
            scanf("%d", &plaintext1);
            if (plaintext1 > 2147483647){
                    a = 1;
            }
            else if (plaintext1 < -2147483647){
                    a = 1;
            }
            else {

                    a = 0;
                    }
            }
*/
    LweSample* ciphertext1 = new_gate_bootstrapping_ciphertext_array(32, params);
    for (int i=0; i<32; i++) {
        bootsSymEncrypt(&ciphertext1[i], (plaintext1>>i)&1, key);
    }
	
    // carry
    int32_t plaintext3 = 0;
    LweSample* ciphertext3 = new_gate_bootstrapping_ciphertext_array(32, params);
    for (int i = 0; i<32; i++) {
        bootsSymEncrypt(&ciphertext3[i], (plaintext3 >> i) & 1, key);
    }

    printf("Hi there! The number (2222) will be sent to CLOUD in an encrypted state for calculation.\n");

    // read the secret key
    FILE* secret_key = fopen("secret.key","rb");
    TFheGateBootstrappingSecretKeySet* bk = new_tfheGateBootstrappingSecretKeySet_fromFile(secret_key);
    fclose(secret_key);

    // export the cloud key to a file (for the cloud)
    //FILE* cloud_key = fopen("cloud.key","wb");
    //export_tfheGateBootstrappingCloudKeySet_toFile(cloud_key, &key->cloud);
    //fclose(cloud_key);

    // export the 32 ciphertexts to a file (for the cloud)
    FILE* cloud_data = fopen("cloud2.data","wb");
    for (int i=0; i<32; i++)
        export_gate_bootstrapping_ciphertext_toFile(cloud_data, &ciphertext1[i], params);
    for (int i=0; i<32; i++)
        export_gate_bootstrapping_ciphertext_toFile(cloud_data, &ciphertext3[i], params);
    fclose(cloud_data);

    // clean up all pointers
    delete_gate_bootstrapping_ciphertext_array(32, ciphertext1);
    delete_gate_bootstrapping_ciphertext_array(32, ciphertext3);
    delete_gate_bootstrapping_secret_keyset(key);
    delete_gate_bootstrapping_parameters(params);
}
