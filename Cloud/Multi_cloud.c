#include <string.h>
#include <iostream>
#include <algorithm>
#include <utility>
#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>
#include <stdio.h>
#include <time.h>
#include <vector>
#include <cassert>
#include <sys/time.h>

#define T_FILE "averagestandard.txt"

void add_full(LweSample *sum, const LweSample *x, const LweSample *y, const LweSample *c, const int32_t nb_bits, const TFheGateBootstrappingCloudKeySet *keyset){

	const LweParams *in_out_params = keyset->params->in_out_params;

	if (nb_bits == 0)
	{
		return;
	}

	LweSample *carry = new_LweSample_array(1, in_out_params);
	LweSample *axc = new_LweSample_array(1, in_out_params);
	LweSample *bxc = new_LweSample_array(1, in_out_params);
	bootsCOPY(carry, c, keyset);

	for(int32_t i = 0; i < nb_bits; ++i)
	{
		bootsCOPY(axc, x + i, keyset);
		bootsCOPY(bxc, y + i, keyset);
		bootsXOR(axc, axc, carry, keyset);
		bootsXOR(bxc, bxc, carry, keyset);
		bootsXOR(sum + i, x + i, bxc, keyset);
		bootsAND(axc, axc, bxc, keyset);
		bootsXOR(carry, carry, axc, keyset);
	}

	delete_LweSample_array(1, carry);
	delete_LweSample_array(1, axc);
	delete_LweSample_array(1, bxc);
}

void mul(LweSample *result, LweSample *a, LweSample *b, const LweSample *c, const int32_t nb_bits, TFheGateBootstrappingCloudKeySet *keyset)
{
	const LweParams *in_out_params = keyset->params->in_out_params;
	LweSample *sum1 = new_LweSample_array(32, in_out_params); // Current Sum
	LweSample *tmp = new_LweSample_array(32, in_out_params);
	for (int32_t i = 0; i < nb_bits; ++i)
	{
		bootsCONSTANT(sum1 + i, 0, keyset);
		bootsCONSTANT(result + i, 0, keyset);
		bootsCONSTANT(tmp + i, 0, keyset);
	}
	for (int32_t i = 0; i < nb_bits; ++i)
	{
		for (int32_t k = 0; k < nb_bits; ++k)
		{
			bootsAND(tmp + k, b + k, a + i, keyset);
		}
		add_full(sum1 + i, sum1 + i, tmp, c, nb_bits - i, keyset);
	}
	for (int32_t i = 0; i < nb_bits; ++i)
	{
		bootsCOPY(result + i, sum1 + i, keyset);
	}
	delete_LweSample_array(32, sum1);
	delete_LweSample_array(32, tmp);
}

int main() {

	printf("reading the key...\n");

	// reads the cloud key from file
	FILE* cloud_key = fopen("cloud.key", "rb");
	TFheGateBootstrappingCloudKeySet* bk = new_tfheGateBootstrappingCloudKeySet_fromFile(cloud_key);
	fclose(cloud_key);

	// if necessary, the params are inside the key
	const TFheGateBootstrappingParameterSet* params = bk->params;

	printf("reading the input...\n");

	// read the 2x32 ciphertexts
	LweSample* ciphertext1 = new_gate_bootstrapping_ciphertext_array(32, params);
	LweSample* ciphertext2 = new_gate_bootstrapping_ciphertext_array(32, params);
	LweSample* ciphertext3 = new_gate_bootstrapping_ciphertext_array(32, params);

	// reads the 2x32 ciphertexts from the cloud file
	FILE* cloud_data = fopen("cloud.data", "rb");
	for (int i = 0; i<32; i++)
		import_gate_bootstrapping_ciphertext_fromFile(cloud_data, &ciphertext1[i], params);
	for (int i = 0; i<32; i++)
		import_gate_bootstrapping_ciphertext_fromFile(cloud_data, &ciphertext2[i], params);
	for (int i = 0; i<32; i++)
		import_gate_bootstrapping_ciphertext_fromFile(cloud_data, &ciphertext3[i], params);
	fclose(cloud_data);

	printf("doing the homomorphic computation...\n");

	// do some operations on the ciphertexts: here, we will compute the
	// product of the two
	LweSample* result = new_gate_bootstrapping_ciphertext_array(32, params);

	struct timeval start, end;
	double get_time;

	gettimeofday(&start, NULL);
	mul(result, ciphertext1, ciphertext3, ciphertext2, 32, bk);
	gettimeofday(&end, NULL);

	get_time = (end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec) * 1.0E-6;
        printf("Computation Time: %lf[sec]\n", get_time);

        // write computation time to file
        FILE *t_file;
        t_file = fopen(T_FILE, "a");
        fprintf(t_file, "%lf\n", get_time);
        fclose(t_file);

	printf("writing the answer to file...\n");

	// export the 32 ciphertexts to a file (for the cloud)
	FILE* answer_data = fopen("answer.data", "wb");
	for (int i = 0; i<32; i++)
		export_gate_bootstrapping_ciphertext_toFile(answer_data, &result[i], params);
	fclose(answer_data);

	// clean up all pointers
	delete_gate_bootstrapping_ciphertext_array(32, result);
	delete_gate_bootstrapping_ciphertext_array(32, ciphertext2);
	delete_gate_bootstrapping_ciphertext_array(32, ciphertext1);
	delete_gate_bootstrapping_ciphertext_array(32, ciphertext3);
	delete_gate_bootstrapping_cloud_keyset(bk);
}
