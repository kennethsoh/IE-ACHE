#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>
#include <stdio.h>
#include <time.h>
#include <sys/time.h>

void add(LweSample* sum, const LweSample* a, const LweSample* b, const TFheGateBootstrappingCloudKeySet* ck, const size_t size) 
{
  	LweSample *carry = new_gate_bootstrapping_ciphertext(ck->params),
                  *tmp_s = new_gate_bootstrapping_ciphertext(ck->params),
                  *tmp_c = new_gate_bootstrapping_ciphertext(ck->params);

	// first iteration
	bootsXOR(&sum[0], &a[0], &b[0], ck);
	bootsAND(carry, &a[0], &b[0], ck);
	for(int i = 1; i < size; i++)
 	{
		bootsXOR(tmp_s, &a[i], &b[i], ck);
		bootsAND(tmp_c, &a[i], &b[i], ck);
		bootsXOR(&sum[i], tmp_s, carry, ck);
		bootsAND(carry, carry, tmp_s, ck);
		bootsOR(carry, carry, tmp_c, ck);
	}

	// clean up
	delete_gate_bootstrapping_ciphertext(carry);
	delete_gate_bootstrapping_ciphertext(tmp_s);
	delete_gate_bootstrapping_ciphertext(tmp_c);
}

void MUX(LweSample* result, const LweSample* a, const LweSample* b, const LweSample* c, const TFheGateBootstrappingCloudKeySet* ck, const size_t size) 
{
	for(int i = 0; i < size; i++)
	{
		bootsMUX(&result[i], &a[0], &b[i], &c[i], ck);
  	}
}

void zero(LweSample* result, const TFheGateBootstrappingCloudKeySet* ck, const size_t size) 
{
	for(int i = 0; i < size; i++)
	{
		bootsCONSTANT(&result[i], 0, ck);
	}
}

void NOT(LweSample* result, const LweSample* a, const TFheGateBootstrappingCloudKeySet* ck, const size_t size) 
{
	for(int i = 0; i < size; i++)
	{
		bootsNOT(&result[i], &a[i], ck);
	}
}

void twosComplement(LweSample* result, const LweSample* a, const TFheGateBootstrappingCloudKeySet* ck, const size_t size) {
	LweSample *one = new_gate_bootstrapping_ciphertext_array(size, ck->params),
		*c = new_gate_bootstrapping_ciphertext_array(size, ck->params);;
	zero(one, ck, size);
  	bootsCONSTANT(&one[0], 1, ck);

  	NOT(c, a, ck, size);
  	add(result, c, one, ck, size);

	// clean up
  	delete_gate_bootstrapping_ciphertext_array(size, one);
  	delete_gate_bootstrapping_ciphertext_array(size, c);
}


void sub(LweSample* result, const LweSample* a, const LweSample* b, const TFheGateBootstrappingCloudKeySet* ck, const size_t size) 
{
  	LweSample *c = new_gate_bootstrapping_ciphertext_array(size, ck->params);
  	twosComplement(c, b, ck, size);
	add(result, a, c, ck, size);

	// clean up
  	delete_gate_bootstrapping_ciphertext_array(size, c);
}

void dieDrama(LweSample* result, const LweSample* a, const TFheGateBootstrappingCloudKeySet* keyset, const size_t size)
{
	for(int i = 0; i < size; i++)
        {
                bootsCOPY(result + i, a + i, keyset);
        }
}

void leftShift(LweSample* result, const LweSample* a, const TFheGateBootstrappingCloudKeySet* keyset, const size_t size, int amnt)
{
	const LweParams * in_out_params = keyset->params->in_out_params;
	LweSample *tmp = new_LweSample_array(32, in_out_params);
	int shifted = size - amnt;

	for(int32_t i = 0; i < size; i++)
	{
                bootsCOPY(tmp + i, result + i, keyset);
        }

	for(int32_t i = 0; i < size; i++)
        {
                bootsCONSTANT(result + i, 0, keyset);
        }
	dieDrama(result + amnt, tmp, keyset, shifted);
}

void divide(LweSample *quotient, LweSample *remainder, const LweSample *x, const LweSample *y, const LweSample *c, TFheGateBootstrappingCloudKeySet *keyset, const int32_t nbbits, const int32_t nbd)
{
	const LweParams *in_out_params = keyset->params->in_out_params; //initialise in_out_params;
	LweSample *temp = new_LweSample_array(nbd, in_out_params); //temp = remainder
	LweSample *tempBack = new_LweSample_array(nbd, in_out_params); //tempBack = backup for temp
	LweSample *temptemp = new_LweSample_array(nbd, in_out_params);
	LweSample *tempq = new_LweSample_array(nbbits, in_out_params); //tempq = Quotient
	LweSample *sign = new_LweSample_array(nbd, in_out_params); //sign = takes the "sign" bit
	LweSample *odd = new_LweSample_array(nbd, in_out_params);
	LweSample *yyy = new_LweSample_array(nbd, in_out_params);
//	LweSample *denominator = new_LweSample_array(nbd, in_out_params);
	for(int i = 0;i<nbd;i++)
	{
		bootsCONSTANT(odd + i, 0, keyset);
		bootsCOPY(yyy + i, y + i, keyset);
	}
	for(int i = 0;i<nbd;i++)
	{
		bootsCONSTANT(temp + i, 0, keyset); //saves 0 into temp
		bootsCONSTANT(temptemp + i, 0, keyset);
	}
	for(int i = 0;i<nbbits;i++)
	{
		bootsCOPY(tempq + i, x + i, keyset); //save x into tempq
	}
	for(int i=0;i<nbbits;i++)
	{

		leftShift(temp, temp, keyset, nbd, 1); //leftShift temp by 1
		bootsCOPY(temp, tempq + nbbits - 1, keyset); //copy tempq[2] into temp[0]
		leftShift(tempq, tempq, keyset, nbbits, 1); //leftShift tempq by 1
		for(int i=0;i<nbd;i++)
		{
			bootsCOPY(tempBack + i, temp + i, keyset); //save temp into tempBack for backup
		}
		sub(temptemp, temp, yyy, keyset, nbd); //subtract y from temp and save into temp
		for(int i = 0;i<nbd;i++)
		{
			bootsCOPY(temp + i, temptemp + i, keyset);
		}
		bootsCOPY(sign, temp + nbd - 1, keyset); //copy temp[4] into sign[0]
		bootsNOT(sign, sign, keyset); //reverse sign
		MUX(temp, sign, temp, tempBack, keyset, nbd); //if NOT(sign) = 0, save tempBack into temp, if NOT(sign)=1, save temp into temp
		bootsCOPY(tempq, sign, keyset); //save sign[0] into tempq[0]*/
	}

	//save into result and remainder.
	for(int i=0;i<nbd;i++)
	{
		bootsCOPY(remainder + i, temp + i, keyset);
	}
//	for(int i=0;i<nbd;i++)
//	{
//		bootsCOPY(denominator + i, yyy + i, keyset);
//	}
	for(int i=0;i<nbbits;i++)
	{
		bootsCOPY(quotient + i, tempq + i, keyset);
	}
}

int main() {

	printf("reading the key...\n");

	//reads the cloud key from file
    	FILE* cloud_key = fopen("cloud.key","rb");
    	TFheGateBootstrappingCloudKeySet* bk = new_tfheGateBootstrappingCloudKeySet_fromFile(cloud_key);
    	fclose(cloud_key);

	//if necessary, the params are inside the key
    	const TFheGateBootstrappingParameterSet* params = bk->params;

    	printf("reading the input...\n");

	//read the 2x16 ciphertexts
    	LweSample* ciphertext1 = new_gate_bootstrapping_ciphertext_array(32, params);
    	LweSample* ciphertext2 = new_gate_bootstrapping_ciphertext_array(32, params);
	LweSample* ciphertext3 = new_gate_bootstrapping_ciphertext_array(16, params);

	//reads the 2x16 ciphertexts from the cloud file
    	FILE* cloud_data = fopen("cloud.data","rb");
    	for (int i=0; i<32; i++)
		import_gate_bootstrapping_ciphertext_fromFile(cloud_data, &ciphertext1[i], params);
    	for (int i=0; i<32; i++)
        	import_gate_bootstrapping_ciphertext_fromFile(cloud_data, &ciphertext2[i], params);
	for (int i = 0; i<16; i++)
		import_gate_bootstrapping_ciphertext_fromFile(cloud_data, &ciphertext3[i], params);
    	fclose(cloud_data);

    	printf("doing the homomorphic computation...\n");

	// do some operations on the ciphertexts: here, we will compute the
	// division of the two
    	LweSample* result = new_gate_bootstrapping_ciphertext_array(32, params);
    	LweSample* remainder = new_gate_bootstrapping_ciphertext_array(32, params);
//    	LweSample* denominator = new_gate_bootstrapping_ciphertext_array(32, params);

	struct timeval start, end;
	double get_time;
	printf("Checkpoint Divide");

	gettimeofday(&start, NULL);
    	divide(result, remainder, ciphertext1, ciphertext3, ciphertext2, bk, 16,16);
	gettimeofday(&end, NULL);
    	get_time = (end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec) * 1.0E-6;
        printf("Computation Time: %lf[sec]\n", get_time);

    	printf("writing the answer to file...\n");

	//export the 32 ciphertexts to a file (for the cloud)
    	FILE* answer_data = fopen("answer.data","wb");
    	for (int i=0; i<32; i++)
        	export_gate_bootstrapping_ciphertext_toFile(answer_data, &result[i], params);

    	for (int i=0; i<32; i++)
        	export_gate_bootstrapping_ciphertext_toFile(answer_data, &remainder[i], params);

    	for (int i=0; i<32; i++)
        	export_gate_bootstrapping_ciphertext_toFile(answer_data, &ciphertext2[i], params);

    	fclose(answer_data);

	//clean up all pointers
    	delete_gate_bootstrapping_ciphertext_array(32, result);
    	delete_gate_bootstrapping_ciphertext_array(32, ciphertext2);
   	delete_gate_bootstrapping_ciphertext_array(32, ciphertext1);
	delete_gate_bootstrapping_ciphertext_array(16, ciphertext3);
    	delete_gate_bootstrapping_cloud_keyset(bk);
}


