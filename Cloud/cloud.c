#include <string>
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
#include <omp.h>
#include <fstream>
using namespace std;
ifstream read;

#define T_FILE "averagestandard.txt"
void add(LweSample *sum, LweSample *carryover, const LweSample *x, const LweSample *y, const LweSample *c, const int32_t nb_bits, const TFheGateBootstrappingCloudKeySet *keyset)
{
        const LweParams *in_out_params = keyset->params->in_out_params;
        LweSample *carry = new_LweSample_array(1, in_out_params);
        LweSample *axc = new_LweSample_array(1, in_out_params);
        LweSample *bxc = new_LweSample_array(1, in_out_params);
        bootsCOPY(carry, c, keyset);
        for(int32_t  i = 0; i < nb_bits; i++)
        {
		#pragma omp parallel sections num_threads(2)
		{	
			#pragma omp section
			bootsXOR(axc, x + i, carry, keyset);
			#pragma omp section
			bootsXOR(bxc, y + i, carry, keyset);
		}

		#pragma omp parallel sections num_threads(2)
		{
			#pragma omp section
			bootsXOR(sum + i, x + i, bxc, keyset);
			#pragma omp section
			bootsAND(axc, axc, bxc, keyset);
		}

		bootsXOR(carry, carry, axc, keyset);
        }

	bootsCOPY(carryover, carry, keyset);

        delete_LweSample_array(1, carry);
        delete_LweSample_array(1, axc);
        delete_LweSample_array(1, bxc);
}

void zero(LweSample* result, const TFheGateBootstrappingCloudKeySet* keyset, const size_t size)
{
	for(int i = 0; i < size; i++){
		bootsCONSTANT(result + i, 0, keyset);}
}

void NOT(LweSample* result, const LweSample* x, const TFheGateBootstrappingCloudKeySet* keyset, const size_t size)
{
	for(int i = 0; i < size; i++){
		bootsNOT(result + i, x + i, keyset);}
}

void split(LweSample *finalresult, LweSample *finalresult2, LweSample *finalresult3, LweSample *a, LweSample *b, LweSample *c, LweSample *d,LweSample *e, const LweSample *carry, const int32_t nb_bits, TFheGateBootstrappingCloudKeySet *keyset)
{
	const LweParams *in_out_params = keyset->params->in_out_params;
	
	LweSample *sum = new_LweSample_array(32, in_out_params);
	LweSample *sum2 = new_LweSample_array(32, in_out_params);
	LweSample *sum3 = new_LweSample_array(32, in_out_params);
	
	LweSample *carryover = new_LweSample_array(32, in_out_params);
	LweSample *carryover2 = new_LweSample_array(32, in_out_params);
	LweSample *carryover3 = new_LweSample_array(32, in_out_params);

        for (int32_t i = 0; i < nb_bits; ++i)
	{
		bootsCONSTANT(sum + i, 0, keyset);
		bootsCONSTANT(sum2 + i, 0, keyset);
		bootsCONSTANT(sum3 + i, 0, keyset);
		
		bootsCONSTANT(carryover + i, 0, keyset);
		bootsCONSTANT(carryover2 + i, 0, keyset);
		bootsCONSTANT(carryover3 + i, 0, keyset);
	}
	
	//adding the 2nd result with the carry
	add(sum, carryover, e, b, carry, nb_bits, keyset);
	add(sum2, carryover2, d, a, carryover, nb_bits, keyset);
	add(sum3, carryover3, c, carryover2,carry,nb_bits, keyset);
	
	for (int32_t i = 0; i < nb_bits; ++i)
	{
		bootsCOPY(finalresult + i, sum3 + i, keyset);
	}
	for (int32_t i = 0; i < nb_bits; ++i)
	{
		bootsCOPY(finalresult2 + i, sum2 + i, keyset);
	}
	for (int32_t i = 0; i < nb_bits; ++i)
	{
		bootsCOPY(finalresult3 + i, sum + i, keyset);
	}
	
	delete_LweSample_array(32, sum);
	delete_LweSample_array(32, sum2);
	delete_LweSample_array(32, sum3);
	
	delete_LweSample_array(32, carryover);
	delete_LweSample_array(32, carryover2);
	delete_LweSample_array(32, carryover3);
}

void mul32(LweSample *result, LweSample *result2, LweSample *a, LweSample *b,const LweSample *carry, const int32_t nb_bits, TFheGateBootstrappingCloudKeySet *keyset)
{
	const LweParams *in_out_params = keyset->params->in_out_params;
	//sum of the output
	LweSample *sum3c1 = new_LweSample_array(32, in_out_params);
	LweSample *sum3c2 = new_LweSample_array(32, in_out_params);

	LweSample *tmp = new_LweSample_array(32, in_out_params);
	LweSample *tmp2 = new_LweSample_array(32, in_out_params);
	
	LweSample *tmp3c1 = new_LweSample_array(32, in_out_params);
	LweSample *tmp3c2 = new_LweSample_array(32, in_out_params);

	LweSample *carry1 = new_LweSample_array(32, in_out_params);
	LweSample *carry2 = new_LweSample_array(32, in_out_params);
	
	//set all these to 0
	for (int32_t i = 0; i < nb_bits; ++i)
	{
		bootsCONSTANT(sum3c1 + i, 0, keyset);
		bootsCONSTANT(sum3c2 + i, 0, keyset);
		
		bootsCONSTANT(tmp + i, 0, keyset);
		bootsCONSTANT(tmp2 + i, 0, keyset);

		bootsCONSTANT(tmp3c1 + i, 0, keyset);
		bootsCONSTANT(tmp3c2 + i, 0, keyset);
		
		bootsCONSTANT(carry1 + i, 0, keyset);
		bootsCONSTANT(carry2 + i, 0, keyset);
	}
	
	//multiply all the bits together with the other bits..
	int round = 0;
 
	for (int32_t i = 0; i < nb_bits; ++i)
	{
		for (int32_t k = 0; k < nb_bits; ++k)
		{
			//this is basically multiplying as it is an AND gate
			//a(ciphertext1) should be the least significant bit
			#pragma omp parallel sections num_threads(2)
			{
				#pragma omp section
				bootsAND(tmp  + k,  a + k, b + i, keyset);
			}
			
		}
		
		if (round > 0) {
			for (int32_t i = 0; i < round; ++i) {
			        //putting number of 0s infront
				bootsCONSTANT(tmp3c1 + i, 0, keyset);
			}
		}
		
		//copy all the bits that fit into a int32 with the 0s inside
		for (int32_t i = 0; i < 32 - round; ++i)
		{
			// +round cause infront has the 0s
			//tmp is the least significant bit
			#pragma omp parallel sections num_threads(2) 
			{	
				#pragma omp section
				bootsCOPY(tmp3c1 + i + round , tmp + i, keyset);
			
			}
		}
		
		//the rest of the bits that couldnt fit inside 
		for (int32_t i = 0; i < round; ++i)
		{
			#pragma omp parallel sections num_threads(2) 
			{
				#pragma omp section
				bootsCOPY(tmp3c2 + i, tmp + i + 32 - round, keyset);
			}
		}
		
		add(sum3c1, carry1, sum3c1, tmp3c1, carry, 32, keyset);
		add(sum3c2, carry2, sum3c2, tmp3c2, carry1, 32, keyset);
		
		round++;
	}
	
	for (int32_t i = 0; i < 32; ++i)
	{
		bootsCOPY(result   + i,  sum3c2 + i, keyset);
		bootsCOPY(result2  + i,  sum3c1 + i, keyset);
		
	}
	
	delete_LweSample_array(32, sum3c1);
	delete_LweSample_array(32, sum3c2);

	delete_LweSample_array(32, tmp);
	delete_LweSample_array(32, tmp2);
	
	delete_LweSample_array(32, tmp3c1);
	delete_LweSample_array(32, tmp3c2);
	
	delete_LweSample_array(32, carry1);
	delete_LweSample_array(32, carry2);
}

void mul64(LweSample *result, LweSample *result2,LweSample *result3, LweSample *a, LweSample *b,LweSample *c,const LweSample *carry, const int32_t nb_bits, TFheGateBootstrappingCloudKeySet *keyset)
{
	const LweParams *in_out_params = keyset->params->in_out_params;
	//sum of the output
	LweSample *sum3c1 = new_LweSample_array(32, in_out_params);
	LweSample *sum3c2 = new_LweSample_array(32, in_out_params);
	LweSample *sum3c3 = new_LweSample_array(32, in_out_params);


	LweSample *tmp = new_LweSample_array(32, in_out_params);
	LweSample *tmp2 = new_LweSample_array(32, in_out_params);
	
	LweSample *tmp3c1 = new_LweSample_array(32, in_out_params);
	LweSample *tmp3c2 = new_LweSample_array(32, in_out_params);
	LweSample *tmp3c3 = new_LweSample_array(32, in_out_params);
	LweSample *tmp3c4 = new_LweSample_array(32, in_out_params);
	
	LweSample *carry1 = new_LweSample_array(32, in_out_params);
	LweSample *carry2 = new_LweSample_array(32, in_out_params);
	LweSample *carry3 = new_LweSample_array(32, in_out_params);
	LweSample *carry4 = new_LweSample_array(32, in_out_params);
	
	//set all these to 0
	for (int32_t i = 0; i < nb_bits; ++i)
	{
		bootsCONSTANT(sum3c1 + i, 0, keyset);
		bootsCONSTANT(sum3c2 + i, 0, keyset);
		bootsCONSTANT(sum3c3 + i, 0, keyset);

		
		bootsCONSTANT(tmp + i, 0, keyset);
		bootsCONSTANT(tmp2 + i, 0, keyset);

		bootsCONSTANT(tmp3c1 + i, 0, keyset);
		bootsCONSTANT(tmp3c2 + i, 0, keyset);
		bootsCONSTANT(tmp3c3 + i, 0, keyset);
		bootsCONSTANT(tmp3c4 + i, 0, keyset);
		
		bootsCONSTANT(carry1 + i, 0, keyset);
		bootsCONSTANT(carry2 + i, 0, keyset);
		bootsCONSTANT(carry3 + i, 0, keyset);
		bootsCONSTANT(carry4 + i, 0, keyset);
	}
	
	//multiply all the bits together with the other bits..
	int round = 0;
	int counter1 = 0;
	int counter2 = 0;
	
	

 
	for (int32_t i = 0; i < nb_bits; ++i)
	{
		

		for (int32_t k = 0; k < nb_bits; ++k)
		{
			//this is basically multiplying as it is an AND gate
			//a(ciphertext1) should be the least significant bit
			#pragma omp parallel sections num_threads(2)
			{
				#pragma omp section
				bootsAND(tmp  + k,  a + k, c + i, keyset);
				
				#pragma omp section
				bootsAND(tmp2 + k,  b + k, c + i, keyset);
			}
			
		}
		 counter1 = 32 - round;
		 counter2 = 32 - counter1;

		
		
		if (round > 0) {
			for (int32_t i = 0; i < round; ++i) {
			        //putting number of 0s infront
				bootsCONSTANT(tmp3c1 + i, 0, keyset);
			}
		}
		
		//copy all the bits that fit into a int32 with the 0s inside

		//tmp to tmp3c1
		for (int32_t i = 0; i < counter1; ++i)
		{
			// +round cause infront has the 0s
			//tmp is the least significant bit
			#pragma omp parallel sections num_threads(2) 
			{	
				#pragma omp section
				bootsCOPY(tmp3c1 + i + round , tmp + i, keyset);
			}
		}

		//remaining of tmp to tmp3c2
		for (int32_t i = 0; i < counter2; ++i)
		{
			// +round cause infront has the 0s
			//tmp is the least significant bit
			#pragma omp parallel sections num_threads(2) 
			{	
				#pragma omp section
				bootsCOPY(tmp3c2 + i, tmp + i + counter1, keyset);
			}
		}

		//some of tmp2 to remaining of tmp3c2
		//repeats 31 times
		for (int32_t i = 0; i < counter1; ++i)
		{
			// +round cause infront has the 0s
			//tmp is the least significant bit
			#pragma omp parallel sections num_threads(2) 
			{	
				#pragma omp section
				bootsCOPY(tmp3c2 + i + counter2, tmp2 + i, keyset);
			}
		}
		
		//the rest of tmp2 to tmp3c3
		//repeats 1 time
		for (int32_t i = 0; i < counter2; ++i)
		{
			// +round cause infront has the 0s
			//tmp is the least significant bit
			#pragma omp parallel sections num_threads(2) 
			{	
				#pragma omp section
				bootsCOPY(tmp3c3 + i, tmp2 + i + counter1, keyset);
			}
		}
		
		add(sum3c1, carry1, sum3c1, tmp3c1, carry, 32, keyset);
		add(sum3c2, carry2, sum3c2, tmp3c2, carry1, 32, keyset);
		add(sum3c3, carry3, sum3c3, tmp3c3, carry2, 32, keyset);
		
		round++;
	}
	
	for (int32_t i = 0; i < 32; ++i)
	{
		bootsCOPY(result   + i,  sum3c3 + i, keyset);
		bootsCOPY(result2  + i,  sum3c2 + i, keyset);
		bootsCOPY(result3  + i,  sum3c1 + i, keyset);
	}
	
	delete_LweSample_array(32, sum3c1);
	delete_LweSample_array(32, sum3c2);
	delete_LweSample_array(32, sum3c3);

	delete_LweSample_array(32, tmp);
	delete_LweSample_array(32, tmp2);
	
	delete_LweSample_array(32, tmp3c1);
	delete_LweSample_array(32, tmp3c2);
	delete_LweSample_array(32, tmp3c3);
	delete_LweSample_array(32, tmp3c4);
	
	delete_LweSample_array(32, carry1);
	delete_LweSample_array(32, carry2);
	delete_LweSample_array(32, carry3);
	delete_LweSample_array(32, carry4);

}

void mul128(LweSample *result, LweSample *result2,LweSample *result3,LweSample *result4,LweSample *result5, LweSample *a, LweSample *b,LweSample *c,LweSample *d, LweSample *e,const LweSample *carry, const int32_t nb_bits, TFheGateBootstrappingCloudKeySet *keyset)
{
	const LweParams *in_out_params = keyset->params->in_out_params;
	//sum of the output
	LweSample *sum3c1 = new_LweSample_array(32, in_out_params);
	LweSample *sum3c2 = new_LweSample_array(32, in_out_params);
	LweSample *sum3c3 = new_LweSample_array(32, in_out_params);
	LweSample *sum3c4 = new_LweSample_array(32, in_out_params);
	LweSample *sum3c5 = new_LweSample_array(32, in_out_params);

	LweSample *tmp = new_LweSample_array(32, in_out_params);
	LweSample *tmp2 = new_LweSample_array(32, in_out_params);
	LweSample *tmp3 = new_LweSample_array(32, in_out_params);
	LweSample *tmp4 = new_LweSample_array(32, in_out_params);
	
	LweSample *tmp3c1 = new_LweSample_array(32, in_out_params);
	LweSample *tmp3c2 = new_LweSample_array(32, in_out_params);
	LweSample *tmp3c3 = new_LweSample_array(32, in_out_params);
	LweSample *tmp3c4 = new_LweSample_array(32, in_out_params);
	LweSample *tmp3c5 = new_LweSample_array(32, in_out_params);
	
	LweSample *carry1 = new_LweSample_array(32, in_out_params);
	LweSample *carry2 = new_LweSample_array(32, in_out_params);
	LweSample *carry3 = new_LweSample_array(32, in_out_params);
	LweSample *carry4 = new_LweSample_array(32, in_out_params);
	LweSample *carry5 = new_LweSample_array(32, in_out_params);
	
	//set all these to 0
	for (int32_t i = 0; i < nb_bits; ++i)
	{
		bootsCONSTANT(sum3c1 + i, 0, keyset);
		bootsCONSTANT(sum3c2 + i, 0, keyset);
		bootsCONSTANT(sum3c3 + i, 0, keyset);
		bootsCONSTANT(sum3c4 + i, 0, keyset);
		bootsCONSTANT(sum3c5 + i, 0, keyset);

		bootsCONSTANT(tmp + i, 0, keyset);
		bootsCONSTANT(tmp2 + i, 0, keyset);
		bootsCONSTANT(tmp3 + i, 0, keyset);
		bootsCONSTANT(tmp4 + i, 0, keyset);

		bootsCONSTANT(tmp3c1 + i, 0, keyset);
		bootsCONSTANT(tmp3c2 + i, 0, keyset);
		bootsCONSTANT(tmp3c3 + i, 0, keyset);
		bootsCONSTANT(tmp3c4 + i, 0, keyset);
		bootsCONSTANT(tmp3c5 + i, 0, keyset);
		
		bootsCONSTANT(carry1 + i, 0, keyset);
		bootsCONSTANT(carry2 + i, 0, keyset);
		bootsCONSTANT(carry3 + i, 0, keyset);
		bootsCONSTANT(carry4 + i, 0, keyset);
		bootsCONSTANT(carry5 + i, 0, keyset);
		
	}
	
	//multiply all the bits together with the other bits..
	int round = 0;
	int counter1 = 0;
	int counter2 = 0;
	
	

 
	for (int32_t i = 0; i < nb_bits; ++i)
	{
		

		for (int32_t k = 0; k < nb_bits; ++k)
		{
			//this is basically multiplying as it is an AND gate
			//a(ciphertext1) should be the least significant bit
			#pragma omp parallel sections num_threads(4)
			{
				#pragma omp section
				bootsAND(tmp  + k,  a + k, e + i, keyset);
				
				#pragma omp section
				bootsAND(tmp2 + k,  b + k, e + i, keyset);
				
				#pragma omp section
				bootsAND(tmp3 + k,  c + k, e + i, keyset);
				
				#pragma omp section
				bootsAND(tmp4 + k,  d + k, e + i, keyset);
			}
			
		}
		 counter1 = 32 - round;
		 counter2 = 32 - counter1;

		
		
		if (round > 0) {
			for (int32_t i = 0; i < round; ++i) {
			        //putting number of 0s infront
				bootsCONSTANT(tmp3c1 + i, 0, keyset);
			}
		}
		
		//copy all the bits that fit into a int32 with the 0s inside

		//tmp to tmp3c1
		for (int32_t i = 0; i < counter1; ++i)
		{
			// +round cause infront has the 0s
			//tmp is the least significant bit
			#pragma omp parallel sections num_threads(2) 
			{	
				#pragma omp section
				bootsCOPY(tmp3c1 + i + round , tmp + i, keyset);
			
			}
		
	
		}

		
		//remaining of tmp to tmp3c2
		for (int32_t i = 0; i < counter2; ++i)
		{
			// +round cause infront has the 0s
			//tmp is the least significant bit
			#pragma omp parallel sections num_threads(2) 
			{	
				#pragma omp section
				bootsCOPY(tmp3c2 + i, tmp + i + counter1, keyset);
			
			}
		
	
		}

		
		//some of tmp2 to remaining of tmp3c2
		for (int32_t i = 0; i < counter1; ++i)
		{
			// +round cause infront has the 0s
			//tmp is the least significant bit
			#pragma omp parallel sections num_threads(2) 
			{	
				#pragma omp section
				bootsCOPY(tmp3c2 + i + counter2, tmp2 + i, keyset);
			
			}
		
	
		}

		
		
		//remaining tmp2 to tmp3c3
		for (int32_t i = 0; i < counter2; ++i)
		{
			// +round cause infront has the 0s
			//tmp is the least significant bit
			#pragma omp parallel sections num_threads(2) 
			{	
				#pragma omp section
				bootsCOPY(tmp3c3 + i, tmp2 + i + counter1, keyset);
			
			}
		
	
		}
		
		//some of tmp3 to remaining tmp3c3
		for (int32_t i = 0; i < counter1; ++i)
		{
			#pragma omp parallel sections num_threads(2) 
			{	
				#pragma omp section
				bootsCOPY(tmp3c3 + i + counter2, tmp3 + i, keyset);
			
			}
		
	
		}
		
		//rest of tmp3 to tmp3c4
		for (int32_t i = 0; i < counter2; ++i)
		{
			#pragma omp parallel sections num_threads(2) 
			{	
				#pragma omp section
				bootsCOPY(tmp3c4 + i, tmp3 + i + counter1, keyset);
			
			}
		
	
		}
		
		//some of tmp4 to remaining tmp3c4
		for (int32_t i = 0; i < counter1; ++i)
		{
			#pragma omp parallel sections num_threads(2) 
			{	
				#pragma omp section
				bootsCOPY(tmp3c4 + i + counter2, tmp4 + i, keyset);
			
			}
		
	
		}
		
		//rest of tmp4 to tmp3c5
		for (int32_t i = 0; i < counter2; ++i)
		{
			#pragma omp parallel sections num_threads(2) 
			{	
				#pragma omp section
				bootsCOPY(tmp3c5 + i, tmp4 + i + counter1, keyset);
			
			}
		
	
		}
		
		add(sum3c1, carry1, sum3c1, tmp3c1, carry, 32, keyset);
		add(sum3c2, carry2, sum3c2, tmp3c2, carry1, 32, keyset);
		add(sum3c3, carry3, sum3c3, tmp3c3, carry2, 32, keyset);
		add(sum3c4, carry4, sum3c4, tmp3c4, carry3, 32, keyset);
		add(sum3c5, carry5, sum3c5, tmp3c5, carry4, 32, keyset);
		
		round++;
		
	}
	
	for (int32_t i = 0; i < 32; ++i)
	{
		bootsCOPY(result   + i,  sum3c5 + i, keyset);
		bootsCOPY(result2  + i,  sum3c4 + i, keyset);
		bootsCOPY(result3  + i,  sum3c3 + i, keyset);
		bootsCOPY(result4  + i,  sum3c2 + i, keyset);
		bootsCOPY(result5  + i,  sum3c1 + i, keyset);
	}
	
	
	delete_LweSample_array(32, sum3c1);
	delete_LweSample_array(32, sum3c2);
	delete_LweSample_array(32, sum3c3);
	delete_LweSample_array(32, sum3c4);
	delete_LweSample_array(32, sum3c5);


	delete_LweSample_array(32, tmp);
	delete_LweSample_array(32, tmp2);
	delete_LweSample_array(32, tmp3);
	delete_LweSample_array(32, tmp4);
	
	delete_LweSample_array(32, tmp3c1);
	delete_LweSample_array(32, tmp3c2);
	delete_LweSample_array(32, tmp3c3);
	delete_LweSample_array(32, tmp3c4);
	delete_LweSample_array(32, tmp3c5);
	
	delete_LweSample_array(32, carry1);
	delete_LweSample_array(32, carry2);
	delete_LweSample_array(32, carry3);
	delete_LweSample_array(32, carry4);
	delete_LweSample_array(32, carry5);
}


int main() {
	// dragonfly_cipher_cloud should have already appended 2 cipherstreams into cloud.data

	printf("Reading the key...\n");

	// reads the cloud key from file
	FILE* cloud_key = fopen("cloud.key", "rb");
	TFheGateBootstrappingCloudKeySet* bk = new_tfheGateBootstrappingCloudKeySet_fromFile(cloud_key);
	fclose(cloud_key);

	FILE* nbit_key = fopen("nbit.key","rb");
    TFheGateBootstrappingSecretKeySet* nbitkey = new_tfheGateBootstrappingSecretKeySet_fromFile(nbit_key);
    fclose(nbit_key);

	// if necessary, the params are inside the key
	const TFheGateBootstrappingParameterSet* params = bk->params;

	// if necessary, the params are inside the key
	const TFheGateBootstrappingParameterSet* nbitparams = nbitkey->params;

	// Create ciphertext blocks for negative1, bit1, negative2, bit2 and values
	LweSample* ciphertextbit = new_gate_bootstrapping_ciphertext_array(32, nbitparams);

	LweSample* ciphertextnegative1 = new_gate_bootstrapping_ciphertext_array(32, nbitparams);
	LweSample* ciphertextbit1 = new_gate_bootstrapping_ciphertext_array(32, nbitparams);

	LweSample* ciphertextnegative2 = new_gate_bootstrapping_ciphertext_array(32, nbitparams);
	LweSample* ciphertextbit2 = new_gate_bootstrapping_ciphertext_array(32, nbitparams);

	LweSample* ciphertext1 = new_gate_bootstrapping_ciphertext_array(32, params);
	LweSample* ciphertext2 = new_gate_bootstrapping_ciphertext_array(32, params);
	LweSample* ciphertext3 = new_gate_bootstrapping_ciphertext_array(32, params);
	LweSample* ciphertext4 = new_gate_bootstrapping_ciphertext_array(32, params);
	LweSample* ciphertext5 = new_gate_bootstrapping_ciphertext_array(32, params);
	LweSample* ciphertext6 = new_gate_bootstrapping_ciphertext_array(32, params);
	LweSample* ciphertext7 = new_gate_bootstrapping_ciphertext_array(32, params);
	LweSample* ciphertext8 = new_gate_bootstrapping_ciphertext_array(32, params);
	LweSample* ciphertext9 = new_gate_bootstrapping_ciphertext_array(32, params);
	LweSample* ciphertext10 = new_gate_bootstrapping_ciphertext_array(32, params);
	LweSample* ciphertext11 = new_gate_bootstrapping_ciphertext_array(32, params);
	LweSample* ciphertext12 = new_gate_bootstrapping_ciphertext_array(32, params);
	LweSample* ciphertext13 = new_gate_bootstrapping_ciphertext_array(32, params);
	LweSample* ciphertext14 = new_gate_bootstrapping_ciphertext_array(32, params);
	LweSample* ciphertext15 = new_gate_bootstrapping_ciphertext_array(32, params);
	LweSample* ciphertext16 = new_gate_bootstrapping_ciphertext_array(32, params);

	LweSample* ciphertextcarry1 = new_gate_bootstrapping_ciphertext_array(32, params);
	LweSample* ciphertextcarry2 = new_gate_bootstrapping_ciphertext_array(32, params);

	printf("Reading input 1...\n");

	// reads ciphertexts from cloud.data
	FILE* cloud_data = fopen("cloud.data", "rb");
	for (int i = 0; i<32; i++) // line0
		import_gate_bootstrapping_ciphertext_fromFile(cloud_data, &ciphertextnegative1[i], nbitparams);
	for (int i = 0; i<32; i++) // line1
		import_gate_bootstrapping_ciphertext_fromFile(cloud_data, &ciphertextbit1[i], nbitparams);
	
	// Decrypts bit size1 
	int32_t int_bit1 = 0;
    	for (int i=0; i<32; i++) {
       	int ai = bootsSymDecrypt(&ciphertextbit1[i],nbitkey)>0;
       	int_bit1 |= (ai<<i); }

	for (int i=0; i<32; i++)
	import_gate_bootstrapping_ciphertext_fromFile(cloud_data, &ciphertext1[i], params);
	for (int i=0; i<32; i++)
	import_gate_bootstrapping_ciphertext_fromFile(cloud_data, &ciphertext2[i], params);
	for (int i=0; i<32; i++)
	import_gate_bootstrapping_ciphertext_fromFile(cloud_data, &ciphertext3[i], params);
	for (int i=0; i<32; i++)
	import_gate_bootstrapping_ciphertext_fromFile(cloud_data, &ciphertext4[i], params);
	for (int i=0; i<32; i++)
	import_gate_bootstrapping_ciphertext_fromFile(cloud_data, &ciphertext5[i], params);
	for (int i=0; i<32; i++)
	import_gate_bootstrapping_ciphertext_fromFile(cloud_data, &ciphertext6[i], params);
	for (int i=0; i<32; i++)
	import_gate_bootstrapping_ciphertext_fromFile(cloud_data, &ciphertext7[i], params);
	for (int i=0; i<32; i++)
	import_gate_bootstrapping_ciphertext_fromFile(cloud_data, &ciphertext8[i], params);

	for (int i = 0; i<32; i++) // line10
	import_gate_bootstrapping_ciphertext_fromFile(cloud_data, &ciphertextcarry1[i], params);

	printf("Reading input 2...\n");

	for (int i = 0; i<32; i++) // line11
	import_gate_bootstrapping_ciphertext_fromFile(cloud_data, &ciphertextnegative2[i], nbitparams);
	for (int i = 0; i<32; i++) // line12
	import_gate_bootstrapping_ciphertext_fromFile(cloud_data, &ciphertextbit2[i], nbitparams);

	// Decrypts bit size2
	int32_t int_bit2 = 0;
    	for (int i=0; i<32; i++) {
       	int ai = bootsSymDecrypt(&ciphertextbit2[i],nbitkey)>0;
       	int_bit2 |= (ai<<i); }

	for (int i=0; i<32; i++)
	import_gate_bootstrapping_ciphertext_fromFile(cloud_data, &ciphertext9[i], params);
	for (int i=0; i<32; i++)
	import_gate_bootstrapping_ciphertext_fromFile(cloud_data, &ciphertext10[i], params);
	for (int i=0; i<32; i++)
	import_gate_bootstrapping_ciphertext_fromFile(cloud_data, &ciphertext11[i], params);
	for (int i=0; i<32; i++)
	import_gate_bootstrapping_ciphertext_fromFile(cloud_data, &ciphertext12[i], params);
	for (int i=0; i<32; i++)
	import_gate_bootstrapping_ciphertext_fromFile(cloud_data, &ciphertext13[i], params);
	for (int i=0; i<32; i++)
	import_gate_bootstrapping_ciphertext_fromFile(cloud_data, &ciphertext14[i], params);
	for (int i=0; i<32; i++)
	import_gate_bootstrapping_ciphertext_fromFile(cloud_data, &ciphertext15[i], params);
	for (int i=0; i<32; i++)
	import_gate_bootstrapping_ciphertext_fromFile(cloud_data, &ciphertext16[i], params);

	for (int i = 0; i<32; i++) // line21
	import_gate_bootstrapping_ciphertext_fromFile(cloud_data, &ciphertextcarry2[i], params);
	
	printf("Reading operation code...\n");
	
	// Get Operation Code from File
	int32_t int_op;
   	read.open("operator.txt");
	read >> int_op;
	
	// Homomorphic encryption to add negative1 and negative2 ciphertexts
	LweSample* ciphertextnegative = new_gate_bootstrapping_ciphertext_array(32, nbitparams);
	LweSample* carry1 = new_gate_bootstrapping_ciphertext_array(32, params);
	// add(ciphertextnegative, carry1, ciphertextnegative1, ciphertextnegative2, ciphertextcarry1, 32, nbitcloudkey); // NOTE

	// Decrypts Negative1
	int32_t int_negative1 = 0;
    	for (int i=0; i<32; i++) {
       	int ai = bootsSymDecrypt(&ciphertextnegative1[i],nbitkey)>0;
       	int_negative1 |= (ai<<i); }
    	std::cout << int_negative1 << " => negative1" << "\n";
	
	// convert first value negativity code from 2 to 1
	if (int_negative1 == 2){
		int_negative1 = 1;}
    	
	// Decrypts Negative2
	int32_t int_negative2 = 0;
	for (int i=0; i<32; i++) {
       	int ai = bootsSymDecrypt(&ciphertextnegative2[i],nbitkey)>0;
       	int_negative2 |= (ai<<i); }
    	std::cout << int_negative2 << " => negative2" << "\n";

	// Add Negatives. 
	// If both v1 & v2 are positive, int_negative = 0
	// If only v1 is negative, int_negative = 1
	// If only v2 is negative, int_negative = 2
	// If both v1 & v2 are negative, int_negative = 3
	int32_t int_negative;
	int_negative = (int_negative1 + int_negative2);
	// std::cout << int_negative << " -> negatives" << "\n";


    //export the negative and bit data for the verif
    FILE* answer_data = fopen("answer.data", "wb");

	// Write negative to  answer.data
	int32_t ciphernegative = 0;
	if (int_negative == 1){
		ciphernegative = 1;
	}
	if (int_negative == 2){
		ciphernegative = 2;
	}
	if (int_negative == 3){
		ciphernegative = 4;
	} 
	for (int i=0; i<32; i++) { 
	bootsSymEncrypt(&ciphertextnegative[i], (ciphernegative>>i)&1, nbitkey);
    }
	for (int i = 0; i<32; i++)
		export_gate_bootstrapping_ciphertext_toFile(answer_data, &ciphertextnegative[i], nbitparams);
	std::cout << ciphernegative << " => total negatives" << "\n";

	delete_gate_bootstrapping_ciphertext_array(32, ciphertextnegative);
	
	// Compare bit sizes
	int32_t int_bit = 0;
	if (int_op == 4){
		if (int_bit1 >= int_bit2){int_bit = (int_bit1 * 2);}
		else{int_bit = (int_bit2 * 2);}
		for (int i=0; i<32; i++) { 
			bootsSymEncrypt(&ciphertextbit[i], (int_bit>>i)&1, nbitkey);}
		for (int i = 0; i<32; i++)
			export_gate_bootstrapping_ciphertext_toFile(answer_data, &ciphertextbit[i], nbitparams);
    			std::cout << int_bit << " written to answer.data" << "\n";
		if (int_bit1 >= int_bit2){int_bit = int_bit1;}
		else{int_bit = int_bit2;}
	}
	else if (int_bit1 >= int_bit2) {
		int_bit = int_bit1;
		for (int i = 0; i<32; i++)
			export_gate_bootstrapping_ciphertext_toFile(answer_data, &ciphertextbit1[i], nbitparams);
    			std::cout << int_bit << " written to answer.data" << "\n";
	}
	else{
		int_bit = int_bit2;
		for (int i = 0; i<32; i++)
			export_gate_bootstrapping_ciphertext_toFile(answer_data, &ciphertextbit2[i], nbitparams);
    			std::cout << int_bit << " written to answer.data" << "\n";
	}
	
	fclose(cloud_data);
	
	// If trying to multiply a 256 bit number
	if ((int_op == 4) && (int_bit >= 256)){
    		std::cout << "Cannot multiply 256 bit number!" << "\n";
		fclose(answer_data);
		return 126;
	}


	// Addition
	//if (the operation is add AND (both numbers are positive OR both numbers are negative)) OR (the operation is subtract AND either number is negative)
	// A+B, [(-A)+(-B)], A-(-B), (-A)-(B)
    if ((int_op == 1 && (int_negative != 1 && int_negative != 2 )) || (int_op == 2 && (int_negative == 1 || int_negative == 2))) {
    	if (int_op == 1){
    	std::cout << int_bit << " bit Addition computation" << "\n";
    	}else{
    	std::cout << int_bit << " bit Subtraction computation" << "\n";
    	}
			
		//32 Bit Addition
		if (int_bit == 32) 
		{	
			// Ciphertext to hold the result and carry
			LweSample* result = new_gate_bootstrapping_ciphertext_array(32, params);
			LweSample* carry1 = new_gate_bootstrapping_ciphertext_array(32, params);

			struct timeval start, end;
			double get_time;
			gettimeofday(&start, NULL);
			
			printf("Doing the homomorphic computation...\n");
		
			//Adding component
			add(result, carry1, ciphertext1, ciphertext9, ciphertextcarry1, 32, bk);
				
			// Timings
			gettimeofday(&end, NULL);
			get_time = (end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec) * 1.0E-6;
			printf("Computation Time: %lf[sec]\n", get_time);

			// export the result ciphertexts to a file (for the cloud)
			for (int i=0; i<32; i++) // result1
				export_gate_bootstrapping_ciphertext_toFile(answer_data, &result[i], params);
			for (int i=0; i<32; i++) // 2
				export_gate_bootstrapping_ciphertext_toFile(answer_data, &ciphertextcarry1[i], params);
			for (int i=0; i<32; i++) // 3
				export_gate_bootstrapping_ciphertext_toFile(answer_data, &ciphertextcarry1[i], params);	
			for (int i=0; i<32; i++) // 4
				export_gate_bootstrapping_ciphertext_toFile(answer_data, &ciphertextcarry1[i], params);
			for (int i=0; i<32; i++) // 5
				export_gate_bootstrapping_ciphertext_toFile(answer_data, &ciphertextcarry1[i], params);	
			for (int i=0; i<32; i++) // 6
				export_gate_bootstrapping_ciphertext_toFile(answer_data, &ciphertextcarry1[i], params);
			for (int i=0; i<32; i++) // 7
				export_gate_bootstrapping_ciphertext_toFile(answer_data, &ciphertextcarry1[i], params);	
			for (int i=0; i<32; i++) // 8
				export_gate_bootstrapping_ciphertext_toFile(answer_data, &ciphertextcarry1[i], params);	
			for (int i=0; i<32; i++) // carry
				export_gate_bootstrapping_ciphertext_toFile(answer_data, &ciphertextcarry1[i], params);		
			fclose(answer_data);
			
			printf("writing the answer to file...\n");	
			
			//Clean up
			delete_gate_bootstrapping_ciphertext_array(32, result);
			delete_gate_bootstrapping_ciphertext_array(32, carry1);
			delete_gate_bootstrapping_ciphertext_array(32, ciphertextbit1);
			delete_gate_bootstrapping_ciphertext_array(32, ciphertextnegative1);
			delete_gate_bootstrapping_ciphertext_array(32, ciphertextbit2);
			delete_gate_bootstrapping_ciphertext_array(32, ciphertextnegative2);
			delete_gate_bootstrapping_ciphertext_array(32, ciphertext1);
			delete_gate_bootstrapping_ciphertext_array(32, ciphertext9);
			delete_gate_bootstrapping_ciphertext_array(32, ciphertextcarry1);	
		}

		//64 Bit Addition
		if (int_bit == 64) 
		{
			//Ciphertext to hold the result and carry
			LweSample* result = new_gate_bootstrapping_ciphertext_array(32, params);
			LweSample* result2 = new_gate_bootstrapping_ciphertext_array(32, params);
				
			LweSample* carry1 = new_gate_bootstrapping_ciphertext_array(32, params);
			LweSample* carry2 = new_gate_bootstrapping_ciphertext_array(32, params);
				
			struct timeval start, end;
			double get_time;
			gettimeofday(&start, NULL);
			printf("Doing the homomorphic computation...\n");
			//Adding component
			add(result, carry1, ciphertext1, ciphertext9, ciphertextcarry1, 32, bk);
			add(result2, carry2, ciphertext2, ciphertext10, carry1, 32, bk);
				
			gettimeofday(&end, NULL);
			get_time = (end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec) * 1.0E-6;
			printf("Computation Time: %lf[sec]\n", get_time);

			printf("writing the answer to file...\n");

			// export the result ciphertexts to a file (for the cloud)
			for (int i=0; i<32; i++) // result1
				export_gate_bootstrapping_ciphertext_toFile(answer_data, &result[i], params);
			for (int i=0; i<32; i++) // result2 
				export_gate_bootstrapping_ciphertext_toFile(answer_data, &result2[i], params);
			for (int i=0; i<32; i++) // 3
				export_gate_bootstrapping_ciphertext_toFile(answer_data, &ciphertextcarry1[i], params);
			for (int i=0; i<32; i++) // 4
				export_gate_bootstrapping_ciphertext_toFile(answer_data, &ciphertextcarry1[i], params);	
			for (int i=0; i<32; i++) // 5
				export_gate_bootstrapping_ciphertext_toFile(answer_data, &ciphertextcarry1[i], params);
			for (int i=0; i<32; i++) // 6
				export_gate_bootstrapping_ciphertext_toFile(answer_data, &ciphertextcarry1[i], params);	
			for (int i=0; i<32; i++) // 7
				export_gate_bootstrapping_ciphertext_toFile(answer_data, &ciphertextcarry1[i], params);
			for (int i=0; i<32; i++) // 8
				export_gate_bootstrapping_ciphertext_toFile(answer_data, &ciphertextcarry1[i], params);	
			for (int i=0; i<32; i++) // carry
				export_gate_bootstrapping_ciphertext_toFile(answer_data, &ciphertextcarry1[i], params);	
			fclose(answer_data);
				
			//Clean up
			delete_gate_bootstrapping_ciphertext_array(32, result);
			delete_gate_bootstrapping_ciphertext_array(32, result2);
			delete_gate_bootstrapping_ciphertext_array(32, carry1);
			delete_gate_bootstrapping_ciphertext_array(32, carry2);
			delete_gate_bootstrapping_ciphertext_array(32, ciphertextbit1);
			delete_gate_bootstrapping_ciphertext_array(32, ciphertextnegative1);
			delete_gate_bootstrapping_ciphertext_array(32, ciphertextbit2);
			delete_gate_bootstrapping_ciphertext_array(32, ciphertextnegative2);
			delete_gate_bootstrapping_ciphertext_array(32, ciphertext1);
			delete_gate_bootstrapping_ciphertext_array(32, ciphertext2);
			delete_gate_bootstrapping_ciphertext_array(32, ciphertext9);
			delete_gate_bootstrapping_ciphertext_array(32, ciphertext10);
			delete_gate_bootstrapping_ciphertext_array(32, ciphertextcarry1);
		}
			
		//128 Bit Addition
		if (int_bit == 128) 
		{
			//Ciphertext to hold the result and carry
			LweSample* result = new_gate_bootstrapping_ciphertext_array(32, params);
			LweSample* result2 = new_gate_bootstrapping_ciphertext_array(32, params);
			LweSample* result3 = new_gate_bootstrapping_ciphertext_array(32, params);
			LweSample* result4 = new_gate_bootstrapping_ciphertext_array(32, params);
				
			LweSample* carry1 = new_gate_bootstrapping_ciphertext_array(32, params);
			LweSample* carry2 = new_gate_bootstrapping_ciphertext_array(32, params);
			LweSample* carry3 = new_gate_bootstrapping_ciphertext_array(32, params);
			LweSample* carry4 = new_gate_bootstrapping_ciphertext_array(32, params);
				
			struct timeval start, end;
			double get_time;
			gettimeofday(&start, NULL);
			printf("Doing the homomorphic computation...\n");
			
			//Adding component
			add(result, carry1, ciphertext1, ciphertext9, ciphertextcarry1, 32, bk);
			add(result2, carry2, ciphertext2, ciphertext10, carry1, 32, bk);
			add(result3, carry3, ciphertext3, ciphertext11, carry2, 32, bk);
			add(result4, carry4, ciphertext4, ciphertext12, carry3, 32, bk);
				
			// Timing
			gettimeofday(&end, NULL);
			get_time = (end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec) * 1.0E-6;
			printf("Computation Time: %lf[sec]\n", get_time);

			printf("writing the answer to file...\n");

			// export the result ciphertexts to a file (for the cloud)
			for (int i=0; i<32; i++) // result1
				export_gate_bootstrapping_ciphertext_toFile(answer_data, &result[i], params);
			for (int i=0; i<32; i++) // result2
				export_gate_bootstrapping_ciphertext_toFile(answer_data, &result2[i], params);
			for (int i=0; i<32; i++) // result3
				export_gate_bootstrapping_ciphertext_toFile(answer_data, &result3[i], params);
			for (int i=0; i<32; i++) // result4
				export_gate_bootstrapping_ciphertext_toFile(answer_data, &result4[i], params);
			for (int i=0; i<32; i++) // 5
				export_gate_bootstrapping_ciphertext_toFile(answer_data, &ciphertextcarry1[i], params);
			for (int i=0; i<32; i++) // 6
				export_gate_bootstrapping_ciphertext_toFile(answer_data, &ciphertextcarry1[i], params);	
			for (int i=0; i<32; i++) // 7
				export_gate_bootstrapping_ciphertext_toFile(answer_data, &ciphertextcarry1[i], params);
			for (int i=0; i<32; i++) // 8
				export_gate_bootstrapping_ciphertext_toFile(answer_data, &ciphertextcarry1[i], params);	
			for (int i=0; i<32; i++) // carry
				export_gate_bootstrapping_ciphertext_toFile(answer_data, &ciphertextcarry1[i], params);	
			fclose(answer_data);
				
			//Clean up
			delete_gate_bootstrapping_ciphertext_array(32, result);
			delete_gate_bootstrapping_ciphertext_array(32, result2);
			delete_gate_bootstrapping_ciphertext_array(32, result3);
			delete_gate_bootstrapping_ciphertext_array(32, result4);
			delete_gate_bootstrapping_ciphertext_array(32, carry1);
			delete_gate_bootstrapping_ciphertext_array(32, carry2);
			delete_gate_bootstrapping_ciphertext_array(32, carry3);
			delete_gate_bootstrapping_ciphertext_array(32, carry4);
			delete_gate_bootstrapping_ciphertext_array(32, ciphertextbit1);
			delete_gate_bootstrapping_ciphertext_array(32, ciphertextnegative1);
			delete_gate_bootstrapping_ciphertext_array(32, ciphertextbit2);
			delete_gate_bootstrapping_ciphertext_array(32, ciphertextnegative2);
			delete_gate_bootstrapping_ciphertext_array(32, ciphertext1);
			delete_gate_bootstrapping_ciphertext_array(32, ciphertext2);
			delete_gate_bootstrapping_ciphertext_array(32, ciphertext3);
			delete_gate_bootstrapping_ciphertext_array(32, ciphertext4);
			delete_gate_bootstrapping_ciphertext_array(32, ciphertext9);
			delete_gate_bootstrapping_ciphertext_array(32, ciphertext10);
			delete_gate_bootstrapping_ciphertext_array(32, ciphertext11);
			delete_gate_bootstrapping_ciphertext_array(32, ciphertext12);
			delete_gate_bootstrapping_ciphertext_array(32, ciphertextcarry1);
		}
			
		//256 Bit Addition
		if (int_bit == 256) 
		{
			// do some operations on the ciphertexts: here, we will compute the
			// addition of the two

			LweSample* result = new_gate_bootstrapping_ciphertext_array(32, params);
			LweSample* result2 = new_gate_bootstrapping_ciphertext_array(32, params);
			LweSample* result3 = new_gate_bootstrapping_ciphertext_array(32, params);
			LweSample* result4 = new_gate_bootstrapping_ciphertext_array(32, params);
			LweSample* result5 = new_gate_bootstrapping_ciphertext_array(32, params);
			LweSample* result6 = new_gate_bootstrapping_ciphertext_array(32, params);
			LweSample* result7 = new_gate_bootstrapping_ciphertext_array(32, params);
			LweSample* result8 = new_gate_bootstrapping_ciphertext_array(32, params);
				
			LweSample* carry1 = new_gate_bootstrapping_ciphertext_array(32, params);
			LweSample* carry2 = new_gate_bootstrapping_ciphertext_array(32, params);
			LweSample* carry3 = new_gate_bootstrapping_ciphertext_array(32, params);
			LweSample* carry4 = new_gate_bootstrapping_ciphertext_array(32, params);
			LweSample* carry5 = new_gate_bootstrapping_ciphertext_array(32, params);
			LweSample* carry6 = new_gate_bootstrapping_ciphertext_array(32, params);
			LweSample* carry7 = new_gate_bootstrapping_ciphertext_array(32, params);
			LweSample* carry8 = new_gate_bootstrapping_ciphertext_array(32, params);
				
			// Timing
			struct timeval start, end;
			double get_time;
			gettimeofday(&start, NULL);

			add(result, carry1, ciphertext1, ciphertext9, ciphertextcarry1, 32, bk);
			add(result2, carry2, ciphertext2, ciphertext10, carry1, 32, bk);
			add(result3, carry3, ciphertext3, ciphertext11, carry2, 32, bk);
			add(result4, carry4, ciphertext4, ciphertext12, carry3, 32, bk);
			add(result5, carry5, ciphertext5, ciphertext13, carry4, 32, bk);
			add(result6, carry6, ciphertext6, ciphertext14, carry5, 32, bk);
			add(result7, carry7, ciphertext7, ciphertext15, carry6, 32, bk);
			add(result8, carry8, ciphertext8, ciphertext16, carry7, 32, bk);

			gettimeofday(&end, NULL);
			get_time = (end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec) * 1.0E-6;
			printf("Computation Time: %lf[sec]\n", get_time);

			printf("writing the answer to file...\n");

			// export the 64 ciphertexts to a file (for the cloud)
			for (int i=0; i<32; i++)
				export_gate_bootstrapping_ciphertext_toFile(answer_data, &result[i], params);
			for (int i=0; i<32; i++)
				export_gate_bootstrapping_ciphertext_toFile(answer_data, &result2[i], params);
			for (int i=0; i<32; i++)
				export_gate_bootstrapping_ciphertext_toFile(answer_data, &result3[i], params);
			for (int i=0; i<32; i++)
				export_gate_bootstrapping_ciphertext_toFile(answer_data, &result4[i], params);
			for (int i=0; i<32; i++)
				export_gate_bootstrapping_ciphertext_toFile(answer_data, &result5[i], params);
			for (int i=0; i<32; i++)
				export_gate_bootstrapping_ciphertext_toFile(answer_data, &result6[i], params);
			for (int i=0; i<32; i++)
				export_gate_bootstrapping_ciphertext_toFile(answer_data, &result7[i], params);
			for (int i=0; i<32; i++)
				export_gate_bootstrapping_ciphertext_toFile(answer_data, &result8[i], params);
			for (int i=0; i<32; i++) // carry
				export_gate_bootstrapping_ciphertext_toFile(answer_data, &ciphertextcarry1[i], params);	
			fclose(answer_data);

			// clean up all pointers

			delete_gate_bootstrapping_ciphertext_array(32, result);
			delete_gate_bootstrapping_ciphertext_array(32, result2);
			delete_gate_bootstrapping_ciphertext_array(32, result3);
			delete_gate_bootstrapping_ciphertext_array(32, result4);
			delete_gate_bootstrapping_ciphertext_array(32, result5);
			delete_gate_bootstrapping_ciphertext_array(32, result6);
			delete_gate_bootstrapping_ciphertext_array(32, result7);
			delete_gate_bootstrapping_ciphertext_array(32, result8);
				
			delete_gate_bootstrapping_ciphertext_array(32, carry1);
			delete_gate_bootstrapping_ciphertext_array(32, carry2);
			delete_gate_bootstrapping_ciphertext_array(32, carry3);
			delete_gate_bootstrapping_ciphertext_array(32, carry4);
			delete_gate_bootstrapping_ciphertext_array(32, carry5);
			delete_gate_bootstrapping_ciphertext_array(32, carry6);
			delete_gate_bootstrapping_ciphertext_array(32, carry7);
			delete_gate_bootstrapping_ciphertext_array(32, carry8);
				
			delete_gate_bootstrapping_ciphertext_array(32, ciphertextbit1);
			delete_gate_bootstrapping_ciphertext_array(32, ciphertextnegative1);
			delete_gate_bootstrapping_ciphertext_array(32, ciphertextbit2);
			delete_gate_bootstrapping_ciphertext_array(32, ciphertextnegative2);
			delete_gate_bootstrapping_ciphertext_array(32, ciphertext1);
			delete_gate_bootstrapping_ciphertext_array(32, ciphertext2);
			delete_gate_bootstrapping_ciphertext_array(32, ciphertext3);
			delete_gate_bootstrapping_ciphertext_array(32, ciphertext4);
			delete_gate_bootstrapping_ciphertext_array(32, ciphertext5);
			delete_gate_bootstrapping_ciphertext_array(32, ciphertext6);
			delete_gate_bootstrapping_ciphertext_array(32, ciphertext7);
			delete_gate_bootstrapping_ciphertext_array(32, ciphertext8);
			delete_gate_bootstrapping_ciphertext_array(32, ciphertext9);
			delete_gate_bootstrapping_ciphertext_array(32, ciphertext10);
			delete_gate_bootstrapping_ciphertext_array(32, ciphertext11);
			delete_gate_bootstrapping_ciphertext_array(32, ciphertext12);
			delete_gate_bootstrapping_ciphertext_array(32, ciphertext13);
			delete_gate_bootstrapping_ciphertext_array(32, ciphertext14);
			delete_gate_bootstrapping_ciphertext_array(32, ciphertext15);
			delete_gate_bootstrapping_ciphertext_array(32, ciphertext16);
			delete_gate_bootstrapping_ciphertext_array(32, ciphertextcarry1);
		}
    }
		
	// Subtraction
	// If the operation is subtract OR (the operation is addition AND either one of the values are negative) A-B, A+(-B), (-A)+B
	else if (int_op == 2 || (int_op == 1 && (int_negative == 1 || int_negative == 2))){
		// Normal Subtraction computation with no negative numbers A-B OR Addition with 2nd number negative A+(-B)
		if ((int_op == 2 && int_negative == 0) || (int_op == 1 && int_negative == 2)){
			if (int_op == 2){
    			std::cout << int_bit << " bit Subtraction computation" << "\n";
    		}else {
    			std::cout << int_bit << " bit Addition computation with 2nd value negative" << "\n";
			}
		
			//32 Bit Subtraction
    		if(int_bit == 32)
			{
				printf("Doing the homomorphic computation...\n");
				
				LweSample* temp = new_gate_bootstrapping_ciphertext_array(32, params);
				LweSample* inverse1 = new_gate_bootstrapping_ciphertext_array(32, params);
				
				LweSample* tempcarry1 = new_gate_bootstrapping_ciphertext_array(32, params);
				
				LweSample* twosresult1 = new_gate_bootstrapping_ciphertext_array(32, params);
				
				LweSample* twoscarry1 = new_gate_bootstrapping_ciphertext_array(32, params);
				
				struct timeval start, end;
				double get_time;

				gettimeofday(&start, NULL);
				
				//Subtraction Process
				
				//Step 1. Inverse the 32 bit chunks in the second input value
				NOT(inverse1, ciphertext9, bk, 32);
				
				//iniailize tempcarry and temp carry to 0
				zero(temp, bk, 32);
				zero(tempcarry1, bk, 32); 
				
				
				//Assign temp to have a value of 1 for 2nd complement
				bootsCONSTANT(temp, 1, bk); 
				
				//Add 1 to inverted
				add(twosresult1, twoscarry1, inverse1, temp, tempcarry1, 32, bk);
				
			
				LweSample* result1 = new_gate_bootstrapping_ciphertext_array(32, params);
				
				LweSample* carry1 = new_gate_bootstrapping_ciphertext_array(32, params);
				
				
				//Do the addition, this is basically adding the first value to the inversed value of the second value, a + (-b)
				add(result1, carry1, ciphertext1, twosresult1, ciphertextcarry1, 32, bk);
				
				gettimeofday(&end, NULL);
			
				get_time = (end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec) * 1.0E-6;
				printf("Computation Time: %lf[sec]\n", get_time);

				printf("writing the answer to file...\n");

				//export the 32 ciphertexts to a file (for the cloud)
				for (int i=0; i<32; i++) //result1
					export_gate_bootstrapping_ciphertext_toFile(answer_data, &result1[i], params);
				for (int i=0; i<32; i++) // 2
					export_gate_bootstrapping_ciphertext_toFile(answer_data, &ciphertextcarry1[i], params);	
				for (int i=0; i<32; i++) // 3
					export_gate_bootstrapping_ciphertext_toFile(answer_data, &ciphertextcarry1[i], params);	
				for (int i=0; i<32; i++) // 4
					export_gate_bootstrapping_ciphertext_toFile(answer_data, &ciphertextcarry1[i], params);	
				for (int i=0; i<32; i++) // 5
					export_gate_bootstrapping_ciphertext_toFile(answer_data, &ciphertextcarry1[i], params);	
				for (int i=0; i<32; i++) // 6
					export_gate_bootstrapping_ciphertext_toFile(answer_data, &ciphertextcarry1[i], params);	
				for (int i=0; i<32; i++) // 7
					export_gate_bootstrapping_ciphertext_toFile(answer_data, &ciphertextcarry1[i], params);	
				for (int i=0; i<32; i++) // 8
					export_gate_bootstrapping_ciphertext_toFile(answer_data, &ciphertextcarry1[i], params);		
				for (int i=0; i<32; i++) // carry
					export_gate_bootstrapping_ciphertext_toFile(answer_data, &ciphertextcarry1[i], params);					
				fclose(answer_data);
				
				delete_gate_bootstrapping_ciphertext_array(32, temp);
				delete_gate_bootstrapping_ciphertext_array(32, inverse1);
					
				delete_gate_bootstrapping_ciphertext_array(32, tempcarry1);
					
				delete_gate_bootstrapping_ciphertext_array(32, twosresult1);
					
				delete_gate_bootstrapping_ciphertext_array(32, twoscarry1);
				
				delete_gate_bootstrapping_ciphertext_array(32, carry1);
					
				delete_gate_bootstrapping_ciphertext_array(32, result1);
					
				delete_gate_bootstrapping_ciphertext_array(32, ciphertextbit1);
				delete_gate_bootstrapping_ciphertext_array(32, ciphertextnegative1);
				delete_gate_bootstrapping_ciphertext_array(32, ciphertextbit2);
				delete_gate_bootstrapping_ciphertext_array(32, ciphertextnegative2);
				delete_gate_bootstrapping_ciphertext_array(32, ciphertext1);
				delete_gate_bootstrapping_ciphertext_array(32, ciphertext9);
				delete_gate_bootstrapping_ciphertext_array(32, ciphertextcarry1);		
			}
			
			//64 Bit Subtraction
			if(int_bit == 64)
			{
				LweSample* temp = new_gate_bootstrapping_ciphertext_array(32, params);
				LweSample* inverse1 = new_gate_bootstrapping_ciphertext_array(32, params);
				LweSample* inverse2 = new_gate_bootstrapping_ciphertext_array(32, params);
				
				LweSample* tempcarry1 = new_gate_bootstrapping_ciphertext_array(32, params);
				LweSample* tempcarry2 = new_gate_bootstrapping_ciphertext_array(32, params);
				
				LweSample* twosresult1 = new_gate_bootstrapping_ciphertext_array(32, params);
				LweSample* twosresult2 = new_gate_bootstrapping_ciphertext_array(32, params);
				
				LweSample* twoscarry1 = new_gate_bootstrapping_ciphertext_array(32, params);
				LweSample* twoscarry2 = new_gate_bootstrapping_ciphertext_array(32, params);
				
				struct timeval start, end;
				double get_time;
				printf("Doing the homomorphic computation...\n");

				gettimeofday(&start, NULL);
				
				//Subtraction Process
				
				//Step 1. Inverse the 32 bit chunks in the second input value
				NOT(inverse1, ciphertext9, bk, 32);
				NOT(inverse2, ciphertext10, bk, 32);
				
				//iniailize tempcarry and temp carry to 0
				zero(temp, bk, 32);
				zero(tempcarry1, bk, 32); 
				zero(tempcarry2, bk, 32); 
				
				
				//Assign temp to have a value of 1 for 2nd complement
				bootsCONSTANT(temp, 1, bk); 
				
				//Add 1 to inverted
				add(twosresult1, twoscarry1, inverse1, temp, tempcarry1, 32, bk);
				
				//Add the rest of the inverted
				add(twosresult2, twoscarry2, inverse2, tempcarry2, twoscarry1, 32, bk);
				
			
				LweSample* result1 = new_gate_bootstrapping_ciphertext_array(32, params);
				LweSample* result2 = new_gate_bootstrapping_ciphertext_array(32, params);
				
				LweSample* carry1 = new_gate_bootstrapping_ciphertext_array(32, params);
				LweSample* carry2 = new_gate_bootstrapping_ciphertext_array(32, params);
				
				
				//Do the addition, this is basically adding the first value to the inversed value of the second value, a + (-b)
				add(result1, carry1, ciphertext1, twosresult1, ciphertextcarry1, 32, bk);
				add(result2, carry2, ciphertext2, twosresult2, carry1, 32, bk);
				
				gettimeofday(&end, NULL);
			
				get_time = (end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec) * 1.0E-6;
				printf("Computation Time: %lf[sec]\n", get_time);

				printf("writing the answer to file...\n");

				//export the 32 ciphertexts to a file (for the cloud)
				for (int i=0; i<32; i++) // result1
					export_gate_bootstrapping_ciphertext_toFile(answer_data, &result1[i], params);
				for (int i=0; i<32; i++) // result2
					export_gate_bootstrapping_ciphertext_toFile(answer_data, &result2[i], params);
				for (int i=0; i<32; i++) // 3
					export_gate_bootstrapping_ciphertext_toFile(answer_data, &ciphertextcarry1[i], params);	
				for (int i=0; i<32; i++) // 4
					export_gate_bootstrapping_ciphertext_toFile(answer_data, &ciphertextcarry1[i], params);	
				for (int i=0; i<32; i++) // 5
					export_gate_bootstrapping_ciphertext_toFile(answer_data, &ciphertextcarry1[i], params);	
				for (int i=0; i<32; i++) // 6
					export_gate_bootstrapping_ciphertext_toFile(answer_data, &ciphertextcarry1[i], params);	
				for (int i=0; i<32; i++) // 7
					export_gate_bootstrapping_ciphertext_toFile(answer_data, &ciphertextcarry1[i], params);	
				for (int i=0; i<32; i++) // 8
					export_gate_bootstrapping_ciphertext_toFile(answer_data, &ciphertextcarry1[i], params);	
				for (int i=0; i<32; i++) // carry
					export_gate_bootstrapping_ciphertext_toFile(answer_data, &ciphertextcarry1[i], params);
				fclose(answer_data);
				
				delete_gate_bootstrapping_ciphertext_array(32, temp);
				delete_gate_bootstrapping_ciphertext_array(32, inverse1);
				delete_gate_bootstrapping_ciphertext_array(32, inverse2);
					
				delete_gate_bootstrapping_ciphertext_array(32, tempcarry1);
				delete_gate_bootstrapping_ciphertext_array(32, tempcarry2);
					
				delete_gate_bootstrapping_ciphertext_array(32, twosresult1);
				delete_gate_bootstrapping_ciphertext_array(32, twosresult2);
					
				delete_gate_bootstrapping_ciphertext_array(32, twoscarry1);
				delete_gate_bootstrapping_ciphertext_array(32, twoscarry2);
				
				delete_gate_bootstrapping_ciphertext_array(32, carry1);
				delete_gate_bootstrapping_ciphertext_array(32, carry2);
					
				delete_gate_bootstrapping_ciphertext_array(32, result1);
				delete_gate_bootstrapping_ciphertext_array(32, result2);
					
				delete_gate_bootstrapping_ciphertext_array(32, ciphertextbit1);
				delete_gate_bootstrapping_ciphertext_array(32, ciphertextnegative1);
				delete_gate_bootstrapping_ciphertext_array(32, ciphertextbit2);
				delete_gate_bootstrapping_ciphertext_array(32, ciphertextnegative2);
				delete_gate_bootstrapping_ciphertext_array(32, ciphertext1);
				delete_gate_bootstrapping_ciphertext_array(32, ciphertext2);
				delete_gate_bootstrapping_ciphertext_array(32, ciphertext9);
				delete_gate_bootstrapping_ciphertext_array(32, ciphertext10);
				delete_gate_bootstrapping_ciphertext_array(32, ciphertextcarry1);
			}
			
			//128 Bit Subtraction
			if(int_bit == 128)
			{
				// reads the 2x32 ciphertexts from the cloud file
				
				printf("Doing the homomorphic computation...\n");

				//do some operations on the ciphertexts: here, we will compute the
				//difference of the two
				LweSample* temp = new_gate_bootstrapping_ciphertext_array(32, params);
				LweSample* inverse1 = new_gate_bootstrapping_ciphertext_array(32, params);
				LweSample* inverse2 = new_gate_bootstrapping_ciphertext_array(32, params);
				LweSample* inverse3 = new_gate_bootstrapping_ciphertext_array(32, params);
				LweSample* inverse4 = new_gate_bootstrapping_ciphertext_array(32, params);
				
				
				LweSample* tempcarry1 = new_gate_bootstrapping_ciphertext_array(32, params);
				LweSample* tempcarry2 = new_gate_bootstrapping_ciphertext_array(32, params);
				LweSample* tempcarry3 = new_gate_bootstrapping_ciphertext_array(32, params);
				LweSample* tempcarry4 = new_gate_bootstrapping_ciphertext_array(32, params);
				
				
				LweSample* twosresult1 = new_gate_bootstrapping_ciphertext_array(32, params);
				LweSample* twosresult2 = new_gate_bootstrapping_ciphertext_array(32, params);
				LweSample* twosresult3 = new_gate_bootstrapping_ciphertext_array(32, params);
				LweSample* twosresult4 = new_gate_bootstrapping_ciphertext_array(32, params);
				
				
				LweSample* twoscarry1 = new_gate_bootstrapping_ciphertext_array(32, params);
				LweSample* twoscarry2 = new_gate_bootstrapping_ciphertext_array(32, params);
				LweSample* twoscarry3 = new_gate_bootstrapping_ciphertext_array(32, params);
				LweSample* twoscarry4 = new_gate_bootstrapping_ciphertext_array(32, params);
				
				struct timeval start, end;
				double get_time;

				gettimeofday(&start, NULL);
				
				//Subtraction Process
				
				//Step 1. Inverse the 32 bit chunks in the second input value
				NOT(inverse1, ciphertext9, bk, 32);
				NOT(inverse2, ciphertext10, bk, 32);
				NOT(inverse3, ciphertext11, bk, 32);
				NOT(inverse4, ciphertext12, bk, 32);
				
				
				//iniailize tempcarry and temp carry to 0
				zero(temp, bk, 32);
				zero(tempcarry1, bk, 32); 
				zero(tempcarry2, bk, 32); 
				zero(tempcarry3, bk, 32); 
				zero(tempcarry4, bk, 32); 
				
				
				//Assign temp to have a value of 1 for 2nd complement
				bootsCONSTANT(temp, 1, bk); 
	

				//Add 1 to inverted
				add(twosresult1, twoscarry1, inverse1, temp, tempcarry1, 32, bk);
				
				//Add the rest of the inverted
				add(twosresult2, twoscarry2, inverse2, tempcarry2, twoscarry1, 32, bk);
				add(twosresult3, twoscarry3, inverse3, tempcarry3, twoscarry2, 32, bk);
				add(twosresult4, twoscarry4, inverse4, tempcarry4, twoscarry3, 32, bk);
				
				
				LweSample* result1 = new_gate_bootstrapping_ciphertext_array(32, params);
				LweSample* result2 = new_gate_bootstrapping_ciphertext_array(32, params);
				LweSample* result3 = new_gate_bootstrapping_ciphertext_array(32, params);
				LweSample* result4 = new_gate_bootstrapping_ciphertext_array(32, params);
				
				
				LweSample* carry1 = new_gate_bootstrapping_ciphertext_array(32, params);
				LweSample* carry2 = new_gate_bootstrapping_ciphertext_array(32, params);
				LweSample* carry3 = new_gate_bootstrapping_ciphertext_array(32, params);
				LweSample* carry4 = new_gate_bootstrapping_ciphertext_array(32, params);
				
				
				//Do the addition, this is basically adding the first value to the inversed value of the second value, a + (-b)
				add(result1, carry1, ciphertext1, twosresult1, ciphertextcarry1, 32, bk);
				add(result2, carry2, ciphertext2, twosresult2, carry1, 32, bk);
				add(result3, carry3, ciphertext3, twosresult3, carry2, 32, bk);
				add(result4, carry4, ciphertext4, twosresult4, carry3, 32, bk);
				
				gettimeofday(&end, NULL);

				get_time = (end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec) * 1.0E-6;
				printf("Computation Time: %lf[sec]\n", get_time);

				printf("writing the answer to file...\n");

				//export the 32 ciphertexts to a file (for the cloud)
				for (int i=0; i<32; i++) // result1
					export_gate_bootstrapping_ciphertext_toFile(answer_data, &result1[i], params);
				for (int i=0; i<32; i++) // result2
					export_gate_bootstrapping_ciphertext_toFile(answer_data, &result2[i], params);
				for (int i=0; i<32; i++) // result3
					export_gate_bootstrapping_ciphertext_toFile(answer_data, &result3[i], params);
				for (int i=0; i<32; i++) // result4
					export_gate_bootstrapping_ciphertext_toFile(answer_data, &result4[i], params);
				for (int i=0; i<32; i++) // 5
					export_gate_bootstrapping_ciphertext_toFile(answer_data, &ciphertextcarry1[i], params);	
				for (int i=0; i<32; i++) // 6
					export_gate_bootstrapping_ciphertext_toFile(answer_data, &ciphertextcarry1[i], params);	
				for (int i=0; i<32; i++) // 7
					export_gate_bootstrapping_ciphertext_toFile(answer_data, &ciphertextcarry1[i], params);	
				for (int i=0; i<32; i++) // 8
					export_gate_bootstrapping_ciphertext_toFile(answer_data, &ciphertextcarry1[i], params);	
				for (int i=0; i<32; i++) // carry
					export_gate_bootstrapping_ciphertext_toFile(answer_data, &ciphertextcarry1[i], params);
				fclose(answer_data);
				
			

				//clean up all pointers
				delete_gate_bootstrapping_ciphertext_array(32, temp);
				delete_gate_bootstrapping_ciphertext_array(32, inverse1);
				delete_gate_bootstrapping_ciphertext_array(32, inverse2);
				delete_gate_bootstrapping_ciphertext_array(32, inverse3);
				delete_gate_bootstrapping_ciphertext_array(32, inverse4);
				
				
				delete_gate_bootstrapping_ciphertext_array(32, tempcarry1);
				delete_gate_bootstrapping_ciphertext_array(32, tempcarry2);
				delete_gate_bootstrapping_ciphertext_array(32, tempcarry3);
				delete_gate_bootstrapping_ciphertext_array(32, tempcarry4);
				
				
				delete_gate_bootstrapping_ciphertext_array(32, twosresult1);
				delete_gate_bootstrapping_ciphertext_array(32, twosresult2);
				delete_gate_bootstrapping_ciphertext_array(32, twosresult3);
				delete_gate_bootstrapping_ciphertext_array(32, twosresult4);
				
				
				delete_gate_bootstrapping_ciphertext_array(32, twoscarry1);
				delete_gate_bootstrapping_ciphertext_array(32, twoscarry2);
				delete_gate_bootstrapping_ciphertext_array(32, twoscarry3);
				delete_gate_bootstrapping_ciphertext_array(32, twoscarry4);
				
				
				delete_gate_bootstrapping_ciphertext_array(32, carry1);
				delete_gate_bootstrapping_ciphertext_array(32, carry2);
				delete_gate_bootstrapping_ciphertext_array(32, carry3);
				delete_gate_bootstrapping_ciphertext_array(32, carry4);
				delete_gate_bootstrapping_ciphertext_array(32, result1);
				delete_gate_bootstrapping_ciphertext_array(32, result2);
				delete_gate_bootstrapping_ciphertext_array(32, result3);
				delete_gate_bootstrapping_ciphertext_array(32, result4);
					
				delete_gate_bootstrapping_ciphertext_array(32, ciphertextbit1);
				delete_gate_bootstrapping_ciphertext_array(32, ciphertextnegative1);
				delete_gate_bootstrapping_ciphertext_array(32, ciphertextbit2);
				delete_gate_bootstrapping_ciphertext_array(32, ciphertextnegative2);
				delete_gate_bootstrapping_ciphertext_array(32, ciphertext1);
				delete_gate_bootstrapping_ciphertext_array(32, ciphertext2);
				delete_gate_bootstrapping_ciphertext_array(32, ciphertext3);
				delete_gate_bootstrapping_ciphertext_array(32, ciphertext4);
				delete_gate_bootstrapping_ciphertext_array(32, ciphertext9);
				delete_gate_bootstrapping_ciphertext_array(32, ciphertext10);
				delete_gate_bootstrapping_ciphertext_array(32, ciphertext11);
				delete_gate_bootstrapping_ciphertext_array(32, ciphertext12);
				delete_gate_bootstrapping_ciphertext_array(32, ciphertextcarry1);
					
			}
			
			//256 Bit Subtraction
			if (int_bit == 256) 
			{
				// reads the 2x32 ciphertexts from the cloud file
				
				printf("Doing the homomorphic computation...\n");

				//do some operations on the ciphertexts: here, we will compute the
				//difference of the two
				LweSample* temp = new_gate_bootstrapping_ciphertext_array(32, params);
				LweSample* inverse1 = new_gate_bootstrapping_ciphertext_array(32, params);
				LweSample* inverse2 = new_gate_bootstrapping_ciphertext_array(32, params);
				LweSample* inverse3 = new_gate_bootstrapping_ciphertext_array(32, params);
				LweSample* inverse4 = new_gate_bootstrapping_ciphertext_array(32, params);
				LweSample* inverse5 = new_gate_bootstrapping_ciphertext_array(32, params);
				LweSample* inverse6 = new_gate_bootstrapping_ciphertext_array(32, params);
				LweSample* inverse7 = new_gate_bootstrapping_ciphertext_array(32, params);
				LweSample* inverse8 = new_gate_bootstrapping_ciphertext_array(32, params);
				
				LweSample* tempcarry1 = new_gate_bootstrapping_ciphertext_array(32, params);
				LweSample* tempcarry2 = new_gate_bootstrapping_ciphertext_array(32, params);
				LweSample* tempcarry3 = new_gate_bootstrapping_ciphertext_array(32, params);
				LweSample* tempcarry4 = new_gate_bootstrapping_ciphertext_array(32, params);
				LweSample* tempcarry5 = new_gate_bootstrapping_ciphertext_array(32, params);
				LweSample* tempcarry6 = new_gate_bootstrapping_ciphertext_array(32, params);
				LweSample* tempcarry7 = new_gate_bootstrapping_ciphertext_array(32, params);
				LweSample* tempcarry8 = new_gate_bootstrapping_ciphertext_array(32, params);
				
				LweSample* twosresult1 = new_gate_bootstrapping_ciphertext_array(32, params);
				LweSample* twosresult2 = new_gate_bootstrapping_ciphertext_array(32, params);
				LweSample* twosresult3 = new_gate_bootstrapping_ciphertext_array(32, params);
				LweSample* twosresult4 = new_gate_bootstrapping_ciphertext_array(32, params);
				LweSample* twosresult5 = new_gate_bootstrapping_ciphertext_array(32, params);
				LweSample* twosresult6 = new_gate_bootstrapping_ciphertext_array(32, params);
				LweSample* twosresult7 = new_gate_bootstrapping_ciphertext_array(32, params);
				LweSample* twosresult8 = new_gate_bootstrapping_ciphertext_array(32, params);
				
				LweSample* twoscarry1 = new_gate_bootstrapping_ciphertext_array(32, params);
				LweSample* twoscarry2 = new_gate_bootstrapping_ciphertext_array(32, params);
				LweSample* twoscarry3 = new_gate_bootstrapping_ciphertext_array(32, params);
				LweSample* twoscarry4 = new_gate_bootstrapping_ciphertext_array(32, params);
				LweSample* twoscarry5 = new_gate_bootstrapping_ciphertext_array(32, params);
				LweSample* twoscarry6 = new_gate_bootstrapping_ciphertext_array(32, params);
				LweSample* twoscarry7 = new_gate_bootstrapping_ciphertext_array(32, params);
				LweSample* twoscarry8 = new_gate_bootstrapping_ciphertext_array(32, params);
	
	
				struct timeval start, end;
				double get_time;

				gettimeofday(&start, NULL);
				
				//Subtraction Process
				
				//Step 1. Inverse the 32 bit chunks in the second input value
				NOT(inverse1, ciphertext9, bk, 32);
				NOT(inverse2, ciphertext10, bk, 32);
				NOT(inverse3, ciphertext11, bk, 32);
				NOT(inverse4, ciphertext12, bk, 32);
				NOT(inverse5, ciphertext13, bk, 32);
				NOT(inverse6, ciphertext14, bk, 32);
				NOT(inverse7, ciphertext15, bk, 32);
				NOT(inverse8, ciphertext16, bk, 32);
				
				//iniailize tempcarry and temp carry to 0
				zero(temp, bk, 32);
				zero(tempcarry1, bk, 32); 
				zero(tempcarry2, bk, 32); 
				zero(tempcarry3, bk, 32); 
				zero(tempcarry4, bk, 32); 
				zero(tempcarry5, bk, 32); 
				zero(tempcarry6, bk, 32); 
				zero(tempcarry7, bk, 32); 
				zero(tempcarry8, bk, 32); 
				
				//Assign temp to have a value of 1 for 2nd complement
				bootsCONSTANT(temp, 1, bk); 
	
				//Add 1 to inverted
				add(twosresult1, twoscarry1, inverse1, temp, tempcarry1, 32, bk);
				
				//Add the rest of the inverted
				add(twosresult2, twoscarry2, inverse2, tempcarry2, twoscarry1, 32, bk);
				add(twosresult3, twoscarry3, inverse3, tempcarry3, twoscarry2, 32, bk);
				add(twosresult4, twoscarry4, inverse4, tempcarry4, twoscarry3, 32, bk);
				add(twosresult5, twoscarry5, inverse5, tempcarry5, twoscarry4, 32, bk);
				add(twosresult6, twoscarry6, inverse6, tempcarry6, twoscarry5, 32, bk);
				add(twosresult7, twoscarry7, inverse7, tempcarry7, twoscarry6, 32, bk);
				add(twosresult8, twoscarry8, inverse8, tempcarry8, twoscarry7, 32, bk);
				
				LweSample* result1 = new_gate_bootstrapping_ciphertext_array(32, params);
				LweSample* result2 = new_gate_bootstrapping_ciphertext_array(32, params);
				LweSample* result3 = new_gate_bootstrapping_ciphertext_array(32, params);
				LweSample* result4 = new_gate_bootstrapping_ciphertext_array(32, params);
				LweSample* result5 = new_gate_bootstrapping_ciphertext_array(32, params);
				LweSample* result6 = new_gate_bootstrapping_ciphertext_array(32, params);
				LweSample* result7 = new_gate_bootstrapping_ciphertext_array(32, params);
				LweSample* result8 = new_gate_bootstrapping_ciphertext_array(32, params);
				
				LweSample* carry1 = new_gate_bootstrapping_ciphertext_array(32, params);
				LweSample* carry2 = new_gate_bootstrapping_ciphertext_array(32, params);
				LweSample* carry3 = new_gate_bootstrapping_ciphertext_array(32, params);
				LweSample* carry4 = new_gate_bootstrapping_ciphertext_array(32, params);
				LweSample* carry5 = new_gate_bootstrapping_ciphertext_array(32, params);
				LweSample* carry6 = new_gate_bootstrapping_ciphertext_array(32, params);
				LweSample* carry7 = new_gate_bootstrapping_ciphertext_array(32, params);
				LweSample* carry8 = new_gate_bootstrapping_ciphertext_array(32, params);
				
				//Do the addition, this is basically adding the first value to the inversed value of the second value, a + (-b)
				add(result1, carry1, ciphertext1, twosresult1, ciphertextcarry1, 32, bk);
				add(result2, carry2, ciphertext2, twosresult2, carry1, 32, bk);
				add(result3, carry3, ciphertext3, twosresult3, carry2, 32, bk);
				add(result4, carry4, ciphertext4, twosresult4, carry3, 32, bk);
				add(result5, carry5, ciphertext5, twosresult5, carry4, 32, bk);
				add(result6, carry6, ciphertext6, twosresult6, carry5, 32, bk);
				add(result7, carry7, ciphertext7, twosresult7, carry6, 32, bk);
				add(result8, carry8, ciphertext8, twosresult8, carry7, 32, bk);

				gettimeofday(&end, NULL);

				get_time = (end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec) * 1.0E-6;
				printf("Computation Time: %lf[sec]\n", get_time);

				printf("Writing the answer to file...\n");

				//export the 32 ciphertexts to a file (for the cloud)
				for (int i=0; i<32; i++) //result1
					export_gate_bootstrapping_ciphertext_toFile(answer_data, &result1[i], params);
				for (int i=0; i<32; i++) //result2
					export_gate_bootstrapping_ciphertext_toFile(answer_data, &result2[i], params);
				for (int i=0; i<32; i++) //result3
					export_gate_bootstrapping_ciphertext_toFile(answer_data, &result3[i], params);
				for (int i=0; i<32; i++) //result4
					export_gate_bootstrapping_ciphertext_toFile(answer_data, &result4[i], params);
				for (int i=0; i<32; i++) //result5
					export_gate_bootstrapping_ciphertext_toFile(answer_data, &result5[i], params);
				for (int i=0; i<32; i++) //result6
					export_gate_bootstrapping_ciphertext_toFile(answer_data, &result6[i], params);
				for (int i=0; i<32; i++) //result7
					export_gate_bootstrapping_ciphertext_toFile(answer_data, &result7[i], params);
				for (int i=0; i<32; i++) //result8
					export_gate_bootstrapping_ciphertext_toFile(answer_data, &result8[i], params);
				for (int i=0; i<32; i++) // carry
					export_gate_bootstrapping_ciphertext_toFile(answer_data, &ciphertextcarry1[i], params);
				fclose(answer_data);

				//clean up all pointers
				delete_gate_bootstrapping_ciphertext_array(32, temp);
				delete_gate_bootstrapping_ciphertext_array(32, inverse1);
				delete_gate_bootstrapping_ciphertext_array(32, inverse2);
				delete_gate_bootstrapping_ciphertext_array(32, inverse3);
				delete_gate_bootstrapping_ciphertext_array(32, inverse4);
				delete_gate_bootstrapping_ciphertext_array(32, inverse5);
				delete_gate_bootstrapping_ciphertext_array(32, inverse6);
				delete_gate_bootstrapping_ciphertext_array(32, inverse7);
				delete_gate_bootstrapping_ciphertext_array(32, inverse8);
				
				delete_gate_bootstrapping_ciphertext_array(32, tempcarry1);
				delete_gate_bootstrapping_ciphertext_array(32, tempcarry2);
				delete_gate_bootstrapping_ciphertext_array(32, tempcarry3);
				delete_gate_bootstrapping_ciphertext_array(32, tempcarry4);
				delete_gate_bootstrapping_ciphertext_array(32, tempcarry5);
				delete_gate_bootstrapping_ciphertext_array(32, tempcarry6);
				delete_gate_bootstrapping_ciphertext_array(32, tempcarry7);
				delete_gate_bootstrapping_ciphertext_array(32, tempcarry8);
				
				delete_gate_bootstrapping_ciphertext_array(32, twosresult1);
				delete_gate_bootstrapping_ciphertext_array(32, twosresult2);
				delete_gate_bootstrapping_ciphertext_array(32, twosresult3);
				delete_gate_bootstrapping_ciphertext_array(32, twosresult4);
				delete_gate_bootstrapping_ciphertext_array(32, twosresult5);
				delete_gate_bootstrapping_ciphertext_array(32, twosresult6);
				delete_gate_bootstrapping_ciphertext_array(32, twosresult7);
				delete_gate_bootstrapping_ciphertext_array(32, twosresult8);
				
				delete_gate_bootstrapping_ciphertext_array(32, twoscarry1);
				delete_gate_bootstrapping_ciphertext_array(32, twoscarry2);
				delete_gate_bootstrapping_ciphertext_array(32, twoscarry3);
				delete_gate_bootstrapping_ciphertext_array(32, twoscarry4);
				delete_gate_bootstrapping_ciphertext_array(32, twoscarry5);
				delete_gate_bootstrapping_ciphertext_array(32, twoscarry6);
				delete_gate_bootstrapping_ciphertext_array(32, twoscarry7);
				delete_gate_bootstrapping_ciphertext_array(32, twoscarry8);
				
				delete_gate_bootstrapping_ciphertext_array(32, carry1);
				delete_gate_bootstrapping_ciphertext_array(32, carry2);
				delete_gate_bootstrapping_ciphertext_array(32, result1);
				delete_gate_bootstrapping_ciphertext_array(32, result2);
				delete_gate_bootstrapping_ciphertext_array(32, result3);
				delete_gate_bootstrapping_ciphertext_array(32, result4);
				delete_gate_bootstrapping_ciphertext_array(32, result5);
				delete_gate_bootstrapping_ciphertext_array(32, result6);
				delete_gate_bootstrapping_ciphertext_array(32, result7);
				delete_gate_bootstrapping_ciphertext_array(32, result8);
					
				delete_gate_bootstrapping_ciphertext_array(32, ciphertextbit1);
				delete_gate_bootstrapping_ciphertext_array(32, ciphertextnegative1);
				delete_gate_bootstrapping_ciphertext_array(32, ciphertextbit2);
				delete_gate_bootstrapping_ciphertext_array(32, ciphertextnegative2);
				delete_gate_bootstrapping_ciphertext_array(32, ciphertext1);
				delete_gate_bootstrapping_ciphertext_array(32, ciphertext2);
				delete_gate_bootstrapping_ciphertext_array(32, ciphertext3);
				delete_gate_bootstrapping_ciphertext_array(32, ciphertext4);
				delete_gate_bootstrapping_ciphertext_array(32, ciphertext5);
				delete_gate_bootstrapping_ciphertext_array(32, ciphertext6);
				delete_gate_bootstrapping_ciphertext_array(32, ciphertext7);
				delete_gate_bootstrapping_ciphertext_array(32, ciphertext8);
				delete_gate_bootstrapping_ciphertext_array(32, ciphertext9);
				delete_gate_bootstrapping_ciphertext_array(32, ciphertext10);
				delete_gate_bootstrapping_ciphertext_array(32, ciphertext11);
				delete_gate_bootstrapping_ciphertext_array(32, ciphertext12);
				delete_gate_bootstrapping_ciphertext_array(32, ciphertext13);
				delete_gate_bootstrapping_ciphertext_array(32, ciphertext14);
				delete_gate_bootstrapping_ciphertext_array(32, ciphertext15);
				delete_gate_bootstrapping_ciphertext_array(32, ciphertext16);
				delete_gate_bootstrapping_ciphertext_array(32, ciphertextcarry1);
			}
    		
    	}
    	//Addition (for subtraction) with value 1 being a negative number (-A)+B
    	else{
			if (int_op == 2){
    			std::cout << int_bit << " bit Subtraction computation" << "\n";
    		}else {
    			std::cout << int_bit << " bit Addition computation with 1st value negative" << "\n";
			}
		    if(int_bit == 32){
				LweSample* temp = new_gate_bootstrapping_ciphertext_array(32, params);
				LweSample* inverse1 = new_gate_bootstrapping_ciphertext_array(32, params);
				LweSample* tempcarry1 = new_gate_bootstrapping_ciphertext_array(32, params);
				LweSample* twosresult1 = new_gate_bootstrapping_ciphertext_array(32, params);
				LweSample* twoscarry1 = new_gate_bootstrapping_ciphertext_array(32, params);
						
				struct timeval start, end;
				double get_time;
				printf("Doing the homomorphic computation...\n");
				gettimeofday(&start, NULL);
						
				//Subtraction Process
						
				//Step 1. Inverse the 32 bit chunks in the first input value
				NOT(inverse1, ciphertext1, bk, 32);
						
				//iniailize tempcarry and temp carry to 0
				zero(temp, bk, 32);
				zero(tempcarry1, bk, 32); 
						
				//Assign temp to have a value of 1 for 2nd complement
				bootsCONSTANT(temp, 1, bk); 
						
				//Add 1 to inverted
				add(twosresult1, twoscarry1, inverse1, temp, tempcarry1, 32, bk);
						
				LweSample* result1 = new_gate_bootstrapping_ciphertext_array(32, params);
				LweSample* carry1 = new_gate_bootstrapping_ciphertext_array(32, params);
						
				//Do the addition, this is basically adding the first value to the inversed value of the second value, a + (-b)
				add(result1, carry1, ciphertext9, twosresult1, ciphertextcarry1, 32, bk);
						
				gettimeofday(&end, NULL);
				get_time = (end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec) * 1.0E-6;
				printf("Computation Time: %lf[sec]\n", get_time);

				printf("writing the answer to file...\n");

				//export the 32 ciphertexts to a file (for the cloud)
					
				for (int i=0; i<32; i++) // result1
					export_gate_bootstrapping_ciphertext_toFile(answer_data, &result1[i], params);
				for (int i=0; i<32; i++) // 2
					export_gate_bootstrapping_ciphertext_toFile(answer_data, &ciphertextcarry1[i], params);	
				for (int i=0; i<32; i++) // 3
					export_gate_bootstrapping_ciphertext_toFile(answer_data, &ciphertextcarry1[i], params);	
				for (int i=0; i<32; i++) // 4
					export_gate_bootstrapping_ciphertext_toFile(answer_data, &ciphertextcarry1[i], params);	
				for (int i=0; i<32; i++) // 5
					export_gate_bootstrapping_ciphertext_toFile(answer_data, &ciphertextcarry1[i], params);	
				for (int i=0; i<32; i++) // 6
					export_gate_bootstrapping_ciphertext_toFile(answer_data, &ciphertextcarry1[i], params);	
				for (int i=0; i<32; i++) // 7
					export_gate_bootstrapping_ciphertext_toFile(answer_data, &ciphertextcarry1[i], params);	
				for (int i=0; i<32; i++) // 8
					export_gate_bootstrapping_ciphertext_toFile(answer_data, &ciphertextcarry1[i], params);	
				for (int i=0; i<32; i++) // carry
					export_gate_bootstrapping_ciphertext_toFile(answer_data, &ciphertextcarry1[i], params);
				fclose(answer_data);
						
				delete_gate_bootstrapping_ciphertext_array(32, temp);
				delete_gate_bootstrapping_ciphertext_array(32, inverse1);
				delete_gate_bootstrapping_ciphertext_array(32, tempcarry1);
				delete_gate_bootstrapping_ciphertext_array(32, twosresult1);
				delete_gate_bootstrapping_ciphertext_array(32, twoscarry1);
				delete_gate_bootstrapping_ciphertext_array(32, carry1);
				delete_gate_bootstrapping_ciphertext_array(32, result1);
							
				delete_gate_bootstrapping_ciphertext_array(32, ciphertext1);
				delete_gate_bootstrapping_ciphertext_array(32, ciphertext9);
				delete_gate_bootstrapping_ciphertext_array(32, ciphertextcarry1);
						
				}
			else if (int_bit == 64){
					
				LweSample* temp = new_gate_bootstrapping_ciphertext_array(32, params);
				LweSample* inverse1 = new_gate_bootstrapping_ciphertext_array(32, params);
				LweSample* inverse2 = new_gate_bootstrapping_ciphertext_array(32, params);
					
				LweSample* tempcarry1 = new_gate_bootstrapping_ciphertext_array(32, params);
				LweSample* tempcarry2 = new_gate_bootstrapping_ciphertext_array(32, params);
					
				LweSample* twosresult1 = new_gate_bootstrapping_ciphertext_array(32, params);
				LweSample* twosresult2 = new_gate_bootstrapping_ciphertext_array(32, params);
					
				LweSample* twoscarry1 = new_gate_bootstrapping_ciphertext_array(32, params);
				LweSample* twoscarry2 = new_gate_bootstrapping_ciphertext_array(32, params);
					
				struct timeval start, end;
				double get_time;
				printf("Doing the homomorphic computation...\n");
				gettimeofday(&start, NULL);
					
				//Subtraction Process
				
				//Step 1. Inverse the 32 bit chunks in the first input value
				NOT(inverse1, ciphertext1, bk, 32);
				NOT(inverse2, ciphertext2, bk, 32);
					
				//iniailize tempcarry and temp carry to 0
				zero(temp, bk, 32);
				zero(tempcarry1, bk, 32); 
				zero(tempcarry2, bk, 32); 
					
					
				//Assign temp to have a value of 1 for 2nd complement
				bootsCONSTANT(temp, 1, bk); 
					
				//Add 1 to inverted
				add(twosresult1, twoscarry1, inverse1, temp, tempcarry1, 32, bk);
					
				//Add the rest of the inverted
				add(twosresult2, twoscarry2, inverse2, tempcarry2, twoscarry1, 32, bk);
					
				LweSample* result1 = new_gate_bootstrapping_ciphertext_array(32, params);
				LweSample* result2 = new_gate_bootstrapping_ciphertext_array(32, params);
					
				LweSample* carry1 = new_gate_bootstrapping_ciphertext_array(32, params);
				LweSample* carry2 = new_gate_bootstrapping_ciphertext_array(32, params);
						
				//Do the addition, this is basically adding the first inversed value to the second value, (-a) + b
				add(result1, carry1, ciphertext9, twosresult1, ciphertextcarry1, 32, bk);
				add(result2, carry2, ciphertext10, twosresult2, carry1, 32, bk);
					
				gettimeofday(&end, NULL);
				get_time = (end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec) * 1.0E-6;
				printf("Computation Time: %lf[sec]\n", get_time);

				printf("writing the answer to file...\n");

				//export the 32 ciphertexts to a file (for the cloud)
				for (int i=0; i<32; i++) // result1
					export_gate_bootstrapping_ciphertext_toFile(answer_data, &result1[i], params);
				for (int i=0; i<32; i++) //result2
					export_gate_bootstrapping_ciphertext_toFile(answer_data, &result2[i], params);
				for (int i=0; i<32; i++) // 3
					export_gate_bootstrapping_ciphertext_toFile(answer_data, &ciphertextcarry1[i], params);	
				for (int i=0; i<32; i++) // 4
					export_gate_bootstrapping_ciphertext_toFile(answer_data, &ciphertextcarry1[i], params);	
				for (int i=0; i<32; i++) // 5
					export_gate_bootstrapping_ciphertext_toFile(answer_data, &ciphertextcarry1[i], params);	
				for (int i=0; i<32; i++) // 6
					export_gate_bootstrapping_ciphertext_toFile(answer_data, &ciphertextcarry1[i], params);	
				for (int i=0; i<32; i++) // 7
					export_gate_bootstrapping_ciphertext_toFile(answer_data, &ciphertextcarry1[i], params);	
				for (int i=0; i<32; i++) // 8
					export_gate_bootstrapping_ciphertext_toFile(answer_data, &ciphertextcarry1[i], params);	
				for (int i=0; i<32; i++) // carry
					export_gate_bootstrapping_ciphertext_toFile(answer_data, &ciphertextcarry1[i], params);
				fclose(answer_data);
					
				delete_gate_bootstrapping_ciphertext_array(32, temp);
				delete_gate_bootstrapping_ciphertext_array(32, inverse1);
				delete_gate_bootstrapping_ciphertext_array(32, inverse2);		
				delete_gate_bootstrapping_ciphertext_array(32, tempcarry1);
				delete_gate_bootstrapping_ciphertext_array(32, tempcarry2);
				delete_gate_bootstrapping_ciphertext_array(32, twosresult1);
				delete_gate_bootstrapping_ciphertext_array(32, twosresult2);
				delete_gate_bootstrapping_ciphertext_array(32, twoscarry1);
				delete_gate_bootstrapping_ciphertext_array(32, twoscarry2);
				delete_gate_bootstrapping_ciphertext_array(32, carry1);
				delete_gate_bootstrapping_ciphertext_array(32, carry2);
				delete_gate_bootstrapping_ciphertext_array(32, result1);
				delete_gate_bootstrapping_ciphertext_array(32, result2);
				delete_gate_bootstrapping_ciphertext_array(32, ciphertextbit1);
				delete_gate_bootstrapping_ciphertext_array(32, ciphertextnegative1);
				delete_gate_bootstrapping_ciphertext_array(32, ciphertextbit2);
				delete_gate_bootstrapping_ciphertext_array(32, ciphertextnegative2);
				delete_gate_bootstrapping_ciphertext_array(32, ciphertext1);
				delete_gate_bootstrapping_ciphertext_array(32, ciphertext2);
				delete_gate_bootstrapping_ciphertext_array(32, ciphertext9);
				delete_gate_bootstrapping_ciphertext_array(32, ciphertext10);
				delete_gate_bootstrapping_ciphertext_array(32, ciphertextcarry1);
				}
			else if (int_bit == 128){

			printf("Doing the homomorphic computation...\n");

			//do some operations on the ciphertexts: here, we will compute the
			//difference of the two
			LweSample* temp = new_gate_bootstrapping_ciphertext_array(32, params);
			LweSample* inverse1 = new_gate_bootstrapping_ciphertext_array(32, params);
			LweSample* inverse2 = new_gate_bootstrapping_ciphertext_array(32, params);
			LweSample* inverse3 = new_gate_bootstrapping_ciphertext_array(32, params);
			LweSample* inverse4 = new_gate_bootstrapping_ciphertext_array(32, params);
							
			LweSample* tempcarry1 = new_gate_bootstrapping_ciphertext_array(32, params);
			LweSample* tempcarry2 = new_gate_bootstrapping_ciphertext_array(32, params);
			LweSample* tempcarry3 = new_gate_bootstrapping_ciphertext_array(32, params);
			LweSample* tempcarry4 = new_gate_bootstrapping_ciphertext_array(32, params);
					
			LweSample* twosresult1 = new_gate_bootstrapping_ciphertext_array(32, params);
			LweSample* twosresult2 = new_gate_bootstrapping_ciphertext_array(32, params);
			LweSample* twosresult3 = new_gate_bootstrapping_ciphertext_array(32, params);
			LweSample* twosresult4 = new_gate_bootstrapping_ciphertext_array(32, params);
					
			LweSample* twoscarry1 = new_gate_bootstrapping_ciphertext_array(32, params);
			LweSample* twoscarry2 = new_gate_bootstrapping_ciphertext_array(32, params);
			LweSample* twoscarry3 = new_gate_bootstrapping_ciphertext_array(32, params);
			LweSample* twoscarry4 = new_gate_bootstrapping_ciphertext_array(32, params);
					
			struct timeval start, end;
			double get_time;
			gettimeofday(&start, NULL);
					
			//Subtraction Process
					
			//Step 1. Inverse the 32 bit chunks in the first input value
			NOT(inverse1, ciphertext1, bk, 32);
			NOT(inverse2, ciphertext2, bk, 32);
			NOT(inverse3, ciphertext3, bk, 32);
			NOT(inverse4, ciphertext4, bk, 32);
					
			//iniailize tempcarry and temp carry to 0
			zero(temp, bk, 32);
			zero(tempcarry1, bk, 32); 
			zero(tempcarry2, bk, 32); 
			zero(tempcarry3, bk, 32); 
			zero(tempcarry4, bk, 32); 
					
			//Assign temp to have a value of 1 for 2nd complement
			bootsCONSTANT(temp, 1, bk); 
	
			//Add 1 to inverted
			add(twosresult1, twoscarry1, inverse1, temp, tempcarry1, 32, bk);
				
			//Add the rest of the inverted
			add(twosresult2, twoscarry2, inverse2, tempcarry2, twoscarry1, 32, bk);
			add(twosresult3, twoscarry3, inverse3, tempcarry3, twoscarry2, 32, bk);
			add(twosresult4, twoscarry4, inverse4, tempcarry4, twoscarry3, 32, bk);
					
			LweSample* result1 = new_gate_bootstrapping_ciphertext_array(32, params);
			LweSample* result2 = new_gate_bootstrapping_ciphertext_array(32, params);
			LweSample* result3 = new_gate_bootstrapping_ciphertext_array(32, params);
			LweSample* result4 = new_gate_bootstrapping_ciphertext_array(32, params);
					
			LweSample* carry1 = new_gate_bootstrapping_ciphertext_array(32, params);
			LweSample* carry2 = new_gate_bootstrapping_ciphertext_array(32, params);
			LweSample* carry3 = new_gate_bootstrapping_ciphertext_array(32, params);
			LweSample* carry4 = new_gate_bootstrapping_ciphertext_array(32, params);
					
			//Do the addition, this is basically adding the first inversed value to the second value,(-a) + b
			add(result1, carry1, ciphertext9, twosresult1, ciphertextcarry1, 32, bk);
			add(result2, carry2, ciphertext10, twosresult2, carry1, 32, bk);
			add(result3, carry3, ciphertext11, twosresult3, carry2, 32, bk);
			add(result4, carry4, ciphertext12, twosresult4, carry3, 32, bk);
					
			gettimeofday(&end, NULL);

			get_time = (end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec) * 1.0E-6;
			printf("Computation Time: %lf[sec]\n", get_time);

			printf("writing the answer to file...\n");

			//export the 32 ciphertexts to a file (for the cloud)
					
			for (int i=0; i<32; i++) // result1
				export_gate_bootstrapping_ciphertext_toFile(answer_data, &result1[i], params);
			for (int i=0; i<32; i++) // result2
				export_gate_bootstrapping_ciphertext_toFile(answer_data, &result2[i], params);
			for (int i=0; i<32; i++) // result3
				export_gate_bootstrapping_ciphertext_toFile(answer_data, &result3[i], params);
			for (int i=0; i<32; i++) // result4
				export_gate_bootstrapping_ciphertext_toFile(answer_data, &result4[i], params);
			for (int i=0; i<32; i++) // 5
				export_gate_bootstrapping_ciphertext_toFile(answer_data, &ciphertextcarry1[i], params);	
			for (int i=0; i<32; i++) // 6
				export_gate_bootstrapping_ciphertext_toFile(answer_data, &ciphertextcarry1[i], params);	
			for (int i=0; i<32; i++) // 7
				export_gate_bootstrapping_ciphertext_toFile(answer_data, &ciphertextcarry1[i], params);	
			for (int i=0; i<32; i++) // 8
				export_gate_bootstrapping_ciphertext_toFile(answer_data, &ciphertextcarry1[i], params);	
			for (int i=0; i<32; i++) // carry
				export_gate_bootstrapping_ciphertext_toFile(answer_data, &ciphertextcarry1[i], params);
			fclose(answer_data);	

			//clean up all pointers
			delete_gate_bootstrapping_ciphertext_array(32, temp);
			delete_gate_bootstrapping_ciphertext_array(32, inverse1);
			delete_gate_bootstrapping_ciphertext_array(32, inverse2);
			delete_gate_bootstrapping_ciphertext_array(32, inverse3);
			delete_gate_bootstrapping_ciphertext_array(32, inverse4);			
						
			delete_gate_bootstrapping_ciphertext_array(32, tempcarry1);
			delete_gate_bootstrapping_ciphertext_array(32, tempcarry2);
			delete_gate_bootstrapping_ciphertext_array(32, tempcarry3);
			delete_gate_bootstrapping_ciphertext_array(32, tempcarry4);
						
			delete_gate_bootstrapping_ciphertext_array(32, twosresult1);
			delete_gate_bootstrapping_ciphertext_array(32, twosresult2);
			delete_gate_bootstrapping_ciphertext_array(32, twosresult3);
			delete_gate_bootstrapping_ciphertext_array(32, twosresult4);
						
			delete_gate_bootstrapping_ciphertext_array(32, twoscarry1);
			delete_gate_bootstrapping_ciphertext_array(32, twoscarry2);
			delete_gate_bootstrapping_ciphertext_array(32, twoscarry3);
			delete_gate_bootstrapping_ciphertext_array(32, twoscarry4);
						
			delete_gate_bootstrapping_ciphertext_array(32, carry1);
			delete_gate_bootstrapping_ciphertext_array(32, carry2);
			delete_gate_bootstrapping_ciphertext_array(32, carry3);
			delete_gate_bootstrapping_ciphertext_array(32, carry4);
			delete_gate_bootstrapping_ciphertext_array(32, result1);
			delete_gate_bootstrapping_ciphertext_array(32, result2);
			delete_gate_bootstrapping_ciphertext_array(32, result3);
			delete_gate_bootstrapping_ciphertext_array(32, result4);
			
			delete_gate_bootstrapping_ciphertext_array(32, ciphertextbit1);
			delete_gate_bootstrapping_ciphertext_array(32, ciphertextnegative1);
			delete_gate_bootstrapping_ciphertext_array(32, ciphertextbit2);
			delete_gate_bootstrapping_ciphertext_array(32, ciphertextnegative2);
			delete_gate_bootstrapping_ciphertext_array(32, ciphertext1);
			delete_gate_bootstrapping_ciphertext_array(32, ciphertext2);
			delete_gate_bootstrapping_ciphertext_array(32, ciphertext3);
			delete_gate_bootstrapping_ciphertext_array(32, ciphertext4);
			delete_gate_bootstrapping_ciphertext_array(32, ciphertext5);
			delete_gate_bootstrapping_ciphertext_array(32, ciphertext6);
			delete_gate_bootstrapping_ciphertext_array(32, ciphertext7);
			delete_gate_bootstrapping_ciphertext_array(32, ciphertext8);
			delete_gate_bootstrapping_ciphertext_array(32, ciphertextcarry1);
				
				
			}
			else if (int_bit == 256){

			printf("Doing the homomorphic computation...\n");

			//do some operations on the ciphertexts: here, we will compute the
			//difference of the two
			LweSample* temp = new_gate_bootstrapping_ciphertext_array(32, params);
			LweSample* inverse1 = new_gate_bootstrapping_ciphertext_array(32, params);
			LweSample* inverse2 = new_gate_bootstrapping_ciphertext_array(32, params);
			LweSample* inverse3 = new_gate_bootstrapping_ciphertext_array(32, params);
			LweSample* inverse4 = new_gate_bootstrapping_ciphertext_array(32, params);
			LweSample* inverse5 = new_gate_bootstrapping_ciphertext_array(32, params);
			LweSample* inverse6 = new_gate_bootstrapping_ciphertext_array(32, params);
			LweSample* inverse7 = new_gate_bootstrapping_ciphertext_array(32, params);
			LweSample* inverse8 = new_gate_bootstrapping_ciphertext_array(32, params);
					
			LweSample* tempcarry1 = new_gate_bootstrapping_ciphertext_array(32, params);
			LweSample* tempcarry2 = new_gate_bootstrapping_ciphertext_array(32, params);
			LweSample* tempcarry3 = new_gate_bootstrapping_ciphertext_array(32, params);
			LweSample* tempcarry4 = new_gate_bootstrapping_ciphertext_array(32, params);
			LweSample* tempcarry5 = new_gate_bootstrapping_ciphertext_array(32, params);
			LweSample* tempcarry6 = new_gate_bootstrapping_ciphertext_array(32, params);
			LweSample* tempcarry7 = new_gate_bootstrapping_ciphertext_array(32, params);
			LweSample* tempcarry8 = new_gate_bootstrapping_ciphertext_array(32, params);
					
			LweSample* twosresult1 = new_gate_bootstrapping_ciphertext_array(32, params);
			LweSample* twosresult2 = new_gate_bootstrapping_ciphertext_array(32, params);
			LweSample* twosresult3 = new_gate_bootstrapping_ciphertext_array(32, params);
			LweSample* twosresult4 = new_gate_bootstrapping_ciphertext_array(32, params);
			LweSample* twosresult5 = new_gate_bootstrapping_ciphertext_array(32, params);
			LweSample* twosresult6 = new_gate_bootstrapping_ciphertext_array(32, params);
			LweSample* twosresult7 = new_gate_bootstrapping_ciphertext_array(32, params);
			LweSample* twosresult8 = new_gate_bootstrapping_ciphertext_array(32, params);
					
			LweSample* twoscarry1 = new_gate_bootstrapping_ciphertext_array(32, params);
			LweSample* twoscarry2 = new_gate_bootstrapping_ciphertext_array(32, params);
			LweSample* twoscarry3 = new_gate_bootstrapping_ciphertext_array(32, params);
			LweSample* twoscarry4 = new_gate_bootstrapping_ciphertext_array(32, params);
			LweSample* twoscarry5 = new_gate_bootstrapping_ciphertext_array(32, params);
			LweSample* twoscarry6 = new_gate_bootstrapping_ciphertext_array(32, params);
			LweSample* twoscarry7 = new_gate_bootstrapping_ciphertext_array(32, params);
			LweSample* twoscarry8 = new_gate_bootstrapping_ciphertext_array(32, params);
		
			struct timeval start, end;
			double get_time;
			gettimeofday(&start, NULL);
					
			//Subtraction Process
					
			//Step 1. Inverse the 32 bit chunks in the first input value
			NOT(inverse1, ciphertext1, bk, 32);
			NOT(inverse2, ciphertext2, bk, 32);
			NOT(inverse3, ciphertext3, bk, 32);
			NOT(inverse4, ciphertext4, bk, 32);
			NOT(inverse5, ciphertext5, bk, 32);
			NOT(inverse6, ciphertext6, bk, 32);
			NOT(inverse7, ciphertext7, bk, 32);
			NOT(inverse8, ciphertext8, bk, 32);
					
			//iniailize tempcarry and temp carry to 0
			zero(temp, bk, 32);
			zero(tempcarry1, bk, 32); 
			zero(tempcarry2, bk, 32); 
			zero(tempcarry3, bk, 32); 
			zero(tempcarry4, bk, 32); 
			zero(tempcarry5, bk, 32); 
			zero(tempcarry6, bk, 32); 
			zero(tempcarry7, bk, 32); 
			zero(tempcarry8, bk, 32); 
					
			//Assign temp to have a value of 1 for 2nd complement
			bootsCONSTANT(temp, 1, bk); 
		
			//Add 1 to inverted
			add(twosresult1, twoscarry1, inverse1, temp, tempcarry1, 32, bk);
					
			//Add the rest of the inverted
			add(twosresult2, twoscarry2, inverse2, tempcarry2, twoscarry1, 32, bk);
			add(twosresult3, twoscarry3, inverse3, tempcarry3, twoscarry2, 32, bk);
			add(twosresult4, twoscarry4, inverse4, tempcarry4, twoscarry3, 32, bk);
			add(twosresult5, twoscarry5, inverse5, tempcarry5, twoscarry4, 32, bk);
			add(twosresult6, twoscarry6, inverse6, tempcarry6, twoscarry5, 32, bk);
			add(twosresult7, twoscarry7, inverse7, tempcarry7, twoscarry6, 32, bk);
			add(twosresult8, twoscarry8, inverse8, tempcarry8, twoscarry7, 32, bk);
					
			LweSample* result1 = new_gate_bootstrapping_ciphertext_array(32, params);
			LweSample* result2 = new_gate_bootstrapping_ciphertext_array(32, params);
			LweSample* result3 = new_gate_bootstrapping_ciphertext_array(32, params);
			LweSample* result4 = new_gate_bootstrapping_ciphertext_array(32, params);
			LweSample* result5 = new_gate_bootstrapping_ciphertext_array(32, params);
			LweSample* result6 = new_gate_bootstrapping_ciphertext_array(32, params);
			LweSample* result7 = new_gate_bootstrapping_ciphertext_array(32, params);
			LweSample* result8 = new_gate_bootstrapping_ciphertext_array(32, params);
					
			LweSample* carry1 = new_gate_bootstrapping_ciphertext_array(32, params);
			LweSample* carry2 = new_gate_bootstrapping_ciphertext_array(32, params);
			LweSample* carry3 = new_gate_bootstrapping_ciphertext_array(32, params);
			LweSample* carry4 = new_gate_bootstrapping_ciphertext_array(32, params);
			LweSample* carry5 = new_gate_bootstrapping_ciphertext_array(32, params);
			LweSample* carry6 = new_gate_bootstrapping_ciphertext_array(32, params);
			LweSample* carry7 = new_gate_bootstrapping_ciphertext_array(32, params);
			LweSample* carry8 = new_gate_bootstrapping_ciphertext_array(32, params);
					
			//Do the addition, this is basically adding the first inversed value to the second value, (-a) + b
			add(result1, carry1, ciphertext9, twosresult1, ciphertextcarry1, 32, bk);
			add(result2, carry2, ciphertext10, twosresult2, carry1, 32, bk);
			add(result3, carry3, ciphertext11, twosresult3, carry2, 32, bk);
			add(result4, carry4, ciphertext12, twosresult4, carry3, 32, bk);
			add(result5, carry5, ciphertext13, twosresult5, carry4, 32, bk);
			add(result6, carry6, ciphertext14, twosresult6, carry5, 32, bk);
			add(result7, carry7, ciphertext15, twosresult7, carry6, 32, bk);
			add(result8, carry8, ciphertext16, twosresult8, carry7, 32, bk);

			gettimeofday(&end, NULL);
			get_time = (end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec) * 1.0E-6;
			printf("Computation Time: %lf[sec]\n", get_time);

			printf("Writing the answer to file...\n");

			//export the 32 ciphertexts to a file (for the cloud)
			for (int i=0; i<32; i++) // 1
				export_gate_bootstrapping_ciphertext_toFile(answer_data, &result1[i], params);
			for (int i=0; i<32; i++) // 2
				export_gate_bootstrapping_ciphertext_toFile(answer_data, &result2[i], params);
			for (int i=0; i<32; i++) // 3
				export_gate_bootstrapping_ciphertext_toFile(answer_data, &result3[i], params);
			for (int i=0; i<32; i++) // 4
				export_gate_bootstrapping_ciphertext_toFile(answer_data, &result4[i], params);
			for (int i=0; i<32; i++) // 5
				export_gate_bootstrapping_ciphertext_toFile(answer_data, &result5[i], params);
			for (int i=0; i<32; i++) // 6
				export_gate_bootstrapping_ciphertext_toFile(answer_data, &result6[i], params);
			for (int i=0; i<32; i++) // 7
				export_gate_bootstrapping_ciphertext_toFile(answer_data, &result7[i], params);
			for (int i=0; i<32; i++) // 8
				export_gate_bootstrapping_ciphertext_toFile(answer_data, &result8[i], params);
			for (int i=0; i<32; i++) // carry
				export_gate_bootstrapping_ciphertext_toFile(answer_data, &ciphertextcarry1[i], params);
			fclose(answer_data);
			
			//clean up all pointers
			delete_gate_bootstrapping_ciphertext_array(32, temp);
			delete_gate_bootstrapping_ciphertext_array(32, inverse1);
			delete_gate_bootstrapping_ciphertext_array(32, inverse2);
			delete_gate_bootstrapping_ciphertext_array(32, inverse3);
			delete_gate_bootstrapping_ciphertext_array(32, inverse4);
			delete_gate_bootstrapping_ciphertext_array(32, inverse5);
			delete_gate_bootstrapping_ciphertext_array(32, inverse6);
			delete_gate_bootstrapping_ciphertext_array(32, inverse7);
			delete_gate_bootstrapping_ciphertext_array(32, inverse8);
			
			delete_gate_bootstrapping_ciphertext_array(32, tempcarry1);
			delete_gate_bootstrapping_ciphertext_array(32, tempcarry2);
			delete_gate_bootstrapping_ciphertext_array(32, tempcarry3);
			delete_gate_bootstrapping_ciphertext_array(32, tempcarry4);
			delete_gate_bootstrapping_ciphertext_array(32, tempcarry5);
			delete_gate_bootstrapping_ciphertext_array(32, tempcarry6);
			delete_gate_bootstrapping_ciphertext_array(32, tempcarry7);
			delete_gate_bootstrapping_ciphertext_array(32, tempcarry8);
			
			delete_gate_bootstrapping_ciphertext_array(32, twosresult1);
			delete_gate_bootstrapping_ciphertext_array(32, twosresult2);
			delete_gate_bootstrapping_ciphertext_array(32, twosresult3);
			delete_gate_bootstrapping_ciphertext_array(32, twosresult4);
			delete_gate_bootstrapping_ciphertext_array(32, twosresult5);
			delete_gate_bootstrapping_ciphertext_array(32, twosresult6);
			delete_gate_bootstrapping_ciphertext_array(32, twosresult7);
			delete_gate_bootstrapping_ciphertext_array(32, twosresult8);
			
			delete_gate_bootstrapping_ciphertext_array(32, twoscarry1);
			delete_gate_bootstrapping_ciphertext_array(32, twoscarry2);
			delete_gate_bootstrapping_ciphertext_array(32, twoscarry3);
			delete_gate_bootstrapping_ciphertext_array(32, twoscarry4);
			delete_gate_bootstrapping_ciphertext_array(32, twoscarry5);
			delete_gate_bootstrapping_ciphertext_array(32, twoscarry6);
			delete_gate_bootstrapping_ciphertext_array(32, twoscarry7);
			delete_gate_bootstrapping_ciphertext_array(32, twoscarry8);
			
			delete_gate_bootstrapping_ciphertext_array(32, carry1);
			delete_gate_bootstrapping_ciphertext_array(32, carry2);
			delete_gate_bootstrapping_ciphertext_array(32, result1);
			delete_gate_bootstrapping_ciphertext_array(32, result2);
			delete_gate_bootstrapping_ciphertext_array(32, result3);
			delete_gate_bootstrapping_ciphertext_array(32, result4);
			delete_gate_bootstrapping_ciphertext_array(32, result5);
			delete_gate_bootstrapping_ciphertext_array(32, result6);
			delete_gate_bootstrapping_ciphertext_array(32, result7);
			delete_gate_bootstrapping_ciphertext_array(32, result8);
			
			delete_gate_bootstrapping_ciphertext_array(32, ciphertextbit1);
			delete_gate_bootstrapping_ciphertext_array(32, ciphertextnegative1);
			delete_gate_bootstrapping_ciphertext_array(32, ciphertextbit2);
			delete_gate_bootstrapping_ciphertext_array(32, ciphertextnegative2);
			delete_gate_bootstrapping_ciphertext_array(32, ciphertext1);
			delete_gate_bootstrapping_ciphertext_array(32, ciphertext2);
			delete_gate_bootstrapping_ciphertext_array(32, ciphertext3);
			delete_gate_bootstrapping_ciphertext_array(32, ciphertext4);
			delete_gate_bootstrapping_ciphertext_array(32, ciphertext5);
			delete_gate_bootstrapping_ciphertext_array(32, ciphertext6);
			delete_gate_bootstrapping_ciphertext_array(32, ciphertext7);
			delete_gate_bootstrapping_ciphertext_array(32, ciphertext8);
			delete_gate_bootstrapping_ciphertext_array(32, ciphertext9);
			delete_gate_bootstrapping_ciphertext_array(32, ciphertext10);
			delete_gate_bootstrapping_ciphertext_array(32, ciphertext11);
			delete_gate_bootstrapping_ciphertext_array(32, ciphertext12);
			delete_gate_bootstrapping_ciphertext_array(32, ciphertext13);
			delete_gate_bootstrapping_ciphertext_array(32, ciphertext14);
			delete_gate_bootstrapping_ciphertext_array(32, ciphertext15);
			delete_gate_bootstrapping_ciphertext_array(32, ciphertext16);
			delete_gate_bootstrapping_ciphertext_array(32, ciphertextcarry1);
				
			}
		}
    }
	
	// If Multiplication
	else if (int_op == 4){
    	std::cout << int_bit << " bit Multiplication computation" << "\n";

    	if (int_bit == 128){
    		printf("Doing the homomorphic computation...\n");
    		
			// do some operations on the ciphertexts: here, we will compute the
			// product of the two
			LweSample* result1 = new_gate_bootstrapping_ciphertext_array(32, params);
			LweSample* result2 = new_gate_bootstrapping_ciphertext_array(32, params);
			LweSample* result3 = new_gate_bootstrapping_ciphertext_array(32, params);
			LweSample* result4 = new_gate_bootstrapping_ciphertext_array(32, params);
			LweSample* result5 = new_gate_bootstrapping_ciphertext_array(32, params);
			LweSample* result6 = new_gate_bootstrapping_ciphertext_array(32, params);
			LweSample* result7 = new_gate_bootstrapping_ciphertext_array(32, params);
			LweSample* result8 = new_gate_bootstrapping_ciphertext_array(32, params);
			LweSample* result9 = new_gate_bootstrapping_ciphertext_array(32, params);
			LweSample* result10 = new_gate_bootstrapping_ciphertext_array(32, params);
			LweSample* result11 = new_gate_bootstrapping_ciphertext_array(32, params);
			LweSample* result12 = new_gate_bootstrapping_ciphertext_array(32, params);
			LweSample* result13 = new_gate_bootstrapping_ciphertext_array(32, params);
			LweSample* result14 = new_gate_bootstrapping_ciphertext_array(32, params);
			LweSample* result15 = new_gate_bootstrapping_ciphertext_array(32, params);
			LweSample* result16 = new_gate_bootstrapping_ciphertext_array(32, params);
			LweSample* result17 = new_gate_bootstrapping_ciphertext_array(32, params);
			LweSample* result18 = new_gate_bootstrapping_ciphertext_array(32, params);
			LweSample* result19 = new_gate_bootstrapping_ciphertext_array(32, params);
			LweSample* result20 = new_gate_bootstrapping_ciphertext_array(32, params);
	
			LweSample* sum1 = new_gate_bootstrapping_ciphertext_array(32, params);
			LweSample* sum2 = new_gate_bootstrapping_ciphertext_array(32, params);
			LweSample* sum3 = new_gate_bootstrapping_ciphertext_array(32, params);
			LweSample* sum4 = new_gate_bootstrapping_ciphertext_array(32, params);
			LweSample* sum5 = new_gate_bootstrapping_ciphertext_array(32, params);
			LweSample* sum6 = new_gate_bootstrapping_ciphertext_array(32, params);
			LweSample* sum7 = new_gate_bootstrapping_ciphertext_array(32, params);
			LweSample* sum8 = new_gate_bootstrapping_ciphertext_array(32, params);
			LweSample* sum9 = new_gate_bootstrapping_ciphertext_array(32, params);
			LweSample* sum10 = new_gate_bootstrapping_ciphertext_array(32, params);
			LweSample* sum11 = new_gate_bootstrapping_ciphertext_array(32, params);
			LweSample* sum12 = new_gate_bootstrapping_ciphertext_array(32, params);
			LweSample* sum13 = new_gate_bootstrapping_ciphertext_array(32, params);
			LweSample* sum14 = new_gate_bootstrapping_ciphertext_array(32, params);
			LweSample* sum15 = new_gate_bootstrapping_ciphertext_array(32, params);
		
			LweSample* carryover1 = new_gate_bootstrapping_ciphertext_array(32, params);
			LweSample* carryover2 = new_gate_bootstrapping_ciphertext_array(32, params);
			LweSample* carryover3 = new_gate_bootstrapping_ciphertext_array(32, params);
			LweSample* carryover4 = new_gate_bootstrapping_ciphertext_array(32, params);
			LweSample* carryover5 = new_gate_bootstrapping_ciphertext_array(32, params);
			LweSample* carryover6 = new_gate_bootstrapping_ciphertext_array(32, params);
			LweSample* carryover7 = new_gate_bootstrapping_ciphertext_array(32, params);
			LweSample* carryover8 = new_gate_bootstrapping_ciphertext_array(32, params);
			LweSample* carryover9 = new_gate_bootstrapping_ciphertext_array(32, params);
			LweSample* carryover10 = new_gate_bootstrapping_ciphertext_array(32, params);
			LweSample* carryover11 = new_gate_bootstrapping_ciphertext_array(32, params);
			LweSample* carryover12 = new_gate_bootstrapping_ciphertext_array(32, params);
			LweSample* carryover13 = new_gate_bootstrapping_ciphertext_array(32, params);
			LweSample* carryover14 = new_gate_bootstrapping_ciphertext_array(32, params);
			LweSample* carryover15 = new_gate_bootstrapping_ciphertext_array(32, params);

			struct timeval start, end;
			double get_time;
			gettimeofday(&start, NULL);
		
			//result1 
			mul128(result1, result2, result3, result4, result5, ciphertext1, ciphertext2,ciphertext3,ciphertext4,ciphertext9,ciphertextcarry1, 32, bk);
	
			//result2
			mul128(result6, result7, result8, result9, result10, ciphertext1, ciphertext2, ciphertext3, ciphertext4, ciphertext10,ciphertextcarry1, 32, bk);
		
			//result3
			mul128(result11, result12, result13, result14, result15, ciphertext1, ciphertext2,ciphertext3,ciphertext4,ciphertext11,ciphertextcarry1, 32, bk);
		
			//result4
			mul128(result16,result17, result18,result19,result20, ciphertext1, ciphertext2,ciphertext3,ciphertext4,ciphertext12,ciphertextcarry1, 32, bk);
		
			add(sum1, carryover1, result10, result4, ciphertextcarry1, 32, bk);
			add(sum2, carryover2, result9, result3,carryover1,32, bk);
			add(sum3, carryover3, result8, result2,carryover2,32, bk);
			add(sum4, carryover4, result7, result1,carryover3,32, bk);
			add(sum5, carryover5, result6, ciphertextcarry1,carryover4,32, bk);
		
			add(sum6, carryover6, sum2, result15,carryover5,32, bk);
			add(sum7, carryover7, sum3, result14,carryover6,32, bk);
			add(sum8, carryover8, sum4, result13,carryover7,32, bk);
			add(sum9, carryover9, sum5, result12,carryover8,32, bk);
			add(sum10, carryover10, result11, ciphertextcarry1,carryover9,32, bk);
		
			add(sum11, carryover11, sum7,  result20,carryover10,32, bk);
			add(sum12, carryover12, sum8,  result19,carryover11,32, bk);
			add(sum13, carryover13, sum9,  result18,carryover12,32, bk);
			add(sum14, carryover14, sum10, result17,carryover13,32, bk);
			add(sum15, carryover15, result16 , ciphertextcarry1,carryover14,32, bk);

			gettimeofday(&end, NULL);
			get_time = (end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec) * 1.0E-6;
    		printf("Computation Time: %lf[sec]\n", get_time);

       	 	// write computation time to file
       		FILE *t_file;
       		t_file = fopen(T_FILE, "a");
       		fprintf(t_file, "%lf\n", get_time);
       		fclose(t_file);

			printf("writing the answer to file...\n");

			//export the 32 ciphertexts to a file (for the cloud)
			for (int i=0; i<32; i++) // result1
				export_gate_bootstrapping_ciphertext_toFile(answer_data, &result5[i], params);
			for (int i=0; i<32; i++) // result2
				export_gate_bootstrapping_ciphertext_toFile(answer_data, &sum1[i], params);
			for (int i=0; i<32; i++) // result3
				export_gate_bootstrapping_ciphertext_toFile(answer_data, &sum6[i], params);
			for (int i=0; i<32; i++) // result4
				export_gate_bootstrapping_ciphertext_toFile(answer_data, &sum11[i], params);
			for (int i=0; i<32; i++) // result5
				export_gate_bootstrapping_ciphertext_toFile(answer_data, &sum12[i], params);
			for (int i=0; i<32; i++) // result6
				export_gate_bootstrapping_ciphertext_toFile(answer_data, &sum13[i], params);
			for (int i=0; i<32; i++) // result7
				export_gate_bootstrapping_ciphertext_toFile(answer_data, &sum14[i], params);
			for (int i=0; i<32; i++) // result8
				export_gate_bootstrapping_ciphertext_toFile(answer_data, &sum15[i], params);
			for (int i=0; i<32; i++) // carry
				export_gate_bootstrapping_ciphertext_toFile(answer_data, &ciphertextcarry1[i], params);
			fclose(answer_data);

			// clean up all pointers
			delete_gate_bootstrapping_ciphertext_array(32, result1);
			delete_gate_bootstrapping_ciphertext_array(32, result2);
			delete_gate_bootstrapping_ciphertext_array(32, result3);
			delete_gate_bootstrapping_ciphertext_array(32, result4);
			delete_gate_bootstrapping_ciphertext_array(32, result5);
			delete_gate_bootstrapping_ciphertext_array(32, result6);
			delete_gate_bootstrapping_ciphertext_array(32, result7);
			delete_gate_bootstrapping_ciphertext_array(32, result8);
			delete_gate_bootstrapping_ciphertext_array(32, result9);
			delete_gate_bootstrapping_ciphertext_array(32, result10);
			delete_gate_bootstrapping_ciphertext_array(32, result11);
			delete_gate_bootstrapping_ciphertext_array(32, result12);
			delete_gate_bootstrapping_ciphertext_array(32, result13);
			delete_gate_bootstrapping_ciphertext_array(32, result14);
			delete_gate_bootstrapping_ciphertext_array(32, result15);
			delete_gate_bootstrapping_ciphertext_array(32, result16);
			delete_gate_bootstrapping_ciphertext_array(32, result17);
			delete_gate_bootstrapping_ciphertext_array(32, result18);
			delete_gate_bootstrapping_ciphertext_array(32, result19);
			delete_gate_bootstrapping_ciphertext_array(32, result20);
		
			delete_gate_bootstrapping_ciphertext_array(32, sum1);
			delete_gate_bootstrapping_ciphertext_array(32, sum2);
			delete_gate_bootstrapping_ciphertext_array(32, sum3);
			delete_gate_bootstrapping_ciphertext_array(32, sum4);
			delete_gate_bootstrapping_ciphertext_array(32, sum5);
			delete_gate_bootstrapping_ciphertext_array(32, sum6);
			delete_gate_bootstrapping_ciphertext_array(32, sum7);
			delete_gate_bootstrapping_ciphertext_array(32, sum8);
			delete_gate_bootstrapping_ciphertext_array(32, sum9);
			delete_gate_bootstrapping_ciphertext_array(32, sum10);
			delete_gate_bootstrapping_ciphertext_array(32, sum11);
			delete_gate_bootstrapping_ciphertext_array(32, sum12);
			delete_gate_bootstrapping_ciphertext_array(32, sum13);
			delete_gate_bootstrapping_ciphertext_array(32, sum14);
			delete_gate_bootstrapping_ciphertext_array(32, sum15);
		
			delete_gate_bootstrapping_ciphertext_array(32, carryover1);
			delete_gate_bootstrapping_ciphertext_array(32, carryover2);
			delete_gate_bootstrapping_ciphertext_array(32, carryover3);
			delete_gate_bootstrapping_ciphertext_array(32, carryover4);
			delete_gate_bootstrapping_ciphertext_array(32, carryover5);
			delete_gate_bootstrapping_ciphertext_array(32, carryover6);
			delete_gate_bootstrapping_ciphertext_array(32, carryover7);
			delete_gate_bootstrapping_ciphertext_array(32, carryover8);
			delete_gate_bootstrapping_ciphertext_array(32, carryover9);
			delete_gate_bootstrapping_ciphertext_array(32, carryover10);
			delete_gate_bootstrapping_ciphertext_array(32, carryover11);
			delete_gate_bootstrapping_ciphertext_array(32, carryover12);
			delete_gate_bootstrapping_ciphertext_array(32, carryover13);
			delete_gate_bootstrapping_ciphertext_array(32, carryover14);
			delete_gate_bootstrapping_ciphertext_array(32, carryover15);
	
			delete_gate_bootstrapping_ciphertext_array(32, ciphertextbit1);
			delete_gate_bootstrapping_ciphertext_array(32, ciphertextnegative1);
			delete_gate_bootstrapping_ciphertext_array(32, ciphertextbit2);
			delete_gate_bootstrapping_ciphertext_array(32, ciphertextnegative2);
			delete_gate_bootstrapping_ciphertext_array(32, ciphertext1);
			delete_gate_bootstrapping_ciphertext_array(32, ciphertext2);
			delete_gate_bootstrapping_ciphertext_array(32, ciphertext3);
			delete_gate_bootstrapping_ciphertext_array(32, ciphertext4);
			delete_gate_bootstrapping_ciphertext_array(32, ciphertext9);
			delete_gate_bootstrapping_ciphertext_array(32, ciphertext10);
			delete_gate_bootstrapping_ciphertext_array(32, ciphertext11);
			delete_gate_bootstrapping_ciphertext_array(32, ciphertext12);
			delete_gate_bootstrapping_ciphertext_array(32, ciphertextcarry1);
	
			delete_gate_bootstrapping_cloud_keyset(bk);
    		
    	}
		else if (int_bit == 64){
    		printf("Doing the homomorphic computation...\n");
    		
			// do some operations on the ciphertexts: here, we will compute the
			// product of the two
			LweSample* result1 = new_gate_bootstrapping_ciphertext_array(32, params);
			LweSample* result2 = new_gate_bootstrapping_ciphertext_array(32, params);
			LweSample* result3 = new_gate_bootstrapping_ciphertext_array(32, params);
			LweSample* result4 = new_gate_bootstrapping_ciphertext_array(32, params);
			LweSample* result5 = new_gate_bootstrapping_ciphertext_array(32, params);
			LweSample* result6 = new_gate_bootstrapping_ciphertext_array(32, params);
	
			LweSample* finalresult = new_gate_bootstrapping_ciphertext_array(32, params);
			LweSample* finalresult2 = new_gate_bootstrapping_ciphertext_array(32, params);
			LweSample* finalresult3 = new_gate_bootstrapping_ciphertext_array(32, params);

			struct timeval start, end;
			double get_time;
			gettimeofday(&start, NULL);

			//result1
			mul64(result1,result2, result3, ciphertext1, ciphertext2,ciphertext9,ciphertextcarry1, 32, bk);
	
			//result2
			mul64(result4,result5, result6, ciphertext1, ciphertext2,ciphertext10,ciphertextcarry1, 32, bk);
	
			split(finalresult,finalresult2, finalresult3, result1, result2,result4,result5,result6,ciphertextcarry1,32,bk);

			gettimeofday(&end, NULL);
			get_time = (end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec) * 1.0E-6;
    		printf("Computation Time: %lf[sec]\n", get_time);

       		// write computation time to file
       	 	FILE *t_file;
       	 	t_file = fopen(T_FILE, "a");
       	 	fprintf(t_file, "%lf\n", get_time);
       	 	fclose(t_file);
			printf("writing the answer to file...\n");

			//export the 32 ciphertexts to a file (for the cloud)
	
			for (int i=0; i<32; i++) // result1
				export_gate_bootstrapping_ciphertext_toFile(answer_data, &result3[i], params);
			for (int i=0; i<32; i++) // result2
				export_gate_bootstrapping_ciphertext_toFile(answer_data, &finalresult3[i], params);
			for (int i=0; i<32; i++) // result3
				export_gate_bootstrapping_ciphertext_toFile(answer_data, &finalresult2[i], params);
			for (int i=0; i<32; i++) // result4
				export_gate_bootstrapping_ciphertext_toFile(answer_data, &finalresult[i], params);
			for (int i=0; i<32; i++) // 5
				export_gate_bootstrapping_ciphertext_toFile(answer_data, &ciphertextcarry1[i], params);	
			for (int i=0; i<32; i++) // 6
				export_gate_bootstrapping_ciphertext_toFile(answer_data, &ciphertextcarry1[i], params);	
			for (int i=0; i<32; i++) // 7
				export_gate_bootstrapping_ciphertext_toFile(answer_data, &ciphertextcarry1[i], params);	
			for (int i=0; i<32; i++) // 8
				export_gate_bootstrapping_ciphertext_toFile(answer_data, &ciphertextcarry1[i], params);	
			for (int i=0; i<32; i++) // carry
				export_gate_bootstrapping_ciphertext_toFile(answer_data, &ciphertextcarry1[i], params);
			fclose(answer_data);

			// clean up all pointers
			delete_gate_bootstrapping_ciphertext_array(32, result1);
			delete_gate_bootstrapping_ciphertext_array(32, result2);
			delete_gate_bootstrapping_ciphertext_array(32, result3);
			delete_gate_bootstrapping_ciphertext_array(32, result4);
			delete_gate_bootstrapping_ciphertext_array(32, result5);
			delete_gate_bootstrapping_ciphertext_array(32, result6);
	
			delete_gate_bootstrapping_ciphertext_array(32, ciphertextbit1);
			delete_gate_bootstrapping_ciphertext_array(32, ciphertextnegative1);
			delete_gate_bootstrapping_ciphertext_array(32, ciphertextbit2);
			delete_gate_bootstrapping_ciphertext_array(32, ciphertextnegative2);
			delete_gate_bootstrapping_ciphertext_array(32, ciphertext1);
			delete_gate_bootstrapping_ciphertext_array(32, ciphertext2);
			delete_gate_bootstrapping_ciphertext_array(32, ciphertext9);
			delete_gate_bootstrapping_ciphertext_array(32, ciphertext10);
			delete_gate_bootstrapping_ciphertext_array(32, ciphertextcarry1);
	
			delete_gate_bootstrapping_ciphertext_array(32, finalresult);
			delete_gate_bootstrapping_ciphertext_array(32, finalresult2);
			delete_gate_bootstrapping_ciphertext_array(32, finalresult3);
	
			delete_gate_bootstrapping_cloud_keyset(bk);
    	
    	}
		else if (int_bit == 32){
    		printf("Doing the homomorphic computation...\n");
    		
			// do some operations on the ciphertexts: here, we will compute the
			// product of the two
			LweSample* result1 = new_gate_bootstrapping_ciphertext_array(32, params);
			LweSample* result2 = new_gate_bootstrapping_ciphertext_array(32, params);
		
			struct timeval start, end;
			double get_time;
			gettimeofday(&start, NULL);
		
			//result1
			mul32(result1,result2,ciphertext1, ciphertext9,ciphertextcarry1, 32, bk);
		
			gettimeofday(&end, NULL);
			get_time = (end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec) * 1.0E-6;
    		printf("Computation Time: %lf[sec]\n", get_time);

       	 	// write computation time to file
       	 	FILE *t_file;
       	 	t_file = fopen(T_FILE, "a");
       	 	fprintf(t_file, "%lf\n", get_time);
       	 	fclose(t_file);

			printf("writing the answer to file...\n");

			//export the 32 ciphertexts to a file (for the cloud)
			for (int i=0; i<32; i++) // result1
				export_gate_bootstrapping_ciphertext_toFile(answer_data, &result2[i], params);
			for (int i=0; i<32; i++) // result2
				export_gate_bootstrapping_ciphertext_toFile(answer_data, &result1[i], params);
			for (int i=0; i<32; i++) // 3
				export_gate_bootstrapping_ciphertext_toFile(answer_data, &ciphertextcarry1[i], params);	
			for (int i=0; i<32; i++) // 4 
				export_gate_bootstrapping_ciphertext_toFile(answer_data, &ciphertextcarry1[i], params);	
			for (int i=0; i<32; i++) // 5
				export_gate_bootstrapping_ciphertext_toFile(answer_data, &ciphertextcarry1[i], params);	
			for (int i=0; i<32; i++) // 6
				export_gate_bootstrapping_ciphertext_toFile(answer_data, &ciphertextcarry1[i], params);	
			for (int i=0; i<32; i++) // 7
				export_gate_bootstrapping_ciphertext_toFile(answer_data, &ciphertextcarry1[i], params);	
			for (int i=0; i<32; i++) // 8
				export_gate_bootstrapping_ciphertext_toFile(answer_data, &ciphertextcarry1[i], params);	
			for (int i=0; i<32; i++) // carry
				export_gate_bootstrapping_ciphertext_toFile(answer_data, &ciphertextcarry1[i], params);
			fclose(answer_data);
	
			// clean up all pointers
			delete_gate_bootstrapping_ciphertext_array(32, result1);
			delete_gate_bootstrapping_ciphertext_array(32, result2);
			delete_gate_bootstrapping_ciphertext_array(32, ciphertextbit1);
			delete_gate_bootstrapping_ciphertext_array(32, ciphertextnegative1);
			delete_gate_bootstrapping_ciphertext_array(32, ciphertextbit2);
			delete_gate_bootstrapping_ciphertext_array(32, ciphertextnegative2);
	
			delete_gate_bootstrapping_ciphertext_array(32, ciphertext1);
			delete_gate_bootstrapping_ciphertext_array(32, ciphertext9);
			delete_gate_bootstrapping_ciphertext_array(32, ciphertextcarry1);

			delete_gate_bootstrapping_cloud_keyset(bk);
    	
    	}
    }
}
