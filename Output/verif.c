#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>
#include <stdio.h>
#include <stdlib.h>
#include <bitset>
#include <iostream>
#include <iomanip>
#include <boost/multiprecision/cpp_int.hpp>
#include <boost/dynamic_bitset.hpp>
#include <boost/lexical_cast.hpp>
#include <string>
#include <sys/time.h>
#include <time.h>
using namespace std;
using namespace boost::multiprecision;
using boost::multiprecision::int256_t;


int main() {

    //reads the cloud key from file
    FILE* secret_key = fopen("secret.key","rb");
    TFheGateBootstrappingSecretKeySet* key = new_tfheGateBootstrappingSecretKeySet_fromFile(secret_key);
    fclose(secret_key);

	FILE* nbit_key = fopen("nbit.key","rb");
    TFheGateBootstrappingSecretKeySet* nbitkey = new_tfheGateBootstrappingSecretKeySet_fromFile(nbit_key);
    fclose(nbit_key);

    //if necessary, the params are inside the key
    const TFheGateBootstrappingParameterSet* params = key->params;

	// if necessary, the params are inside the key
	const TFheGateBootstrappingParameterSet* nbitparams = nbitkey->params;

    struct timeval start, end;
    double get_time;
    gettimeofday(&start, NULL);

    //read the 16 ciphertexts of the result
    LweSample* negative = new_gate_bootstrapping_ciphertext_array(32, nbitparams);
    LweSample* bit = new_gate_bootstrapping_ciphertext_array(32, nbitparams);
    
    FILE* answer_data = fopen("answer.data","rb");
    for (int i=0; i<32; i++) 
        import_gate_bootstrapping_ciphertext_fromFile(answer_data, &negative[i], nbitparams);
    

    for (int i=0; i<32; i++) 
        import_gate_bootstrapping_ciphertext_fromFile(answer_data, &bit[i], nbitparams);

    
    //decrypt and rebuild the answer
    
	// negativity code
    int32_t int_negative = 0;
    for (int i=0; i<32; i++) {
        int ai = bootsSymDecrypt(&negative[i], nbitkey)>0;
        int_negative |= (ai<<i);
    }
	std::cout << "Negative: " << int_negative << "\n";
    
    // TODO: Obtain opcode from file
	int32_t int_op;
    FILE* fptr;
	fptr = fopen("operator.txt","r");
	fscanf(fptr,"%d", &int_op);
	std::cout << "Opcode: " << int_op << "\n" << "\n";
    
	// Bit count
    int32_t int_bit = 0;
    for (int i=0; i<32; i++) {
        int ai = bootsSymDecrypt(&bit[i], nbitkey)>0;
        int_bit |= (ai<<i);
    }
    
	// Addition
    if (int_op == 1)
	{
    	std::cout << "Result for " << int_bit << " bit Addition computation" << "\n" << "\n";
    	
    	if (int_bit == 32){
    	    LweSample* result = new_gate_bootstrapping_ciphertext_array(32, params);
	
	    	for (int i=0; i<32; i++)
			import_gate_bootstrapping_ciphertext_fromFile(answer_data, &result[i], params);
	    	fclose(answer_data);
	  
	   		// decrypt and rebuild the answer
	    	int32_t int_answer1 = 0;
	    	for (int i=0; i<32; i++) {
				int ai = bootsSymDecrypt(&result[i], key)>0;
				int_answer1 |= (ai<<i);
	    	}
	   
			std::string binary1 = std::bitset<32>(int_answer1).to_string();
		
			std::string binary_combined = binary1;

			if (int_negative != 4){
			std::cout << "The result in binary form is:" << "\n";
			std::cout << binary_combined << "\n";
			}

	    	//Length is the number of bits
			int length = binary_combined.length();
			int lastchar = length - 1;
			char char_array[length + 1];
			strcpy(char_array, binary_combined.c_str());

			int256_t total = 0;

			//Positive or negative checking
			char charvalue = char_array[0];
			std::string stringvalue(1, charvalue);
			int intvalue = std::stoi(stringvalue);

			//if the result is either double positive or negative
			if (int_negative == 0 || int_negative == 4)
			{
				for (int i = 0; i < length; ++i)
				{
					char charvalue = char_array[i];
					std::string stringvalue(1, charvalue);
					int intvalue = std::stoi(stringvalue);
					int256_t calc1 = total * 2;
					total = calc1 + intvalue;
				}
			//if either one of the values are negative, check for negative
			}
			else if (int_negative != 4)
			{
				if (length == 32 && intvalue == 1)
				{
					int256_t lastcharvalue = 2;
					for (int i = 0; i < lastchar - 1; ++i)
					{
						lastcharvalue = lastcharvalue * 2;
					}

					for (int i = 1; i < length; ++i)
					{
						char charvalue = char_array[i];
						std::string stringvalue(1, charvalue);
						int intvalue = std::stoi(stringvalue);
						int256_t calc1 = total * 2;
						total = calc1 + intvalue;
						
					}
					total = total - lastcharvalue;
					}
				else
				{
					for (int i = 0; i < length; ++i)
						{
							char charvalue = char_array[i];
							std::string stringvalue(1, charvalue);
							int intvalue = std::stoi(stringvalue);
							int256_t calc1 = total * 2;
							total = calc1 + intvalue;
						}
					
					}
					
			}
			
	   		//if its a double negative then inverse it		
	   		if (int_negative == 4){
	    		int256_t invertedtotal = total * -1;
	    		std::cout << "The result in decimal form is:" << "\n";
	    		std::cout << invertedtotal;
	    	}
			else
			{
	    		std::cout << "\n" << "\n";
	    		std::cout << "The result in decimal form is:" << "\n";
	    		std::cout << total;
	    	}

	    	printf("\n");
	    	printf("\n");
	    	gettimeofday(&end, NULL);
    	    get_time = (end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec) * 1.0E-6;
    	    printf("Computation Time: %lf[sec]\n", get_time);
    	    printf("\n");

	    	printf("I hope you remembered what calculation you performed!\n");

	    	// clean up all pointers
	    	delete_gate_bootstrapping_ciphertext_array(32, result);
	   		delete_gate_bootstrapping_secret_keyset(key);
    	
    	}
		
		else if (int_bit == 64)
		{
    	    LweSample* result = new_gate_bootstrapping_ciphertext_array(32, params);
	    	LweSample* result2 = new_gate_bootstrapping_ciphertext_array(32, params);
	    
	    	// export the 64 ciphertexts to a file (for the cloud)
	  
	    	for (int i=0; i<32; i++)
			import_gate_bootstrapping_ciphertext_fromFile(answer_data, &result[i], params);
	    
			for (int i=0; i<32; i++)
			import_gate_bootstrapping_ciphertext_fromFile(answer_data, &result2[i], params);
	
	    	fclose(answer_data);
	    
	    	// decrypt and rebuild the answer
	    	int32_t int_answer1 = 0;
	    	for (int i=0; i<32; i++)
			{
				int ai = bootsSymDecrypt(&result[i], key)>0;
				int_answer1 |= (ai<<i);
	    	}
		
	    	int32_t int_answer2 = 0;
	    	for (int i=0; i<32; i++)
			{
				int ai = bootsSymDecrypt(&result2[i], key)>0;
				int_answer2 |= (ai<<i);
	    	}
	    
			std::string binary1 = std::bitset<32>(int_answer1).to_string();
			std::string binary2 = std::bitset<32>(int_answer2).to_string();
			std::string binary_combined = binary2 + binary1;

			if (int_negative != 4)
			{
				std::cout << "The result in binary form is:" << "\n";
				std::cout << binary_combined << "\n";
			}
		
			//Length is the number of bits
			int length = binary_combined.length();
			int lastchar = length - 1;
			char char_array[length + 1];
			strcpy(char_array, binary_combined.c_str());

			int256_t total = 0;

			//Positive or negative checking
			char charvalue = char_array[0];
			std::string stringvalue(1, charvalue);
			int intvalue = std::stoi(stringvalue);
			//if the result is either double positive or negative
			if (int_negative == 0 || int_negative == 4)
			{
				for (int i = 0; i < length; ++i)
				{
					char charvalue = char_array[i];
					std::string stringvalue(1, charvalue);
					int intvalue = std::stoi(stringvalue);
					int256_t calc1 = total * 2;
					total = calc1 + intvalue;
					
				}
				//if either one of the values are negative, check for negative
			}
			else if (int_negative != 4)
			{
				if (length == 64 && intvalue == 1)
				{	
					int256_t lastcharvalue = 2;
					for (int i = 0; i < lastchar - 1; ++i)
					{
						lastcharvalue = lastcharvalue * 2;		
					}

					for (int i = 1; i < length; ++i)
					{
						char charvalue = char_array[i];
						std::string stringvalue(1, charvalue);
						int intvalue = std::stoi(stringvalue);
						int256_t calc1 = total * 2;
						total = calc1 + intvalue;	
					}

					total = total - lastcharvalue;
				}	
				else
				{
					for (int i = 0; i < length; ++i)
						{
							char charvalue = char_array[i];
							std::string stringvalue(1, charvalue);
							int intvalue = std::stoi(stringvalue);
							int256_t calc1 = total * 2;
							total = calc1 + intvalue;
						}
					
				}
					
			}	
	   		if (int_negative == 4)
			{
	    		int256_t invertedtotal = total * -1;
	    		std::cout << "The result in decimal form is:" << "\n";
	    		std::cout << invertedtotal;	
	    	}
			else
			{
	    		std::cout << "\n" << "\n";
	    		std::cout << "The result in decimal form is:" << "\n";
	    		std::cout << total;
	    	}
	    
	    	printf("\n");
	    	printf("\n");
	    	gettimeofday(&end, NULL);
    	    get_time = (end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec) * 1.0E-6;
    	    printf("Computation Time: %lf[sec]\n", get_time);
    	    printf("\n");
	
	    	printf("I hope you remembered what calculation you performed!\n");

	    	// clean up all pointers
	    	delete_gate_bootstrapping_ciphertext_array(32, result);
	    	delete_gate_bootstrapping_ciphertext_array(32, result2);
	    	delete_gate_bootstrapping_secret_keyset(key);
    	
    	}
		
		else if (int_bit == 128)
		{
    	    LweSample* result = new_gate_bootstrapping_ciphertext_array(32, params);
	    	LweSample* result2 = new_gate_bootstrapping_ciphertext_array(32, params);
	    	LweSample* result3 = new_gate_bootstrapping_ciphertext_array(32, params);
	    	LweSample* result4 = new_gate_bootstrapping_ciphertext_array(32, params);
	   
	   		// export the 64 ciphertexts to a file (for the cloud)
	   
	   		for (int i=0; i<32; i++)
			import_gate_bootstrapping_ciphertext_fromFile(answer_data, &result[i], params);
	    
			for (int i=0; i<32; i++)
			import_gate_bootstrapping_ciphertext_fromFile(answer_data, &result2[i], params);
	
			for (int i=0; i<32; i++)
			import_gate_bootstrapping_ciphertext_fromFile(answer_data, &result3[i], params);

			for (int i=0; i<32; i++)
			import_gate_bootstrapping_ciphertext_fromFile(answer_data, &result4[i], params);

	    	fclose(answer_data);
	    
	    	// decrypt and rebuild the answer
	    	int32_t int_answer1 = 0;
	    	for (int i=0; i<32; i++)
			{
				int ai = bootsSymDecrypt(&result[i], key)>0;
				int_answer1 |= (ai<<i);
	    	}
		
	    	int32_t int_answer2 = 0;
	    	for (int i=0; i<32; i++)
			{
				int ai = bootsSymDecrypt(&result2[i], key)>0;
				int_answer2 |= (ai<<i);
	    	}
	    
	    	int32_t int_answer3 = 0;
	    	for (int i=0; i<32; i++) 
			{
				int ai = bootsSymDecrypt(&result3[i], key)>0;
				int_answer3 |= (ai<<i);
	    	}
	    
	    	int32_t int_answer4 = 0;
	    	for (int i=0; i<32; i++)
			{
				int ai = bootsSymDecrypt(&result4[i], key)>0;
				int_answer4 |= (ai<<i);
	    	}
	    	
			std::string binary1 = std::bitset<32>(int_answer1).to_string();
			std::string binary2 = std::bitset<32>(int_answer2).to_string();
			std::string binary3 = std::bitset<32>(int_answer3).to_string();
			std::string binary4 = std::bitset<32>(int_answer4).to_string();
			std::string binary_combined = binary4 + binary3 + binary2 + binary1;
			
			if (int_negative != 4)
			{
				std::cout << "The result in binary form is:" << "\n";
				std::cout << binary_combined << "\n";
			}
	    	//Length is the number of bits
			int length = binary_combined.length();
			int lastchar = length - 1;
			char char_array[length + 1];
			strcpy(char_array, binary_combined.c_str());

			int256_t total = 0;

			//Positive or negative checking
			char charvalue = char_array[0];
			std::string stringvalue(1, charvalue);
			int intvalue = std::stoi(stringvalue);

			//if the result is either double positive or negative
			if (int_negative == 0 || int_negative == 4)
			{
				for (int i = 0; i < length; ++i)
				{
					char charvalue = char_array[i];
					std::string stringvalue(1, charvalue);
					int intvalue = std::stoi(stringvalue);
					int256_t calc1 = total * 2;
					total = calc1 + intvalue;
				}
			}
			//if either one of the values are negative, check for negative
			else if (int_negative != 4)
			{
				if (length == 128 && intvalue == 1)
				{
					int256_t lastcharvalue = 2;
					
					for (int i = 0; i < lastchar - 1; ++i)
					{
						lastcharvalue = lastcharvalue * 2;
					}

					for (int i = 1; i < length; ++i)
					{
						char charvalue = char_array[i];
						std::string stringvalue(1, charvalue);
						int intvalue = std::stoi(stringvalue);
						int256_t calc1 = total * 2;
						total = calc1 + intvalue;
					}
					total = total - lastcharvalue;
				}	
				else
				{
					for (int i = 0; i < length; ++i)
						{
							char charvalue = char_array[i];
							std::string stringvalue(1, charvalue);
							int intvalue = std::stoi(stringvalue);
							int256_t calc1 = total * 2;
							total = calc1 + intvalue;
						}
					
				}
					
			}
	   		if (int_negative == 4)
			{
	    		int256_t invertedtotal = total * -1;
	    		std::cout << "The result in decimal form is:" << "\n";
	    		std::cout << invertedtotal;	
	    	}
			else
			{
	    		std::cout << "\n" << "\n";
	    		std::cout << "The result in decimal form is:" << "\n";
	    		std::cout << total;
	    	}
	    	printf("\n");
	    	printf("\n");
	    	gettimeofday(&end, NULL);
    	    get_time = (end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec) * 1.0E-6;
    	    printf("Computation Time: %lf[sec]\n", get_time);
    	    printf("\n");

		    printf("I hope you remembered what calculation you performed!\n");

	    	// clean up all pointers
	    	delete_gate_bootstrapping_ciphertext_array(32, result);
	    	delete_gate_bootstrapping_ciphertext_array(32, result2);
	    	delete_gate_bootstrapping_ciphertext_array(32, result3);
	    	delete_gate_bootstrapping_ciphertext_array(32, result4);
	    	delete_gate_bootstrapping_secret_keyset(key);
    	
    	}
		
		else if (int_bit == 256)
		{
    	    LweSample* result = new_gate_bootstrapping_ciphertext_array(32, params);
	    	LweSample* result2 = new_gate_bootstrapping_ciphertext_array(32, params);
	    	LweSample* result3 = new_gate_bootstrapping_ciphertext_array(32, params);
	    	LweSample* result4 = new_gate_bootstrapping_ciphertext_array(32, params);
	    	LweSample* result5 = new_gate_bootstrapping_ciphertext_array(32, params);
	    	LweSample* result6 = new_gate_bootstrapping_ciphertext_array(32, params);
	    	LweSample* result7 = new_gate_bootstrapping_ciphertext_array(32, params);
	    	LweSample* result8 = new_gate_bootstrapping_ciphertext_array(32, params);
	  
	    	// export the 64 ciphertexts to a file (for the cloud)
	
	    	for (int i=0; i<32; i++)
			import_gate_bootstrapping_ciphertext_fromFile(answer_data, &result[i], params);
	    
			for (int i=0; i<32; i++)
			import_gate_bootstrapping_ciphertext_fromFile(answer_data, &result2[i], params);

			for (int i=0; i<32; i++)
			import_gate_bootstrapping_ciphertext_fromFile(answer_data, &result3[i], params);
	
			for (int i=0; i<32; i++)
			import_gate_bootstrapping_ciphertext_fromFile(answer_data, &result4[i], params);
	
			for (int i=0; i<32; i++)
			import_gate_bootstrapping_ciphertext_fromFile(answer_data, &result5[i], params);
	
			for (int i=0; i<32; i++)
			import_gate_bootstrapping_ciphertext_fromFile(answer_data, &result6[i], params);
	    
			for (int i=0; i<32; i++)
			import_gate_bootstrapping_ciphertext_fromFile(answer_data, &result7[i], params);
	
			for (int i=0; i<32; i++)
			import_gate_bootstrapping_ciphertext_fromFile(answer_data, &result8[i], params);
	    	fclose(answer_data);

	    	// decrypt and rebuild the answer
	    	int32_t int_answer1 = 0;
	    	for (int i=0; i<32; i++)
			{
				int ai = bootsSymDecrypt(&result[i], key)>0;
				int_answer1 |= (ai<<i);
	    	}
		
	    	int32_t int_answer2 = 0;
	    	for (int i=0; i<32; i++)
			{
				int ai = bootsSymDecrypt(&result2[i], key)>0;
				int_answer2 |= (ai<<i);
	    	}
	    
	    	int32_t int_answer3 = 0;
	    	for (int i=0; i<32; i++)
			{
				int ai = bootsSymDecrypt(&result3[i], key)>0;
				int_answer3 |= (ai<<i);
	    	}
	    
	    	int32_t int_answer4 = 0;
	    	for (int i=0; i<32; i++)
			{
				int ai = bootsSymDecrypt(&result4[i], key)>0;
				int_answer4 |= (ai<<i);
	    	}
	    
	    	int32_t int_answer5 = 0;
	    	for (int i=0; i<32; i++)
			{
				int ai = bootsSymDecrypt(&result5[i], key)>0;
				int_answer5 |= (ai<<i);
	    	}
	    
	    	int32_t int_answer6 = 0;
	    	for (int i=0; i<32; i++)
			{
				int ai = bootsSymDecrypt(&result6[i], key)>0;
				int_answer6 |= (ai<<i);
	    	}
	    
	    	int32_t int_answer7 = 0;
	    	for (int i=0; i<32; i++)
			{
				int ai = bootsSymDecrypt(&result7[i], key)>0;
				int_answer7 |= (ai<<i);
	    	}
	    
	    	int32_t int_answer8 = 0;
	    	for (int i=0; i<32; i++)
			{
				int ai = bootsSymDecrypt(&result8[i], key)>0;
				int_answer8 |= (ai<<i);
	    	}

			std::string binary1 = std::bitset<32>(int_answer1).to_string();
			std::string binary2 = std::bitset<32>(int_answer2).to_string();
			std::string binary3 = std::bitset<32>(int_answer3).to_string();
			std::string binary4 = std::bitset<32>(int_answer4).to_string();
			std::string binary5 = std::bitset<32>(int_answer5).to_string();
			std::string binary6 = std::bitset<32>(int_answer6).to_string();
			std::string binary7 = std::bitset<32>(int_answer7).to_string();
			std::string binary8 = std::bitset<32>(int_answer8).to_string();
			std::string binary_combined = binary8 + binary7 + binary6 + binary5 + binary4 + binary3 + binary2 +binary1;
			
			if (int_negative != 4)
			{
				std::cout << "The result in binary form is:" << "\n";
				std::cout << binary_combined << "\n";
			}

	    	//Length is the number of bits
			int length = binary_combined.length();
			int lastchar = length - 1;
			char char_array[length + 1];
			strcpy(char_array, binary_combined.c_str());

			int256_t total = 0;

			//Positive or negative checking
			char charvalue = char_array[0];
			std::string stringvalue(1, charvalue);
			int intvalue = std::stoi(stringvalue);

			//if the result is either double positive or negative
			if (int_negative == 0 || int_negative == 4)
			{
				for (int i = 0; i < length; ++i)
				{
					char charvalue = char_array[i];
					std::string stringvalue(1, charvalue);
					int intvalue = std::stoi(stringvalue);
					int256_t calc1 = total * 2;
					total = calc1 + intvalue;
				}
			
			}
			//if either one of the values are negative, check for negative
			else if (int_negative == 1 || int_negative == 2)
			{
				if (length == 256 && intvalue == 1)
				{
					int256_t lastcharvalue = 2;
					
					for (int i = 0; i < lastchar - 1; ++i)
					{
						lastcharvalue = lastcharvalue * 2;
					}

					for (int i = 1; i < length; ++i)
					{
						char charvalue = char_array[i];
						std::string stringvalue(1, charvalue);
						int intvalue = std::stoi(stringvalue);
						int256_t calc1 = total * 2;
						total = calc1 + intvalue;
					}
					total = total - lastcharvalue;

				}
				else
				{
					for (int i = 0; i < length; ++i)
					{
						char charvalue = char_array[i];
						std::string stringvalue(1, charvalue);
						int intvalue = std::stoi(stringvalue);
						int256_t calc1 = total * 2;
						total = calc1 + intvalue;
					}
				}
			}
			
	   		if (int_negative == 4)
			{
	    		int256_t invertedtotal = total * -1;
	    		std::cout << "The result in decimal form is:" << "\n";
	    		std::cout << invertedtotal;
	    		
	    	}
			else
			{
	    		std::cout << "\n" << "\n";
	    		std::cout << "The result in decimal form is:" << "\n";
	    		std::cout << total;
	    	}

	    	printf("\n");
	    	printf("\n");
	    	gettimeofday(&end, NULL);
    	    get_time = (end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec) * 1.0E-6;
    	    printf("Computation Time: %lf[sec]\n", get_time);
    	    printf("\n");

	    	printf("I hope you remembered what calculation you performed!\n");

	    	// clean up all pointers
	    	delete_gate_bootstrapping_ciphertext_array(32, result);
	    	delete_gate_bootstrapping_ciphertext_array(32, result2);
	    	delete_gate_bootstrapping_ciphertext_array(32, result3);
	    	delete_gate_bootstrapping_ciphertext_array(32, result4);
	    	delete_gate_bootstrapping_ciphertext_array(32, result5);
	    	delete_gate_bootstrapping_ciphertext_array(32, result6);
	    	delete_gate_bootstrapping_ciphertext_array(32, result7);
	    	delete_gate_bootstrapping_ciphertext_array(32, result8);
	    	delete_gate_bootstrapping_secret_keyset(key);
    	
    	}
    }
	
	// Subtraction
	else if (int_op == 2)
	{
    	std::cout << "Result for " << int_bit << " bit Subtraction computation" << "\n" << "\n";
    	
    	if (int_bit == 32){
    	    LweSample* result = new_gate_bootstrapping_ciphertext_array(32, params);
	    	for (int i=0; i<32; i++)
			import_gate_bootstrapping_ciphertext_fromFile(answer_data, &result[i], params);
	    	fclose(answer_data);

	    	// decrypt and rebuild the answer
	    	int32_t int_answer1 = 0;
	    	for (int i=0; i<32; i++) {
			int ai = bootsSymDecrypt(&result[i], key)>0;
			int_answer1 |= (ai<<i);
	    	}
		
			std::string binary1 = std::bitset<32>(int_answer1).to_string();
			std::string binary_combined = binary1;

			if (int_negative != 1){
				std::cout << "The result in binary form is:" << "\n";
				std::cout << binary_combined;
			}
	    	
			//Length is the number of bits
			int length = binary_combined.length();
			int lastchar = length - 1;
			char char_array[length + 1];
			strcpy(char_array, binary_combined.c_str());
			int256_t total = 0;


			//Positive or negative checking
			char charvalue = char_array[0];
			std::string stringvalue(1, charvalue);
			int intvalue = std::stoi(stringvalue);
			
			if (int_negative == 2){
			
				for (int i = 0; i < length; ++i)
				{
					char charvalue = char_array[i];
					std::string stringvalue(1, charvalue);
					int intvalue = std::stoi(stringvalue);
					int256_t calc1 = total * 2;
					total = calc1 + intvalue;
				}
				
			}
			else{
				// int_negative is not equals to 2
				if (length == 32 && intvalue == 1)
				{
					int256_t lastcharvalue = 2;
				
					for (int i = 0; i < lastchar - 1; ++i)
					{
						lastcharvalue = lastcharvalue * 2;
					}

					for (int i = 1; i < length; ++i)
					{
						char charvalue = char_array[i];
						std::string stringvalue(1, charvalue);
						int intvalue = std::stoi(stringvalue);
						int256_t calc1 = total * 2;
						total = calc1 + intvalue;
					}
					total = total - lastcharvalue;
				}

				else
				{
					for (int i = 0; i < length; ++i)
					{
						char charvalue = char_array[i];
						std::string stringvalue(1, charvalue);
						int intvalue = std::stoi(stringvalue);
						int256_t calc1 = total * 2;
						total = calc1 + intvalue;
					}
				}
			}

	    	if ( int_negative == 1){
	    	int256_t invertedtotal = total * -1;
	    	std::cout << "The result in decimal form is:" << "\n";
	    	std::cout << invertedtotal;
	    		
	    	}else{
	    	std::cout << "\n" << "\n";
	    	std::cout << "The result in decimal form is:" << "\n";
	    	std::cout << total;
	    }
	    printf("\n");
	    printf("\n");
	    gettimeofday(&end, NULL);
    	    get_time = (end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec) * 1.0E-6;
    	    printf("Computation Time: %lf[sec]\n", get_time);
    	    printf("\n");


	    printf("I hope you remembered what calculation you performed!\n");

	    // clean up all pointers
	    delete_gate_bootstrapping_ciphertext_array(32, result);
	    delete_gate_bootstrapping_secret_keyset(key);

    	}
		
		else if (int_bit == 64)
		{
    	    LweSample* result = new_gate_bootstrapping_ciphertext_array(32, params);
	    	LweSample* result2 = new_gate_bootstrapping_ciphertext_array(32, params);

	    	// export the 64 ciphertexts to a file (for the cloud)
	
	    	for (int i=0; i<32; i++)
			import_gate_bootstrapping_ciphertext_fromFile(answer_data, &result[i], params);
	    
			for (int i=0; i<32; i++)
			import_gate_bootstrapping_ciphertext_fromFile(answer_data, &result2[i], params);
	
	    	fclose(answer_data);

	    	// decrypt and rebuild the answer
	    	int32_t int_answer1 = 0;
	    	for (int i=0; i<32; i++) {
				int ai = bootsSymDecrypt(&result[i], key)>0;
				int_answer1 |= (ai<<i);
	    	}
		
	    	int32_t int_answer2 = 0;
	    	for (int i=0; i<32; i++) {
				int ai = bootsSymDecrypt(&result2[i], key)>0;
				int_answer2 |= (ai<<i);
	    	}
	    
		
			std::string binary1 = std::bitset<32>(int_answer1).to_string();
			std::string binary2 = std::bitset<32>(int_answer2).to_string();

			std::string binary_combined = binary2 + binary1;
			if (int_negative != 1){
				std::cout << "The result in binary form is:" << "\n";
				std::cout << binary_combined;
			}

	    	//Length is the number of bits
			int length = binary_combined.length();
			int lastchar = length - 1;
			char char_array[length + 1];
			strcpy(char_array, binary_combined.c_str());

			int256_t total = 0;

			//Positive or negative checking
			char charvalue = char_array[0];
			std::string stringvalue(1, charvalue);
			int intvalue = std::stoi(stringvalue);

			if (int_negative == 2 )
			{
				for (int i = 0; i < length; ++i)
				{
					char charvalue = char_array[i];
					std::string stringvalue(1, charvalue);
					int intvalue = std::stoi(stringvalue);
					int256_t calc1 = total * 2;
					total = calc1 + intvalue;
				}
				
			}
			else
			{
				if (length == 64 && intvalue == 1)
				{
					int256_t lastcharvalue = 2;
				
					for (int i = 0; i < lastchar - 1; ++i)
					{
						lastcharvalue = lastcharvalue * 2;
					}

					for (int i = 1; i < length; ++i)
					{
						char charvalue = char_array[i];
						std::string stringvalue(1, charvalue);
						int intvalue = std::stoi(stringvalue);
						int256_t calc1 = total * 2;
						total = calc1 + intvalue;
					}
					total = total - lastcharvalue;
				}
				else
				{
					for (int i = 0; i < length; ++i)
					{
						char charvalue = char_array[i];
						std::string stringvalue(1, charvalue);
						int intvalue = std::stoi(stringvalue);
						int256_t calc1 = total * 2;
						total = calc1 + intvalue;
					}
				}	
			}
	    	if (int_negative == 1 )
			{
	    		int256_t invertedtotal = total * -1;
	    		std::cout << "The result in decimal form is:" << "\n";
	    		std::cout << invertedtotal;
	    		
	    	}
			else
			{
	    		std::cout << "\n" << "\n";
	    		std::cout << "The result in decimal form is:" << "\n";
	    		std::cout << total;
	    	}

	    	printf("\n");
	    	printf("\n");
	    	gettimeofday(&end, NULL);
    	    get_time = (end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec) * 1.0E-6;
    	    printf("Computation Time: %lf[sec]\n", get_time);
    	    printf("\n");

	    	printf("I hope you remembered what calculation you performed!\n");

	    	// clean up all pointers
	    	delete_gate_bootstrapping_ciphertext_array(32, result);
	    	delete_gate_bootstrapping_ciphertext_array(32, result2);
	    	delete_gate_bootstrapping_secret_keyset(key);
    	
    	
    	}
		
		else if (int_bit == 128)
		{
    	    LweSample* result = new_gate_bootstrapping_ciphertext_array(32, params);
	    	LweSample* result2 = new_gate_bootstrapping_ciphertext_array(32, params);
	    	LweSample* result3 = new_gate_bootstrapping_ciphertext_array(32, params);
	    	LweSample* result4 = new_gate_bootstrapping_ciphertext_array(32, params);

	    	// export the 64 ciphertexts to a file (for the cloud)
	   
	    	for (int i=0; i<32; i++)
			import_gate_bootstrapping_ciphertext_fromFile(answer_data, &result[i], params);
	    
			for (int i=0; i<32; i++)
			import_gate_bootstrapping_ciphertext_fromFile(answer_data, &result2[i], params);
	
			for (int i=0; i<32; i++)
			import_gate_bootstrapping_ciphertext_fromFile(answer_data, &result3[i], params);
	
			for (int i=0; i<32; i++)
			import_gate_bootstrapping_ciphertext_fromFile(answer_data, &result4[i], params);
	
	    	fclose(answer_data);
	
	    	// decrypt and rebuild the answer
	    	int32_t int_answer1 = 0;
	    	for (int i=0; i<32; i++) 
			{
				int ai = bootsSymDecrypt(&result[i], key)>0;
				int_answer1 |= (ai<<i);
	    	}
		
	    	int32_t int_answer2 = 0;
	    	for (int i=0; i<32; i++)
			{
				int ai = bootsSymDecrypt(&result2[i], key)>0;
				int_answer2 |= (ai<<i);
	    	}
	    
	    	int32_t int_answer3 = 0;
	    	for (int i=0; i<32; i++)
			{
				int ai = bootsSymDecrypt(&result3[i], key)>0;
				int_answer3 |= (ai<<i);
	    	}
	    
	    	int32_t int_answer4 = 0;
	    	for (int i=0; i<32; i++)
			{
			int ai = bootsSymDecrypt(&result4[i], key)>0;
			int_answer4 |= (ai<<i);
			}
	    
			std::string binary1 = std::bitset<32>(int_answer1).to_string();
			std::string binary2 = std::bitset<32>(int_answer2).to_string();
			std::string binary3 = std::bitset<32>(int_answer3).to_string();
			std::string binary4 = std::bitset<32>(int_answer4).to_string();
			std::string binary_combined = binary4 + binary3 + binary2 + binary1;

			if (int_negative != 1)
			{
				std::cout << "The result in binary form is:" << "\n";
				std::cout << binary_combined;
			}

	    	//Length is the number of bits
			int length = binary_combined.length();
			int lastchar = length - 1;
			char char_array[length + 1];
			strcpy(char_array, binary_combined.c_str());

			int256_t total = 0;

			//Positive or negative checking
			char charvalue = char_array[0];
			std::string stringvalue(1, charvalue);
			int intvalue = std::stoi(stringvalue);
		
			if (int_negative == 2)
			{
				for (int i = 0; i < length; ++i)
				{
					char charvalue = char_array[i];
					std::string stringvalue(1, charvalue);
					int intvalue = std::stoi(stringvalue);
					int256_t calc1 = total * 2;
					total = calc1 + intvalue;
				}
				
			}
			else
			{
				if (length == 128 && intvalue == 1)
				{
					int256_t lastcharvalue = 2;
				
					for (int i = 0; i < lastchar - 1; ++i)
					{
						lastcharvalue = lastcharvalue * 2;
					}

					for (int i = 1; i < length; ++i)
					{
						char charvalue = char_array[i];
						std::string stringvalue(1, charvalue);
						int intvalue = std::stoi(stringvalue);
						int256_t calc1 = total * 2;
						total = calc1 + intvalue;
					}

					total = total - lastcharvalue;
				}
				else
				{
					for (int i = 0; i < length; ++i)
					{
						char charvalue = char_array[i];
						std::string stringvalue(1, charvalue);
						int intvalue = std::stoi(stringvalue);
						int256_t calc1 = total * 2;
						total = calc1 + intvalue;
					}
				}
			}
	    	if (int_negative == 1)
			{
	    		int256_t invertedtotal = total * -1;
	    		std::cout << "The result in decimal form is:" << "\n";
	    		std::cout << invertedtotal;		
	    	}
			else
			{
	    		std::cout << "\n" << "\n";
	    		std::cout << "The result in decimal form is:" << "\n";
	    		std::cout << total;
	    	}

	    	printf("\n");
	    	printf("\n");
	    	gettimeofday(&end, NULL);
    	    get_time = (end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec) * 1.0E-6;
    	    printf("Computation Time: %lf[sec]\n", get_time);
    	    printf("\n");

	    	printf("I hope you remembered what calculation you performed!\n");

	    	// clean up all pointers
	    	delete_gate_bootstrapping_ciphertext_array(32, result);
	    	delete_gate_bootstrapping_ciphertext_array(32, result2);
	    	delete_gate_bootstrapping_ciphertext_array(32, result3);
	    	delete_gate_bootstrapping_ciphertext_array(32, result4);
	    	delete_gate_bootstrapping_secret_keyset(key);
    	
    	}
		
		else if (int_bit == 256)
		{
    	    LweSample* result = new_gate_bootstrapping_ciphertext_array(32, params);
	    	LweSample* result2 = new_gate_bootstrapping_ciphertext_array(32, params);
	    	LweSample* result3 = new_gate_bootstrapping_ciphertext_array(32, params);
	    	LweSample* result4 = new_gate_bootstrapping_ciphertext_array(32, params);
	    	LweSample* result5 = new_gate_bootstrapping_ciphertext_array(32, params);
	    	LweSample* result6 = new_gate_bootstrapping_ciphertext_array(32, params);
	    	LweSample* result7 = new_gate_bootstrapping_ciphertext_array(32, params);
	    	LweSample* result8 = new_gate_bootstrapping_ciphertext_array(32, params);

	    	// export the 64 ciphertexts to a file (for the cloud)
	   
	    	for (int i=0; i<32; i++)
			import_gate_bootstrapping_ciphertext_fromFile(answer_data, &result[i], params);
	    
			for (int i=0; i<32; i++)
			import_gate_bootstrapping_ciphertext_fromFile(answer_data, &result2[i], params);
	
			for (int i=0; i<32; i++)
			import_gate_bootstrapping_ciphertext_fromFile(answer_data, &result3[i], params);
	
			for (int i=0; i<32; i++)
			import_gate_bootstrapping_ciphertext_fromFile(answer_data, &result4[i], params);
	
			for (int i=0; i<32; i++)
			import_gate_bootstrapping_ciphertext_fromFile(answer_data, &result5[i], params);
	    
			for (int i=0; i<32; i++)
			import_gate_bootstrapping_ciphertext_fromFile(answer_data, &result6[i], params);
	
			for (int i=0; i<32; i++)
			import_gate_bootstrapping_ciphertext_fromFile(answer_data, &result7[i], params);
	    
			for (int i=0; i<32; i++)
			import_gate_bootstrapping_ciphertext_fromFile(answer_data, &result8[i], params);
	    	fclose(answer_data);

	    	// decrypt and rebuild the answer
	    	int32_t int_answer1 = 0;
	    	for (int i=0; i<32; i++)
			{
				int ai = bootsSymDecrypt(&result[i], key)>0;
				int_answer1 |= (ai<<i);
	    	}
		
	    	int32_t int_answer2 = 0;
	    	for (int i=0; i<32; i++)
			{
				int ai = bootsSymDecrypt(&result2[i], key)>0;
				int_answer2 |= (ai<<i);
	    	}
	    
	    	int32_t int_answer3 = 0;
	    	for (int i=0; i<32; i++)
			{
				int ai = bootsSymDecrypt(&result3[i], key)>0;
				int_answer3 |= (ai<<i);
	    	}
	    
	    	int32_t int_answer4 = 0;
	    	for (int i=0; i<32; i++)
			{
				int ai = bootsSymDecrypt(&result4[i], key)>0;
				int_answer4 |= (ai<<i);
	    	}
	    
	    	int32_t int_answer5 = 0;
	    	for (int i=0; i<32; i++)
			{
				int ai = bootsSymDecrypt(&result5[i], key)>0;
				int_answer5 |= (ai<<i);
	    	}
	    
	    	int32_t int_answer6 = 0;
	    	for (int i=0; i<32; i++)
			{
				int ai = bootsSymDecrypt(&result6[i], key)>0;
				int_answer6 |= (ai<<i);
	    	}
	    
	    	int32_t int_answer7 = 0;
	    	for (int i=0; i<32; i++)
			{
				int ai = bootsSymDecrypt(&result7[i], key)>0;
				int_answer7 |= (ai<<i);
	    	}
	    
	    	int32_t int_answer8 = 0;
	    	for (int i=0; i<32; i++)
			{
				int ai = bootsSymDecrypt(&result8[i], key)>0;
				int_answer8 |= (ai<<i);
	    	}
		
			std::string binary1 = std::bitset<32>(int_answer1).to_string();
			std::string binary2 = std::bitset<32>(int_answer2).to_string();
			std::string binary3 = std::bitset<32>(int_answer3).to_string();
			std::string binary4 = std::bitset<32>(int_answer4).to_string();
			std::string binary5 = std::bitset<32>(int_answer5).to_string();
			std::string binary6 = std::bitset<32>(int_answer6).to_string();
			std::string binary7 = std::bitset<32>(int_answer7).to_string();
			std::string binary8 = std::bitset<32>(int_answer8).to_string();
			std::string binary_combined = binary8 + binary7 + binary6 + binary5 + binary4 + binary3 + binary2 +binary1;
		
			if (int_negative != 1)
			{
				std::cout << "The result in binary form is:" << "\n";
				std::cout << binary_combined;
			}
	    	
			//Length is the number of bits
			int length = binary_combined.length();
			int lastchar = length - 1;
			char char_array[length + 1];
			strcpy(char_array, binary_combined.c_str());

			int256_t total = 0;

			//Positive or negative checking
			char charvalue = char_array[0];
			std::string stringvalue(1, charvalue);
			int intvalue = std::stoi(stringvalue);
		
			if (int_negative == 2)
			{
				for (int i = 0; i < length; ++i)
				{
					char charvalue = char_array[i];
					std::string stringvalue(1, charvalue);
					int intvalue = std::stoi(stringvalue);
					int256_t calc1 = total * 2;
					total = calc1 + intvalue;
				}
				
			}
			else
			{
				if (length == 256 && intvalue == 1)
				{
					int256_t lastcharvalue = 2;
				
					for (int i = 0; i < lastchar - 1; ++i)
					{
						lastcharvalue = lastcharvalue * 2;
					}

					for (int i = 1; i < length; ++i)
					{
						char charvalue = char_array[i];
						std::string stringvalue(1, charvalue);
						int intvalue = std::stoi(stringvalue);
						int256_t calc1 = total * 2;
						total = calc1 + intvalue;
					}
					total = total - lastcharvalue;
				}
				else
				{
					for (int i = 0; i < length; ++i)
					{
						char charvalue = char_array[i];
						std::string stringvalue(1, charvalue);
						int intvalue = std::stoi(stringvalue);
						int256_t calc1 = total * 2;
						total = calc1 + intvalue;
					}
				}
			}

		    if (int_negative == 1)
			{
	    		int256_t invertedtotal = total * -1;
	    		std::cout << "The result in decimal form is:" << "\n";
	    		std::cout << invertedtotal;	
	   		}
			else
			{
	    		std::cout << "\n" << "\n";
	    		std::cout << "The result in decimal form is:" << "\n";
	    		std::cout << total;
	    	}
	    	printf("\n");
	    	printf("\n");
	    	gettimeofday(&end, NULL);
    	    get_time = (end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec) * 1.0E-6;
    	    printf("Computation Time: %lf[sec]\n", get_time);
    	    printf("\n");

	    	printf("I hope you remembered what calculation you performed!\n");

	    	// clean up all pointers
	    	delete_gate_bootstrapping_ciphertext_array(32, result);
	    	delete_gate_bootstrapping_ciphertext_array(32, result2);
	    	delete_gate_bootstrapping_ciphertext_array(32, result3);
	    	delete_gate_bootstrapping_ciphertext_array(32, result4);
	    	delete_gate_bootstrapping_ciphertext_array(32, result5);
	    	delete_gate_bootstrapping_ciphertext_array(32, result6);
	    	delete_gate_bootstrapping_ciphertext_array(32, result7);
	    	delete_gate_bootstrapping_ciphertext_array(32, result8);
	    	delete_gate_bootstrapping_secret_keyset(key);
    	}
    }
	
	// Multiplication
	else if (int_op == 4)
	{
    	std::cout << "Result for " << int_bit << " bit Multiplication computation" << "\n" << "\n";
    	if (int_bit == 256)
		{
    	    LweSample* finalresult1 = new_gate_bootstrapping_ciphertext_array(32, params);
	    	LweSample* finalresult2 = new_gate_bootstrapping_ciphertext_array(32, params);
	    	LweSample* finalresult3 = new_gate_bootstrapping_ciphertext_array(32, params);
	    	LweSample* finalresult4 = new_gate_bootstrapping_ciphertext_array(32, params);
	    	LweSample* finalresult5 = new_gate_bootstrapping_ciphertext_array(32, params);
	    	LweSample* finalresult6 = new_gate_bootstrapping_ciphertext_array(32, params);
	    	LweSample* finalresult7 = new_gate_bootstrapping_ciphertext_array(32, params);
	    	LweSample* finalresult8 = new_gate_bootstrapping_ciphertext_array(32, params);
	    
	    	//export the 32 ciphertexts to a file (for the cloud)
	    
	    	for (int i=0; i<32; i++)
			import_gate_bootstrapping_ciphertext_fromFile(answer_data, &finalresult1[i], params);
	    
			for (int i=0; i<32; i++)
			import_gate_bootstrapping_ciphertext_fromFile(answer_data, &finalresult2[i], params);
	
			for (int i=0; i<32; i++)
			import_gate_bootstrapping_ciphertext_fromFile(answer_data, &finalresult3[i], params);
	
			for (int i=0; i<32; i++)
			import_gate_bootstrapping_ciphertext_fromFile(answer_data, &finalresult4[i], params);
	    
			for (int i=0; i<32; i++)
			import_gate_bootstrapping_ciphertext_fromFile(answer_data, &finalresult5[i], params);
	    
			for (int i=0; i<32; i++)
			import_gate_bootstrapping_ciphertext_fromFile(answer_data, &finalresult6[i], params);
	    
			for (int i=0; i<32; i++)	
			import_gate_bootstrapping_ciphertext_fromFile(answer_data, &finalresult7[i], params);
	
			for (int i=0; i<32; i++)
			import_gate_bootstrapping_ciphertext_fromFile(answer_data, &finalresult8[i], params);
	    	fclose(answer_data);
	       
	    	//decrypt and rebuild the answer
	    	int32_t int_answer = 0;
	    	for (int i=0; i<32; i++)
			{
				int ai = bootsSymDecrypt(&finalresult1[i], key)>0;
				int_answer |= (ai<<i);
	    	}
	    
	    	int32_t int_answer2 = 0;
	    	for (int i=0; i<32; i++)
			{
				int ai = bootsSymDecrypt(&finalresult2[i], key)>0;
				int_answer2 |= (ai<<i);
	    	}
	    
	    	int32_t int_answer3 = 0;
	    	for (int i=0; i<32; i++)
			{
				int ai = bootsSymDecrypt(&finalresult3[i], key)>0;
				int_answer3 |= (ai<<i);
	    	}
	    
	    	int32_t int_answer4 = 0;
	    	for (int i=0; i<32; i++)
			{
				int ai = bootsSymDecrypt(&finalresult4[i], key)>0;
				int_answer4 |= (ai<<i);
	    	}
	    
	    	int32_t int_answer5 = 0;
	    	for (int i=0; i<32; i++)
			{
				int ai = bootsSymDecrypt(&finalresult5[i], key)>0;
				int_answer5 |= (ai<<i);
	    	}
	    
	    	int32_t int_answer6 = 0;
	    	for (int i=0; i<32; i++)
			{
				int ai = bootsSymDecrypt(&finalresult6[i], key)>0;
				int_answer6 |= (ai<<i);
	    	}
	    
	    	int32_t int_answer7 = 0;
	    	for (int i=0; i<32; i++)
			{
				int ai = bootsSymDecrypt(&finalresult7[i], key)>0;
				int_answer7 |= (ai<<i);
	    	}
	    
	    	int32_t int_answer8 = 0;
	    	for (int i=0; i<32; i++)
			{
				int ai = bootsSymDecrypt(&finalresult8[i], key)>0;
				int_answer8 |= (ai<<i);
	    	}
	    
	    	std::string binary1 = std::bitset<32>(int_answer).to_string();
	    	std::string binary2 = std::bitset<32>(int_answer2).to_string();
	    	std::string binary3 = std::bitset<32>(int_answer3).to_string();
	    	std::string binary4 = std::bitset<32>(int_answer4).to_string();
	    	std::string binary5 = std::bitset<32>(int_answer5).to_string();
	    	std::string binary6 = std::bitset<32>(int_answer6).to_string();
	    	std::string binary7 = std::bitset<32>(int_answer7).to_string();
	    	std::string binary8 = std::bitset<32>(int_answer8).to_string();
	    	std::string binary_combined = binary8 + binary7 + binary6 + binary5 + binary4 + binary3 + binary2 + binary1;

	    	int length = binary_combined.length();
	    	char char_array[length + 1];
	    	strcpy(char_array, binary_combined.c_str());
	    	int256_t total = 0;
	    
	    	if (int_negative == 0 || int_negative == 4)
			{
				std::cout << "The result in binary form is:" << "\n";
				std::cout << binary_combined;
	    	}

	    	for (int i = 0; i < length; ++i)
	    	{
				char charvalue = char_array[i];
				std::string stringvalue(1, charvalue);
				int intvalue = std::stoi(stringvalue);
				int256_t calc1 = total * 2;
				total = calc1 + intvalue;
	    	}

	    	if (int_negative == 1 || int_negative == 2)
			{
	    		int256_t invertedtotal = total * -1;
	    		std::cout << "The result in decimal form is:" << "\n";
	    		std::cout << invertedtotal;	
	    	}
			else
			{
	    		std::cout << "\n" << "\n";
	    		std::cout << "The result in decimal form is:" << "\n";
	    		std::cout << total;
	    	}

	    	printf("\n");
	    	printf("\n");
	    	gettimeofday(&end, NULL);
    	    get_time = (end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec) * 1.0E-6;
    	    printf("Computation Time: %lf[sec]\n", get_time);
    	    printf("\n");

	    	printf("I hope you remembered what calculation you performed!\n");

	    	//clean up all pointers
	    	delete_gate_bootstrapping_ciphertext_array(32, finalresult1);
	    	delete_gate_bootstrapping_ciphertext_array(32, finalresult2);
	    	delete_gate_bootstrapping_ciphertext_array(32, finalresult3);
	    	delete_gate_bootstrapping_ciphertext_array(32, finalresult4);
	    	delete_gate_bootstrapping_ciphertext_array(32, finalresult5);
	    	delete_gate_bootstrapping_ciphertext_array(32, finalresult6);
	    	delete_gate_bootstrapping_ciphertext_array(32, finalresult7);
	    	delete_gate_bootstrapping_ciphertext_array(32, finalresult8);
	    	delete_gate_bootstrapping_secret_keyset(key);
    	
    	}
    	
		else if (int_bit == 128)
		{
    	   	LweSample* finalresult = new_gate_bootstrapping_ciphertext_array(32, params);
	    	LweSample* finalresult2 = new_gate_bootstrapping_ciphertext_array(32, params);
	    	LweSample* finalresult3 = new_gate_bootstrapping_ciphertext_array(32, params);
	    	LweSample* finalresult4 = new_gate_bootstrapping_ciphertext_array(32, params);
	    
	   		//export the 32 ciphertexts to a file (for the cloud)
	   
	    	for (int i=0; i<32; i++)
			import_gate_bootstrapping_ciphertext_fromFile(answer_data, &finalresult[i], params);
	    
			for (int i=0; i<32; i++)
			import_gate_bootstrapping_ciphertext_fromFile(answer_data, &finalresult2[i], params);
	
			for (int i=0; i<32; i++)
			import_gate_bootstrapping_ciphertext_fromFile(answer_data, &finalresult3[i], params);
	
			for (int i=0; i<32; i++)
			import_gate_bootstrapping_ciphertext_fromFile(answer_data, &finalresult4[i], params);
	
	    	fclose(answer_data);

	    	//decrypt and rebuild the answer
	    	int32_t int_answer = 0;
	    	for (int i=0; i<32; i++)
			{
				int ai = bootsSymDecrypt(&finalresult[i], key)>0;
				int_answer |= (ai<<i);
	    	}
	    
	    	int32_t int_answer2 = 0;
	    	for (int i=0; i<32; i++)
			{
				int ai = bootsSymDecrypt(&finalresult2[i], key)>0;
				int_answer2 |= (ai<<i);
	    	}
	    
	    	int32_t int_answer3 = 0;
	    	for (int i=0; i<32; i++)
			{
				int ai = bootsSymDecrypt(&finalresult3[i], key)>0;
				int_answer3 |= (ai<<i);
	    	}
	    
	    	int32_t int_answer4 = 0;
	    	for (int i=0; i<32; i++)
			{
				int ai = bootsSymDecrypt(&finalresult4[i], key)>0;
				int_answer4 |= (ai<<i);
	    	}
	    
	    	std::string binary1 = std::bitset<32>(int_answer).to_string();
	    	std::string binary2 = std::bitset<32>(int_answer2).to_string();
	    	std::string binary3 = std::bitset<32>(int_answer3).to_string();
	    	std::string binary4 = std::bitset<32>(int_answer4).to_string();
	    	std::string binary_combined = binary4 + binary3 + binary2 + binary1;

	    	int length = binary_combined.length();
	    	char char_array[length + 1];
	    	strcpy(char_array, binary_combined.c_str());
	    	int256_t total = 0;
	    
	    	if (int_negative == 0 || int_negative == 4)
			{
				std::cout << "The result in binary form is:" << "\n";
				std::cout << binary_combined;
	    	}

	    	for (int i = 0; i < length; ++i)
	    	{
				char charvalue = char_array[i];
				std::string stringvalue(1, charvalue);
				int intvalue = std::stoi(stringvalue);
				int256_t calc1 = total * 2;
				total = calc1 + intvalue;
	    	}

	    	if (int_negative == 1 || int_negative == 2)
			{
	    		int256_t invertedtotal = total * -1;
	    		std::cout << "The result in decimal form is:" << "\n";
	    		std::cout << invertedtotal;		
	    	}
			else
			{
	    		std::cout << "\n" << "\n";
	    		std::cout << "The result in decimal form is:" << "\n";
	    		std::cout << total;
	    	}
	    
			printf("\n");
	    	printf("\n");
	    	gettimeofday(&end, NULL);
    	    get_time = (end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec) * 1.0E-6;
    	    printf("Computation Time: %lf[sec]\n", get_time);
    	    printf("\n");
	    	printf("I hope you remembered what calculation you performed!\n");

	    	//clean up all pointers
	    	delete_gate_bootstrapping_ciphertext_array(32, finalresult);
	    	delete_gate_bootstrapping_ciphertext_array(32, finalresult2);
	    	delete_gate_bootstrapping_ciphertext_array(32, finalresult3);
	    	delete_gate_bootstrapping_ciphertext_array(32, finalresult4);
	    	delete_gate_bootstrapping_secret_keyset(key);
    	
    	}
		
		else if (int_bit == 64)
		{
    	    LweSample* finalresult = new_gate_bootstrapping_ciphertext_array(32, params);
	    	LweSample* finalresult2 = new_gate_bootstrapping_ciphertext_array(32, params);
	    
	    	//export the 32 ciphertexts to a file (for the cloud)
	  
	    	for (int i=0; i<32; i++)
			import_gate_bootstrapping_ciphertext_fromFile(answer_data, &finalresult[i], params);
	    
			for (int i=0; i<32; i++)
			import_gate_bootstrapping_ciphertext_fromFile(answer_data, &finalresult2[i], params);
	
	    	fclose(answer_data);
	       
	    	//decrypt and rebuild the answer
	    	int32_t int_answer = 0;
	    	for (int i=0; i<32; i++) 
			{
				int ai = bootsSymDecrypt(&finalresult[i], key)>0;
				int_answer |= (ai<<i);
	    	}
	    
	    	int32_t int_answer2 = 0;
	    	for (int i=0; i<32; i++)
			{
				int ai = bootsSymDecrypt(&finalresult2[i], key)>0;
				int_answer2 |= (ai<<i);
	    	}
	    
	    	std::string binary1 = std::bitset<32>(int_answer).to_string();
	    	std::string binary2 = std::bitset<32>(int_answer2).to_string();
	    	std::string binary_combined = binary2 + binary1;

	    	int length = binary_combined.length();
	    	char char_array[length + 1];
	    	strcpy(char_array, binary_combined.c_str());
	    	int256_t total = 0;
	    	if (int_negative == 0 || int_negative == 4)
			{
				std::cout << "The result in binary form is:" << "\n";
				std::cout << binary_combined;
	    	}

	    	for (int i = 0; i < length; ++i)
	    	{
				char charvalue = char_array[i];
			std::string stringvalue(1, charvalue);
			int intvalue = std::stoi(stringvalue);
			int256_t calc1 = total * 2;
			total = calc1 + intvalue;
	    	}

	    	if (int_negative == 1 || int_negative == 2)
			{
	    		int256_t invertedtotal = total * -1;
	    		std::cout << "The result in decimal form is:" << "\n";
	    		std::cout << invertedtotal;	
	    	}
			else
			{
	    		std::cout << "\n" << "\n";
	    		std::cout << "The result in decimal form is:" << "\n";
	    		std::cout << total;
	    	}

	    	printf("\n");
			printf("\n");
	    	gettimeofday(&end, NULL);
    	    get_time = (end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec) * 1.0E-6;
    	    printf("Computation Time: %lf[sec]\n", get_time);
    	    printf("\n");

	    	printf("I hope you remembered what calculation you performed!\n");

	    	//clean up all pointers
	    	delete_gate_bootstrapping_ciphertext_array(32, finalresult);
	    	delete_gate_bootstrapping_ciphertext_array(32, finalresult2);
	    	delete_gate_bootstrapping_secret_keyset(key);
    	
    	}
    }
}

