#include <stdio.h>
#include <assert.h>
#include <limits.h>
#include <iostream>
#include <boost/multiprecision/cpp_int.hpp>
#include <fstream>
#include <string>
#include<sstream>
#include <sys/time.h>
#include <time.h>
#include <vector>
#include <cassert>
#include <utility>
using namespace std;
using namespace boost::multiprecision;
using Int = boost::multiprecision::cpp_int;
using boost::multiprecision::uint128_t;
using boost::multiprecision::uint256_t;
using boost::multiprecision::int256_t;
using boost::multiprecision::int512_t;
using boost::multiprecision::uint1024_t;
bool is_digits(const std::string &str) {
    return str.find_first_not_of("-0123456789") == std::string::npos;
}
int main(){
   char value1_char[256] = {'\0'};
   char value1_char2[256] = {'\0'};
   char value2_char[256] = {'\0'};
   char value2_char2[256] = {'\0'};
   char chunk1[32] = {'\0'};
   char chunk2[32] = {'\0'};
   char chunk3[32] = {'\0'};
   char chunk4[32] = {'\0'};
   char chunk5[32] = {'\0'};
   char chunk6[32] = {'\0'};
   char chunk7[32] = {'\0'};
   char chunk8[32] = {'\0'};

   char negativecheck1;
   char negativecheck2;
   char negative;

   int n = 0;
   int i = 0;
   int m = 0;
   int count1 = 0;
   int count2 = 1;


   std::string input1;
   std::string input2;
   int512_t value1;
   int512_t value2;
   int512_t value1copy;
   int512_t value2copy;
   int256_t value3("115792089237316195423570985008687907853269984665640564039457584007913129639935");
   int512_t total;
   int256_t check128("340282366920938463463374607431768211455");
   int256_t check64("18446744073709551615");
   int256_t check32("4294967295");
   int bitcount1 = 0;
   int bitcount2 = 0;
   FILE * pFile;
   pFile = fopen ("values.txt","w");
   struct timeval start, end;
   double get_time;
   string x; 

   //used for input sanitisation
   while (1){
   	cout << "Enter the number of bits for calculation (32/64/128/256 bits) : "; // Type a number and press enter
   	
        cin >> input1; // Get user input from the keyboard
        if (input1 == "32" ){
        	cout << "32 bit calculation" << "\n";
        	while (1){
        		cout << "Will the number be positive? (yes/no) : ";
        		cin >> input2;
        		if (input2 == "yes"){
        			fprintf(pFile, "00000000000000000000000000000000");
        			fprintf(pFile, "\n");
        			cout << "Wrote a binary value of 2147483647 to values.txt" << "\n";
        			break;
        		
        		}else if (input2 == "no"){
        			fprintf(pFile, "00000000000000000000000000000010");
        			fprintf(pFile, "\n");
        			cout << "Wrote a binary value of -2147483647 to values.txt" << "\n";
        			break;
        		}else{
        			cout << "Invalid input, please try again" << "\n";
        		}
        	}
		fprintf(pFile, "00000000000000000000000000100000");
		fprintf(pFile, "\n");
		fprintf(pFile, "01111111111111111111111111111111");
		fprintf(pFile, "\n");
	        fprintf(pFile, "00000000000000000000000000000000");
		fprintf(pFile, "\n");
        	break;
        }else if (input1 == "64"){
        	cout << "64 bits calculation" << "\n";
        	
        	while (1){
        		cout << "Will the number be positive? (yes/no) : ";
        		cin >> input2;
        		if (input2 == "yes"){
        			fprintf(pFile, "00000000000000000000000000000000");
        			fprintf(pFile, "\n");
        			cout << "Wrote a binary value of 9223372036854775807 to values.txt" << "\n";
        			break;
        		
        		}else if (input2 == "no"){
        			fprintf(pFile, "00000000000000000000000000000010");
        			fprintf(pFile, "\n");
        			cout << "Wrote a binary value of -9223372036854775807 to values.txt" << "\n";
        			break;
        		}else{
        			cout << "Invalid input, please try again" << "\n";
        		}
        	}
		fprintf(pFile, "00000000000000000000000001000000");
		fprintf(pFile, "\n");
		fprintf(pFile, "11111111111111111111111111111111");
		fprintf(pFile, "\n");
		fprintf(pFile, "01111111111111111111111111111111");
		fprintf(pFile, "\n");
	        fprintf(pFile, "00000000000000000000000000000000");
		fprintf(pFile, "\n");
        	break;
        
        }else if (input1 == "128"){
               cout << "128 bits calculation" << "\n";
        	while (1){
        		cout << "Will the number be positive? (yes/no) : ";
        		cin >> input2;
        		if (input2 == "yes"){
        			fprintf(pFile, "00000000000000000000000000000000");
        			fprintf(pFile, "\n");
        			cout << "Wrote a binary value of 170141183460469231731687303715884105727 to values.txt" << "\n";
        			break;
        		
        		}else if (input2 == "no"){
        			fprintf(pFile, "00000000000000000000000000000010");
        			fprintf(pFile, "\n");
        			cout << "Wrote a binary value of -170141183460469231731687303715884105727 to values.txt" << "\n";
        			break;
        		}else{
        			cout << "Invalid input, please try again" << "\n";
        		}
        	}
        	fprintf(pFile, "00000000000000000000000010000000");
		fprintf(pFile, "\n");
		fprintf(pFile, "11111111111111111111111111111111");
		fprintf(pFile, "\n");
		fprintf(pFile, "11111111111111111111111111111111");
		fprintf(pFile, "\n");
		fprintf(pFile, "11111111111111111111111111111111");
		fprintf(pFile, "\n");
		fprintf(pFile, "01111111111111111111111111111111");
		fprintf(pFile, "\n");
	        fprintf(pFile, "00000000000000000000000000000000");
		fprintf(pFile, "\n");
        	break;
        
        }else if (input1 == "256"){
               cout << "256 bits calculation" << "\n";
        	while (1){
        		cout << "Will the number be positive? (yes/no) : ";
        		cin >> input2;
        		if (input2 == "yes"){
        			fprintf(pFile, "00000000000000000000000000000000");
        			fprintf(pFile, "\n");
        			cout << "Wrote a binary value of 57896044618658097711785492504343953926634992332820282019728792003956564819967 to values.txt" << "\n";
        			break;
        		}else if (input2 == "no"){
        			fprintf(pFile, "00000000000000000000000000000010");
        			fprintf(pFile, "\n");
        			cout << "Wrote a binary value of -57896044618658097711785492504343953926634992332820282019728792003956564819967 to values.txt" << "\n";
        			break;
        		}else{
        			cout << "Invalid input, please try again" << "\n";
        		}
        	}
		fprintf(pFile, "00000000000000000000000100000000");
		fprintf(pFile, "\n");
		fprintf(pFile, "11111111111111111111111111111111");
		fprintf(pFile, "\n");
		fprintf(pFile, "11111111111111111111111111111111");
		fprintf(pFile, "\n");
		fprintf(pFile, "11111111111111111111111111111111");
		fprintf(pFile, "\n");
		fprintf(pFile, "11111111111111111111111111111111");
		fprintf(pFile, "\n");
		fprintf(pFile, "11111111111111111111111111111111");
		fprintf(pFile, "\n");
		fprintf(pFile, "11111111111111111111111111111111");
		fprintf(pFile, "\n");
		fprintf(pFile, "11111111111111111111111111111111");
		fprintf(pFile, "\n");
		fprintf(pFile, "01111111111111111111111111111111");
		fprintf(pFile, "\n");
	        fprintf(pFile, "00000000000000000000000000000000");
		fprintf(pFile, "\n");
        	break;
        }else{
        	cout << "Invalid input, please try again" << "\n";
		cin.clear();
		cin.ignore(256,'\n');
        }
        }
   	
   	gettimeofday(&start, NULL);
   	std::cout << "Successfully written values to values.txt" << "\n";
   	return 0;
}



