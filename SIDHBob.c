// Client side C/C++ program to demonstrate Socket programming
#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include "random/random.h"
#define PORT 4380
   
int main(int argc, char const *argv[])
{
	int sock = 0, valread;
	struct sockaddr_in serv_addr;
	char *hello = "Hello from client";
	char buffer[2048] = {0};
	if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
		printf("\n Socket creation error \n");
		return -1;
	}
   
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(PORT);
	   
	// Convert IPv4 and IPv6 addresses from text to binary form
	if(inet_pton(AF_INET, "192.168.0.3", &serv_addr.sin_addr)<=0) 
	{
		printf("\nInvalid address/ Address not supported \n");
		return -1;
	}
   
	if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
	{
		printf("\nConnection Failed \n");
		return -1;
	}
		static void init_basis(digit_t *gen, f2elm_t XP, f2elm_t XQ, f2elm_t XR)
	{ // Initialization of basis points
	
		fpcopy(gen,                  XP[0]);
		fpcopy(gen +   NWORDS_FIELD, XP[1]);
		fpcopy(gen + 2*NWORDS_FIELD, XQ[0]);
		fpcopy(gen + 3*NWORDS_FIELD, XQ[1]);
		fpcopy(gen + 4*NWORDS_FIELD, XR[0]);
		fpcopy(gen + 5*NWORDS_FIELD, XR[1]);
	}
	
		void random_mod_order_B(unsigned char* random_digits)
	{  // Generation of Bob's secret key  
	   // Outputs random value in [0, 2^Floor(Log(2, oB)) - 1]

		randombytes(random_digits, SECRETKEY_B_BYTES);
		random_digits[SECRETKEY_B_BYTES-1] &= MASK_BOB;     // Masking last byte 
	}
	   int EphemeralKeyGeneration_B(const unsigned char* PrivateKeyB, unsigned char* PublicKeyB)
	{ // Bob's ephemeral public key generation
	  // Input:  a private key PrivateKeyB in the range [0, 2^Floor(Log(2,oB)) - 1]. 
	  // Output: the public key PublicKeyB consisting of 3 elements in GF(p^2) which are encoded by removing leading 0 bytes.
		point_proj_t R, phiP = {0}, phiQ = {0}, phiR = {0}, pts[MAX_INT_POINTS_BOB];
		f2elm_t XPB, XQB, XRB, coeff[3], A24plus = {0}, A24minus = {0}, A = {0};
		unsigned int i, row, m, index = 0, pts_index[MAX_INT_POINTS_BOB], npts = 0, ii = 0;
		digit_t SecretKeyB[NWORDS_ORDER] = {0};

		// Initialize basis points
		init_basis((digit_t*)B_gen, XPB, XQB, XRB);
		init_basis((digit_t*)A_gen, phiP->X, phiQ->X, phiR->X);
		fpcopy((digit_t*)&Montgomery_one, (phiP->Z)[0]);
		fpcopy((digit_t*)&Montgomery_one, (phiQ->Z)[0]);
		fpcopy((digit_t*)&Montgomery_one, (phiR->Z)[0]);

		// Initialize constants: A24minus = A-2C, A24plus = A+2C, where A=6, C=1
		fpcopy((digit_t*)&Montgomery_one, A24plus[0]);
		mp2_add(A24plus, A24plus, A24plus);
		mp2_add(A24plus, A24plus, A24minus);
		mp2_add(A24plus, A24minus, A);
		mp2_add(A24minus, A24minus, A24plus);

		// Retrieve kernel point
		decode_to_digits(PrivateKeyB, SecretKeyB, SECRETKEY_B_BYTES, NWORDS_ORDER);
		LADDER3PT(XPB, XQB, XRB, SecretKeyB, BOB, R, A);

		// Traverse tree
		index = 0;  
		for (row = 1; row < MAX_Bob; row++) {
			while (index < MAX_Bob-row) {
				fp2copy(R->X, pts[npts]->X);
				fp2copy(R->Z, pts[npts]->Z);
				pts_index[npts++] = index;
				m = strat_Bob[ii++];
				xTPLe(R, R, A24minus, A24plus, (int)m);
				index += m;
			} 
			get_3_isog(R, A24minus, A24plus, coeff);

			for (i = 0; i < npts; i++) {
				eval_3_isog(pts[i], coeff);
			}     
			eval_3_isog(phiP, coeff);
			eval_3_isog(phiQ, coeff);
			eval_3_isog(phiR, coeff);

			fp2copy(pts[npts-1]->X, R->X); 
			fp2copy(pts[npts-1]->Z, R->Z);
			index = pts_index[npts-1];
			npts -= 1;
		}

		get_3_isog(R, A24minus, A24plus, coeff);
		eval_3_isog(phiP, coeff);
		eval_3_isog(phiQ, coeff);
		eval_3_isog(phiR, coeff);

		inv_3_way(phiP->Z, phiQ->Z, phiR->Z);
		fp2mul_mont(phiP->X, phiP->Z, phiP->X);
		fp2mul_mont(phiQ->X, phiQ->Z, phiQ->X);
		fp2mul_mont(phiR->X, phiR->Z, phiR->X);

		// Format public key
		fp2_encode(phiP->X, PublicKeyB);
		fp2_encode(phiQ->X, PublicKeyB + FP2_ENCODED_BYTES);
		fp2_encode(phiR->X, PublicKeyB + 2*FP2_ENCODED_BYTES);

		return 0;
	}

	send(sock , PublicKeyB , strlen(PublicKeyB) , 0 );
	valread = read( sock , buffer, 2048);
	printf("Alice's Public Key: %s\n", buffer );
	printf("Bob's Public Key sent\n");
   
	int EphemeralSecretAgreement_B(const unsigned char* PrivateKeyB, const unsigned char* PublicKeyA, unsigned char* SharedSecretB)
{ // Bob's ephemeral shared secret computation
  // It produces a shared secret key SharedSecretB using his secret key PrivateKeyB and Alice's public key PublicKeyA
  // Inputs: Bob's PrivateKeyB is an integer in the range [0, 2^Floor(Log(2,oB)) - 1]. 
  //         Alice's PublicKeyA consists of 3 elements in GF(p^2) encoded by removing leading 0 bytes.
  // Output: a shared secret SharedSecretB that consists of one element in GF(p^2) encoded by removing leading 0 bytes.  
	point_proj_t R, pts[MAX_INT_POINTS_BOB];
	f2elm_t coeff[3], PKB[3], jinv;
	f2elm_t A24plus = {0}, A24minus = {0}, A = {0};
	unsigned int i, row, m, index = 0, pts_index[MAX_INT_POINTS_BOB], npts = 0, ii = 0;
	digit_t SecretKeyB[NWORDS_ORDER] = {0};
	  
	// Initialize images of Alice's basis
	fp2_decode(PublicKeyA, PKB[0]);
	fp2_decode(PublicKeyA + FP2_ENCODED_BYTES, PKB[1]);
	fp2_decode(PublicKeyA + 2*FP2_ENCODED_BYTES, PKB[2]);

	// Initialize constants: A24plus = A+2C, A24minus = A-2C, where C=1
	get_A(PKB[0], PKB[1], PKB[2], A);
	mp_add((digit_t*)&Montgomery_one, (digit_t*)&Montgomery_one, A24minus[0], NWORDS_FIELD);
	mp2_add(A, A24minus, A24plus);
	mp2_sub_p2(A, A24minus, A24minus);

	// Retrieve kernel point
	decode_to_digits(PrivateKeyB, SecretKeyB, SECRETKEY_B_BYTES, NWORDS_ORDER);
	LADDER3PT(PKB[0], PKB[1], PKB[2], SecretKeyB, BOB, R, A);
	
	// Traverse tree
	index = 0;  
	for (row = 1; row < MAX_Bob; row++) {
		while (index < MAX_Bob-row) {
			fp2copy(R->X, pts[npts]->X);
			fp2copy(R->Z, pts[npts]->Z);
			pts_index[npts++] = index;
			m = strat_Bob[ii++];
			xTPLe(R, R, A24minus, A24plus, (int)m);
			index += m;
		}
		get_3_isog(R, A24minus, A24plus, coeff);

		for (i = 0; i < npts; i++) {
			eval_3_isog(pts[i], coeff);
		} 

		fp2copy(pts[npts-1]->X, R->X); 
		fp2copy(pts[npts-1]->Z, R->Z);
		index = pts_index[npts-1];
		npts -= 1;
	}
	 
	get_3_isog(R, A24minus, A24plus, coeff);    
	fp2add(A24plus, A24minus, A);                 
	fp2add(A, A, A);
	fp2sub(A24plus, A24minus, A24plus);                   
	j_inv(A, A24plus, jinv);
	fp2_encode(jinv, SharedSecretB);    // Format shared secret

	return 0;
}
   
	printf("Bob's Shared Key: %s\n", SharedSecretB );
	close(sock);
	return 0;
}
