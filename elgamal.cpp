#include <stdio.h>
#include <gmp.h>
#include <pbc.h>
#include <string.h>
#include <time.h>

int main(int argc, char *argv[]) {
    // we have pk pair (e1, e2), sk d, order q, hash of the message h and h_temp
    pairing_t pairing;
    element_t e1, e2, d, q, k, h, h_temp;
    clock_t time1, time2;

    char m1[BUFSIZ] = "A message to encrypt";

    char s[3000] = "type a\nq 8780710799663312522437781984754049815806883199414208211028653399266475630880222957078625179422662221423155858769582317459277713367317481324925129998224791\nh 12016012264891146079388821366740534204802954401251311822919615131047207289359704531102844802183906537786776\nr 730750818665451621361119245571504901405976559617\nexp2 159\n exp1 107\nsign1 1\nsign0 1";

    if (pairing_init_set_buf(pairing, s, strlen(s))) pbc_die("Pairing initialization failed.");
    if (!pairing_is_symmetric(pairing)) pbc_die("pairing must be symmetric");

    element_init_G1(e1, pairing);
    element_init_Zr(d, pairing);
    element_init_G1(e2, pairing);
    element_init_G1(h, pairing);
    element_init_G1(h_temp, pairing);
    element_init_Zr(k, pairing);


    element_set_str(e1,
                    "[2571885912040420003912999353029795482515242872502738349344401687093763805721926640726924042719817440031610585229774432403675905217029746909502694866828610, 1183640508733278024086196210958541915935309661944158283072400964166017539714070157288530571657769185241974774392938163891083456909994713847007054124219725]",
                    10);

    element_set_str(d, "124082650188479568800315864596935264695441418483", 10);
    element_set_str(k, "345345367738479568800315864596935264695445345984", 10);


    // pk pair (e1,e2)
    element_mul_zn(e2, e1, d);

    element_t C1, C2;
    element_init_G1(C1, pairing);
    element_init_G1(C2, pairing);

    element_from_hash(h, m1, strlen(m1));

    time1 = clock();
    element_mul_zn(C1, e1, k);
    element_mul_zn(C2, e2, k);


    element_add(C2, C2, h);
    time2 = clock();
    printf("Encryption time = %f ms\n", ((double) (time2 - time1)) * 1000.0 / CLOCKS_PER_SEC);

    element_mul_zn(h_temp, C1, d);
    element_sub(h_temp, C2, h_temp);
    //element_mul(h_temp, C2, h_temp);

    //element_printf("\n\n\n\nh is: %B\n\nhtemp is: %B \n\n", h, h_temp);

/*
    if(element_cmp(h, h_temp))
        printf("wrong!\n\n"); //decryption success
    else
        printf("correct!\n\n");
*/

    element_t d_1, d_2,C3,C4;
    element_init_Zr(d_1, pairing);
    element_init_Zr(d_2, pairing);
    element_init_G1(C3, pairing);
    element_init_G1(C4, pairing);
    element_set_str(d_1, "1240826501884734534556455864596935264695441418400", 10);
    element_sub(d_2, d, d_1);

    //element_set_str(d2, "000000000000000000000000000000000000000000000003", 10);

    //re-calculate

    int compare_result;

    element_mul_zn(C3, e1, d_1);
    element_sub(C3, e2, C3);
    time1 = clock();
    element_mul_zn(C4, e1, d_2);
    compare_result = element_cmp(C3, C4);
    //element_printf("\n\nC3 is: %B\n\nC4 is: %B \n\n",  C3, C4);
/*
    if(element_cmp(C3, C4))
        printf("wrong!\n\n");
    else
        printf("correct!\n\n");
*/
    time2 = clock();
    printf("transaction condition time = %f ms\n", ((double) (time2 - time1)) * 1000.0 / CLOCKS_PER_SEC);



}