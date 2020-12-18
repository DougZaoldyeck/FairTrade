#include <stdio.h>
#include <gmp.h>
#include <pbc.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
    // we have pk pair (e1, e2), sk x, hash of the message h and h_temp
    pairing_t pairing;
    element_t e1, e2, x, k, h, h1, h2, r, k0, sk, sk1, sk2, k1, d1, d2;
    element_t temp1, temp2;

    clock_t time1, time2;


    char s[3000] = "type a\nq 8780710799663312522437781984754049815806883199414208211028653399266475630880222957078625179422662221423155858769582317459277713367317481324925129998224791\nh 12016012264891146079388821366740534204802954401251311822919615131047207289359704531102844802183906537786776\nr 730750818665451621361119245571504901405976559617\nexp2 159\n exp1 107\nsign1 1\nsign0 1";

    if (pairing_init_set_buf(pairing, s, strlen(s))) pbc_die("Pairing initialization failed.");
    if (!pairing_is_symmetric(pairing)) pbc_die("pairing must be symmetric");

    element_init_G1(e1, pairing);
    element_init_Zr(x, pairing);
    element_init_G1(e2, pairing);
    //element_init_Zr(h, pairing);
    element_init_Zr(h1, pairing);
    element_init_Zr(h2, pairing);
    element_init_Zr(k, pairing);
    element_init_Zr(r, pairing);
    element_init_Zr(temp1, pairing);
    element_init_Zr(temp2, pairing);

    //element_init_Zr(sk, pairing);
    element_init_Zr(sk1, pairing);
    element_init_Zr(sk2, pairing);
    element_init_Zr(k0, pairing);
    element_init_Zr(k1, pairing);
    //element_init_G1(sig1, pairing);
    //element_init_G1(sig2, pairing);
    element_init_Zr(d1, pairing);
    element_init_Zr(d2, pairing);
    element_init_Zr(h, pairing);
    element_init_Zr(sk, pairing);



    element_set_str(e1,
                    "[2571885912040420003912999353029795482515242872502738349344401687093763805721926640726924042719817440031610585229774432403675905217029746909502694866828610, 1183640508733278024086196210958541915935309661944158283072400964166017539714070157288530571657769185241974774392938163891083456909994713847007054124219725]",
                    10);

    element_random(x);
    element_random(k);
    element_random(h1);
    element_random(h2);


/*
    element_set_str(x, "124082650188479568800315864596935264695441418483", 10);
    element_set_str(k, "345345367738479568800315864596935264695445345984", 10);
    element_set_str(h1, "345345367738479568800315864596935264634535459847", 10);
    element_set_str(h2, "345345367738479564564568645969352646954453459846", 10);
*/


    // pk pair (e1,e2), use e2's x-coordinate as x, actually r here
    element_mul_zn(e2, e1, k);
    element_set(r, element_x(e2));

    element_invert(k0, k);
    while(element_is0(k0))
        element_invert(k0,k);

    //element_printf("\n\n%B\n\n",k0);
    //printf("hello\n");
    //sign on message h1
    element_mul_zn(sk1, r, x);
    //element_printf("\n\nr*x = %B\n\n",sk1);
    //element_printf("\n\nh1 = %B\n\n",h1);
    //element_printf("\n\nr = %B\n\n",r);


    element_add(sk1, sk1, h1);
    //element_printf("\n\nm + rx = %B\n\n",sk1);

    element_mul_zn(sk1, sk1, k0);
    //element_printf("\n\n%B\n\n",sk1);

    //element_pairing(sig1, r, sk1);

    //printf("hello\n");
    //sign h2
    element_mul_zn(sk2, r, x);
    element_add(sk2, sk2, h2);
    element_mul_zn(sk2, sk2, k0);
    //element_pairing(sig2, r, sk2);




    //string hex1 = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
    //string hex2 = "0000665702007894000066570200789400006657020078940000665702007894";
    /*
    long dec1 = 0xFFFFFFFFFFFFFFFF;
    long dec2 = 0x0000665702007894;
    long result1 = 0x0000665702007894;
    long result2 = 0x0000665702007894;
    time1 = clock();

    for (int i = 0; i < 4; ++i)
    {
        long result = dec1 ^ dec2;
        if(result == result1)
            printf("correct randomness\n");
        else printf("wrong randomness provided\n");
    }

    time2 = clock();
    printf("transaction condition time = %f ms\n", ((double) (time2 - time1)) * 1000.0 / CLOCKS_PER_SEC);
     */


    //verify signature
    element_t  w, u1, u2, w1, w2;

    element_init_Zr(w,pairing);
    element_init_G1(w1,pairing);
    element_init_G1(w2,pairing);
    element_init_Zr(u1,pairing);
    element_init_Zr(u2,pairing);


    int compare_result;

    time1 = clock();
    element_invert(w, sk1);
    //element_printf("\n\n%B\n\n",w);
    element_mul_zn(u1, w, h1);
    element_mul_zn(w1, e1, u1);
    //element_printf("\n\n%B\n\n",w1);
    element_mul_zn(u2, w, r);
    element_mul_zn(w2, u2, e2);
    //element_printf("\n\n%B\n\n",w2);
    element_add(w1, w1, w2);
    //element_printf("\n\n%B\n\n",w1);

    element_set(w, element_x(w1));
    //element_printf("\n\nr is: %B\n\nPx is: %B\n\n", r, w);

    compare_result = element_cmp(w, r);
    time2 = clock();
    printf("Verification time = %f ms\n", ((double) (time2 - time1)) * 1000.0 / CLOCKS_PER_SEC);




    //recover k
    //element_init_Zr(h, pairing);
    //element_init_Zr(sk, pairing);

    time1 = clock();


    element_sub(h, h1, h2);
    element_sub(sk, sk1, sk2);
    //element_printf("\n\nh is: %B\n\nsk is: %B\n\n", h2, sk2);
    element_div(k1, h, sk);
    //element_invert(sk, sk);
    //element_mul_zn();
    //element_printf("\n\nk is: %B\n\nk1 is: %B \n\n",  k1, k0);

/*
    if(element_cmp(k1,k))
        printf("wrong!\n\n"); //decryption success
    else
        printf("correct!\n\n");
*/
    element_mul_zn(d1, sk1, k);
    element_sub(d1, d1, h1);
    element_div(d1, d1, r);
    element_mul_zn(d2, sk2, k);
    element_sub(d2, d2, h2);
    element_div(d2, d2, r);
/*
    if(element_cmp(d1,d2))
        printf("wrong!\n\n"); //decryption success
    else
        printf("correct!\n\n");
*/

    time2 = clock();
    printf("Derivation time = %f ms\n", ((double) (time2 - time1)) * 1000.0 / CLOCKS_PER_SEC);



    element_clear(e1);
    element_clear(e2);
    element_clear(h);
    element_clear(h1);
    element_clear(h2);
    element_clear(x);
    element_clear(k);
    element_clear(r);
    element_clear(k0);
    element_clear(k1);
    element_clear(sk);
    element_clear(sk1);
    element_clear(sk2);
    element_clear(d1);
    element_clear(d2);
    //element_clear(w);
    //element_clear(u1);
    //element_clear(u2);
    //element_clear(w0);


    pairing_clear(pairing);









}