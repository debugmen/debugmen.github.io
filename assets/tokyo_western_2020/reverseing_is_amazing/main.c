
undefined8 main(int iParm1,long lParm2)

{
  long lVar1;
  int cipher_len;
  int iVar2;
  undefined8 uVar3;
  size_t plain_len;
  BIO *bp;
  long lVar4;
  undefined8 *puVar5;
  undefined8 *puVar6;
  long in_FS_OFFSET;
  EVP_PKEY *local_b10;
  rsa_st *rsa;
  undefined local_af8;
  undefined local_af7;
  undefined local_af6;
  undefined local_af5;
  undefined local_af4;
  undefined local_af3;
  undefined local_af2;
  undefined local_af1;
  undefined local_af0;
  undefined local_aef;
  undefined local_aee;
  undefined local_aed;
  undefined local_aec;
  undefined local_aeb;
  undefined local_aea;
  undefined local_ae9;
  undefined local_ae8;
  undefined local_ae7;
  undefined local_ae6;
  undefined local_ae5;
  undefined local_ae4;
  undefined local_ae3;
  undefined local_ae2;
  undefined local_ae1;
  undefined local_ae0;
  undefined local_adf;
  undefined local_ade;
  undefined local_add;
  undefined local_adc;
  undefined local_adb;
  undefined local_ada;
  undefined local_ad9;
  undefined local_ad8;
  undefined local_ad7;
  undefined local_ad6;
  undefined local_ad5;
  undefined local_ad4;
  undefined local_ad3;
  undefined local_ad2;
  undefined local_ad1;
  undefined local_ad0;
  undefined local_acf;
  undefined local_ace;
  undefined local_acd;
  undefined local_acc;
  undefined local_acb;
  undefined local_aca;
  undefined local_ac9;
  undefined local_ac8;
  undefined local_ac7;
  undefined local_ac6;
  undefined local_ac5;
  undefined local_ac4;
  undefined local_ac3;
  undefined local_ac2;
  undefined local_ac1;
  undefined local_ac0;
  undefined local_abf;
  undefined local_abe;
  undefined local_abd;
  undefined local_abc;
  undefined local_abb;
  undefined local_aba;
  undefined local_ab9;
  undefined local_ab8;
  undefined local_ab7;
  undefined local_ab6;
  undefined local_ab5;
  undefined local_ab4;
  undefined local_ab3;
  undefined local_ab2;
  undefined local_ab1;
  undefined local_ab0;
  undefined local_aaf;
  undefined local_aae;
  undefined local_aad;
  undefined local_aac;
  undefined local_aab;
  undefined local_aaa;
  undefined local_aa9;
  undefined local_aa8;
  undefined local_aa7;
  undefined local_aa6;
  undefined local_aa5;
  undefined local_aa4;
  undefined local_aa3;
  undefined local_aa2;
  undefined local_aa1;
  undefined local_aa0;
  undefined local_a9f;
  undefined local_a9e;
  undefined local_a9d;
  undefined local_a9c;
  undefined local_a9b;
  undefined local_a9a;
  undefined local_a99;
  undefined local_a98;
  undefined local_a97;
  undefined local_a96;
  undefined local_a95;
  undefined local_a94;
  undefined local_a93;
  undefined local_a92;
  undefined local_a91;
  undefined local_a90;
  undefined local_a8f;
  undefined local_a8e;
  undefined local_a8d;
  undefined local_a8c;
  undefined local_a8b;
  undefined local_a8a;
  undefined local_a89;
  undefined local_a88;
  undefined local_a87;
  undefined local_a86;
  undefined local_a85;
  undefined local_a84;
  undefined local_a83;
  undefined local_a82;
  undefined local_a81;
  undefined local_a80;
  undefined local_a7f;
  undefined local_a7e;
  undefined local_a7d;
  undefined local_a7c;
  undefined local_a7b;
  undefined local_a7a;
  undefined local_a79;
  undefined8 local_a78 [76];
  uchar cipher_text [1024];
  uchar plain_text [1032];
  
  lVar1 = *(long *)(in_FS_OFFSET + 0x28);
  local_af8 = 0x6f;
  local_af7 = 0x86;
  local_af6 = 0xe4;
  local_af5 = 0x96;
  local_af4 = 0x29;
  local_af3 = 0xbe;
  local_af2 = 0x8a;
  local_af1 = 0x5e;
  local_af0 = 0x21;
  local_aef = 0xe2;
  local_aee = 0xc0;
  local_aed = 0xda;
  local_aec = 0x25;
  local_aeb = 0xb7;
  local_aea = 0x95;
  local_ae9 = 0xe0;
  local_ae8 = 0x5f;
  local_ae7 = 10;
  local_ae6 = 0x6c;
  local_ae5 = 0xe9;
  local_ae4 = 0x44;
  local_ae3 = 0xdb;
  local_ae2 = 0x12;
  local_ae1 = 0x4c;
  local_ae0 = 0x3a;
  local_adf = 0x6c;
  local_ade = 0x14;
  local_add = 0x87;
  local_adc = 0xc6;
  local_adb = 0x36;
  local_ada = 0x6b;
  local_ad9 = 0x6d;
  local_ad8 = 0x95;
  local_ad7 = 6;
  local_ad6 = 0x1c;
  local_ad5 = 0x2d;
  local_ad4 = 0x11;
  local_ad3 = 0x9e;
  local_ad2 = 0xf8;
  local_ad1 = 0x72;
  local_ad0 = 0xcc;
  local_acf = 0x9b;
  local_ace = 0x74;
  local_acd = 0x87;
  local_acc = 0x73;
  local_acb = 0xa7;
  local_aca = 0x52;
  local_ac9 = 0x72;
  local_ac8 = 0xc;
  local_ac7 = 0x5b;
  local_ac6 = 0x92;
  local_ac5 = 0x8d;
  local_ac4 = 0x7c;
  local_ac3 = 0xa9;
  local_ac2 = 0x35;
  local_ac1 = 0xeb;
  local_ac0 = 0xc5;
  local_abf = 0xd6;
  local_abe = 0x1e;
  local_abd = 0x1c;
  local_abc = 0x9e;
  local_abb = 0x7e;
  local_aba = 0xd3;
  local_ab9 = 0x6e;
  local_ab8 = 0x43;
  local_ab7 = 0x35;
  local_ab6 = 0x93;
  local_ab5 = 0xd0;
  local_ab4 = 0x6c;
  local_ab3 = 0x26;
  local_ab2 = 0xb4;
  local_ab1 = 0x95;
  local_ab0 = 0xe5;
  local_aaf = 0x99;
  local_aae = 0x28;
  local_aad = 99;
  local_aac = 0x5e;
  local_aab = 0xeb;
  local_aaa = 0xad;
  local_aa9 = 0x40;
  local_aa8 = 0xce;
  local_aa7 = 0x26;
  local_aa6 = 0x67;
  local_aa5 = 0xf7;
  local_aa4 = 0x32;
  local_aa3 = 0xb2;
  local_aa2 = 3;
  local_aa1 = 0xd;
  local_aa0 = 0x30;
  local_a9f = 0x24;
  local_a9e = 0x93;
  local_a9d = 0x84;
  local_a9c = 0x3a;
  local_a9b = 0x19;
  local_a9a = 0xac;
  local_a99 = 0x6f;
  local_a98 = 0x11;
  local_a97 = 0xbb;
  local_a96 = 0xb;
  local_a95 = 0x5b;
  local_a94 = 0x41;
  local_a93 = 0x8d;
  local_a92 = 0x9d;
  local_a91 = 0x49;
  local_a90 = 0x1a;
  local_a8f = 0xb1;
  local_a8e = 0x21;
  local_a8d = 0xd9;
  local_a8c = 0x79;
  local_a8b = 0x43;
  local_a8a = 0xbc;
  local_a89 = 0x83;
  local_a88 = 0x1c;
  local_a87 = 0x36;
  local_a86 = 0x98;
  local_a85 = 0xb9;
  local_a84 = 0x5a;
  local_a83 = 0x53;
  local_a82 = 0xd9;
  local_a81 = 0xf4;
  local_a80 = 0xa3;
  local_a7f = 0x99;
  local_a7e = 0x34;
  local_a7d = 0x67;
  local_a7c = 0xa2;
  local_a7b = 0x8b;
  local_a7a = 0xce;
  local_a79 = 6;
  lVar4 = 0x4c;
  puVar5 = &DAT_555555555100;
  puVar6 = local_a78;
  while (lVar4 != 0) {
    lVar4 = lVar4 + -1;
    *puVar6 = *puVar5;
    puVar5 = puVar5 + 1;
    puVar6 = puVar6 + 1;
  }
  if (iParm1 == 2) {
    plain_len = strlen(*(char **)(lParm2 + 8));
    memcpy(plain_text,*(void **)(lParm2 + 8),(long)(int)plain_len);
    rsa = (rsa_st *)0x0;
    local_b10 = (EVP_PKEY *)0x0;
    bp = BIO_new_mem_buf(local_a78,0x260);
    if (bp == (BIO *)0x0) {
      uVar3 = 1;
    }
    else {
      local_b10 = d2i_PrivateKey_bio(bp,&local_b10);
      if (local_b10 == (EVP_PKEY *)0x0) {
        uVar3 = 1;
      }
      else {
        rsa = EVP_PKEY_get1_RSA(local_b10);
        if (rsa == (rsa_st *)0x0) {
          uVar3 = 1;
        }
        else {
          cipher_len = RSA_private_encrypt((int)plain_len,plain_text,cipher_text,(RSA *)rsa,1);
          if (cipher_len < 0) {
            uVar3 = 1;
          }
          else {
            iVar2 = memcmp(cipher_text,&local_af8,(long)cipher_len);
            if (iVar2 == 0) {
              puts("Correct!");
            }
            else {
              puts("Incorrect!");
            }
            RSA_free((RSA *)rsa);
            EVP_PKEY_free(local_b10);
            BIO_free_all(bp);
            uVar3 = 0;
          }
        }
      }
    }
  }
  else {
    printf("./rsa TWCTF{*****************************}");
    uVar3 = 1;
  }
  if (lVar1 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return uVar3;
}

