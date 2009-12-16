/*
* Serpent (SIMD)
* (C) 2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/serp_simd.h>
#include <botan/internal/serp_simd_sbox.h>
#include <botan/internal/simd_32.h>
#include <botan/loadstor.h>

namespace Botan {

namespace {

#define key_xor(round, B0, B1, B2, B3)                             \
   do {                                                            \
      B0 ^= SIMD_32(keys[4*round  ]);                              \
      B1 ^= SIMD_32(keys[4*round+1]);                              \
      B2 ^= SIMD_32(keys[4*round+2]);                              \
      B3 ^= SIMD_32(keys[4*round+3]);                              \
   } while(0);

/*
* Serpent's linear transformations
*/
#define transform(B0, B1, B2, B3)                                  \
   do {                                                            \
      B0.rotate_left(13);                                          \
      B2.rotate_left(3);                                           \
      B1 ^= B0 ^ B2;                                               \
      B3 ^= B2 ^ (B0 << 3);                                        \
      B1.rotate_left(1);                                           \
      B3.rotate_left(7);                                           \
      B0 ^= B1 ^ B3;                                               \
      B2 ^= B3 ^ (B1 << 7);                                        \
      B0.rotate_left(5);                                           \
      B2.rotate_left(22);                                          \
   } while(0);

#define i_transform(B0, B1, B2, B3)                                \
   do {                                                            \
      B2.rotate_right(22);                                         \
      B0.rotate_right(5);                                          \
      B2 ^= B3 ^ (B1 << 7);                                        \
      B0 ^= B1 ^ B3;                                               \
      B3.rotate_right(7);                                          \
      B1.rotate_right(1);                                          \
      B3 ^= B2 ^ (B0 << 3);                                        \
      B1 ^= B0 ^ B2;                                               \
      B2.rotate_right(3);                                          \
      B0.rotate_right(13);                                         \
   } while(0);

/*
* SIMD Serpent Encryption of 4 blocks in parallel
*/
void serpent_encrypt_4(const byte in[64],
                       byte out[64],
                       const u32bit keys[132])
   {
   SIMD_32 B0 = SIMD_32::load_le(in);
   SIMD_32 B1 = SIMD_32::load_le(in + 16);
   SIMD_32 B2 = SIMD_32::load_le(in + 32);
   SIMD_32 B3 = SIMD_32::load_le(in + 48);

   SIMD_32::transpose(B0, B1, B2, B3);

   key_xor( 0,B0,B1,B2,B3); SBoxE1(B0,B1,B2,B3); transform(B0,B1,B2,B3);
   key_xor( 1,B0,B1,B2,B3); SBoxE2(B0,B1,B2,B3); transform(B0,B1,B2,B3);
   key_xor( 2,B0,B1,B2,B3); SBoxE3(B0,B1,B2,B3); transform(B0,B1,B2,B3);
   key_xor( 3,B0,B1,B2,B3); SBoxE4(B0,B1,B2,B3); transform(B0,B1,B2,B3);
   key_xor( 4,B0,B1,B2,B3); SBoxE5(B0,B1,B2,B3); transform(B0,B1,B2,B3);
   key_xor( 5,B0,B1,B2,B3); SBoxE6(B0,B1,B2,B3); transform(B0,B1,B2,B3);
   key_xor( 6,B0,B1,B2,B3); SBoxE7(B0,B1,B2,B3); transform(B0,B1,B2,B3);
   key_xor( 7,B0,B1,B2,B3); SBoxE8(B0,B1,B2,B3); transform(B0,B1,B2,B3);

   key_xor( 8,B0,B1,B2,B3); SBoxE1(B0,B1,B2,B3); transform(B0,B1,B2,B3);
   key_xor( 9,B0,B1,B2,B3); SBoxE2(B0,B1,B2,B3); transform(B0,B1,B2,B3);
   key_xor(10,B0,B1,B2,B3); SBoxE3(B0,B1,B2,B3); transform(B0,B1,B2,B3);
   key_xor(11,B0,B1,B2,B3); SBoxE4(B0,B1,B2,B3); transform(B0,B1,B2,B3);
   key_xor(12,B0,B1,B2,B3); SBoxE5(B0,B1,B2,B3); transform(B0,B1,B2,B3);
   key_xor(13,B0,B1,B2,B3); SBoxE6(B0,B1,B2,B3); transform(B0,B1,B2,B3);
   key_xor(14,B0,B1,B2,B3); SBoxE7(B0,B1,B2,B3); transform(B0,B1,B2,B3);
   key_xor(15,B0,B1,B2,B3); SBoxE8(B0,B1,B2,B3); transform(B0,B1,B2,B3);

   key_xor(16,B0,B1,B2,B3); SBoxE1(B0,B1,B2,B3); transform(B0,B1,B2,B3);
   key_xor(17,B0,B1,B2,B3); SBoxE2(B0,B1,B2,B3); transform(B0,B1,B2,B3);
   key_xor(18,B0,B1,B2,B3); SBoxE3(B0,B1,B2,B3); transform(B0,B1,B2,B3);
   key_xor(19,B0,B1,B2,B3); SBoxE4(B0,B1,B2,B3); transform(B0,B1,B2,B3);
   key_xor(20,B0,B1,B2,B3); SBoxE5(B0,B1,B2,B3); transform(B0,B1,B2,B3);
   key_xor(21,B0,B1,B2,B3); SBoxE6(B0,B1,B2,B3); transform(B0,B1,B2,B3);
   key_xor(22,B0,B1,B2,B3); SBoxE7(B0,B1,B2,B3); transform(B0,B1,B2,B3);
   key_xor(23,B0,B1,B2,B3); SBoxE8(B0,B1,B2,B3); transform(B0,B1,B2,B3);

   key_xor(24,B0,B1,B2,B3); SBoxE1(B0,B1,B2,B3); transform(B0,B1,B2,B3);
   key_xor(25,B0,B1,B2,B3); SBoxE2(B0,B1,B2,B3); transform(B0,B1,B2,B3);
   key_xor(26,B0,B1,B2,B3); SBoxE3(B0,B1,B2,B3); transform(B0,B1,B2,B3);
   key_xor(27,B0,B1,B2,B3); SBoxE4(B0,B1,B2,B3); transform(B0,B1,B2,B3);
   key_xor(28,B0,B1,B2,B3); SBoxE5(B0,B1,B2,B3); transform(B0,B1,B2,B3);
   key_xor(29,B0,B1,B2,B3); SBoxE6(B0,B1,B2,B3); transform(B0,B1,B2,B3);
   key_xor(30,B0,B1,B2,B3); SBoxE7(B0,B1,B2,B3); transform(B0,B1,B2,B3);
   key_xor(31,B0,B1,B2,B3); SBoxE8(B0,B1,B2,B3); key_xor(32,B0,B1,B2,B3);

   SIMD_32::transpose(B0, B1, B2, B3);

   B0.store_le(out);
   B1.store_le(out + 16);
   B2.store_le(out + 32);
   B3.store_le(out + 48);
   }

/*
* SIMD Serpent Decryption of 4 blocks in parallel
*/
void serpent_decrypt_4(const byte in[64],
                       byte out[64],
                       const u32bit keys[132])
   {
   SIMD_32 B0 = SIMD_32::load_le(in);
   SIMD_32 B1 = SIMD_32::load_le(in + 16);
   SIMD_32 B2 = SIMD_32::load_le(in + 32);
   SIMD_32 B3 = SIMD_32::load_le(in + 48);

   SIMD_32::transpose(B0, B1, B2, B3);

   key_xor(32,B0,B1,B2,B3);  SBoxD8(B0,B1,B2,B3); key_xor(31,B0,B1,B2,B3);
   i_transform(B0,B1,B2,B3); SBoxD7(B0,B1,B2,B3); key_xor(30,B0,B1,B2,B3);
   i_transform(B0,B1,B2,B3); SBoxD6(B0,B1,B2,B3); key_xor(29,B0,B1,B2,B3);
   i_transform(B0,B1,B2,B3); SBoxD5(B0,B1,B2,B3); key_xor(28,B0,B1,B2,B3);
   i_transform(B0,B1,B2,B3); SBoxD4(B0,B1,B2,B3); key_xor(27,B0,B1,B2,B3);
   i_transform(B0,B1,B2,B3); SBoxD3(B0,B1,B2,B3); key_xor(26,B0,B1,B2,B3);
   i_transform(B0,B1,B2,B3); SBoxD2(B0,B1,B2,B3); key_xor(25,B0,B1,B2,B3);
   i_transform(B0,B1,B2,B3); SBoxD1(B0,B1,B2,B3); key_xor(24,B0,B1,B2,B3);

   i_transform(B0,B1,B2,B3); SBoxD8(B0,B1,B2,B3); key_xor(23,B0,B1,B2,B3);
   i_transform(B0,B1,B2,B3); SBoxD7(B0,B1,B2,B3); key_xor(22,B0,B1,B2,B3);
   i_transform(B0,B1,B2,B3); SBoxD6(B0,B1,B2,B3); key_xor(21,B0,B1,B2,B3);
   i_transform(B0,B1,B2,B3); SBoxD5(B0,B1,B2,B3); key_xor(20,B0,B1,B2,B3);
   i_transform(B0,B1,B2,B3); SBoxD4(B0,B1,B2,B3); key_xor(19,B0,B1,B2,B3);
   i_transform(B0,B1,B2,B3); SBoxD3(B0,B1,B2,B3); key_xor(18,B0,B1,B2,B3);
   i_transform(B0,B1,B2,B3); SBoxD2(B0,B1,B2,B3); key_xor(17,B0,B1,B2,B3);
   i_transform(B0,B1,B2,B3); SBoxD1(B0,B1,B2,B3); key_xor(16,B0,B1,B2,B3);

   i_transform(B0,B1,B2,B3); SBoxD8(B0,B1,B2,B3); key_xor(15,B0,B1,B2,B3);
   i_transform(B0,B1,B2,B3); SBoxD7(B0,B1,B2,B3); key_xor(14,B0,B1,B2,B3);
   i_transform(B0,B1,B2,B3); SBoxD6(B0,B1,B2,B3); key_xor(13,B0,B1,B2,B3);
   i_transform(B0,B1,B2,B3); SBoxD5(B0,B1,B2,B3); key_xor(12,B0,B1,B2,B3);
   i_transform(B0,B1,B2,B3); SBoxD4(B0,B1,B2,B3); key_xor(11,B0,B1,B2,B3);
   i_transform(B0,B1,B2,B3); SBoxD3(B0,B1,B2,B3); key_xor(10,B0,B1,B2,B3);
   i_transform(B0,B1,B2,B3); SBoxD2(B0,B1,B2,B3); key_xor( 9,B0,B1,B2,B3);
   i_transform(B0,B1,B2,B3); SBoxD1(B0,B1,B2,B3); key_xor( 8,B0,B1,B2,B3);

   i_transform(B0,B1,B2,B3); SBoxD8(B0,B1,B2,B3); key_xor( 7,B0,B1,B2,B3);
   i_transform(B0,B1,B2,B3); SBoxD7(B0,B1,B2,B3); key_xor( 6,B0,B1,B2,B3);
   i_transform(B0,B1,B2,B3); SBoxD6(B0,B1,B2,B3); key_xor( 5,B0,B1,B2,B3);
   i_transform(B0,B1,B2,B3); SBoxD5(B0,B1,B2,B3); key_xor( 4,B0,B1,B2,B3);
   i_transform(B0,B1,B2,B3); SBoxD4(B0,B1,B2,B3); key_xor( 3,B0,B1,B2,B3);
   i_transform(B0,B1,B2,B3); SBoxD3(B0,B1,B2,B3); key_xor( 2,B0,B1,B2,B3);
   i_transform(B0,B1,B2,B3); SBoxD2(B0,B1,B2,B3); key_xor( 1,B0,B1,B2,B3);
   i_transform(B0,B1,B2,B3); SBoxD1(B0,B1,B2,B3); key_xor( 0,B0,B1,B2,B3);

   SIMD_32::transpose(B0, B1, B2, B3);

   B0.store_le(out);
   B1.store_le(out + 16);
   B2.store_le(out + 32);
   B3.store_le(out + 48);
   }

}

#undef key_xor
#undef transform
#undef i_transform

/*
* Serpent Encryption
*/
void Serpent_SIMD::encrypt_n(const byte in[], byte out[], u32bit blocks) const
   {
   while(blocks >= 4)
      {
      serpent_encrypt_4(in, out, this->round_key);
      in += 4 * BLOCK_SIZE;
      out += 4 * BLOCK_SIZE;
      blocks -= 4;
      }

   Serpent::encrypt_n(in, out, blocks);
   }

/*
* Serpent Decryption
*/
void Serpent_SIMD::decrypt_n(const byte in[], byte out[], u32bit blocks) const
   {
   while(blocks >= 4)
      {
      serpent_decrypt_4(in, out, this->round_key);
      in += 4 * BLOCK_SIZE;
      out += 4 * BLOCK_SIZE;
      blocks -= 4;
      }

   Serpent::decrypt_n(in, out, blocks);
   }

}
