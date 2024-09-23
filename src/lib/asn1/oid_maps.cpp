/*
* OID maps
*
* This file was automatically generated by ./src/scripts/dev_tools/gen_oids.py on 2024-10-15
*
* All manual edits to this file will be lost. Edit the script
* then regenerate this source file.
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/oid_map.h>
#include <unordered_map>

namespace Botan {

std::unordered_map<std::string, std::string> OID_Map::load_oid2str_map() {
   return std::unordered_map<std::string, std::string>{

      {"0.3.4401.5.3.1.9.26", "Camellia-192/GCM"},
      {"0.3.4401.5.3.1.9.46", "Camellia-256/GCM"},
      {"0.3.4401.5.3.1.9.6", "Camellia-128/GCM"},
      {"0.4.0.127.0.15.1.1.13.0", "XMSS"},
      {"1.0.14888.3.0.5", "ECKCDSA"},
      {"1.2.156.10197.1.104.100", "SM4/OCB"},
      {"1.2.156.10197.1.104.2", "SM4/CBC"},
      {"1.2.156.10197.1.104.8", "SM4/GCM"},
      {"1.2.156.10197.1.301", "sm2p256v1"},
      {"1.2.156.10197.1.301.1", "SM2"},
      {"1.2.156.10197.1.301.2", "SM2_Kex"},
      {"1.2.156.10197.1.301.3", "SM2_Enc"},
      {"1.2.156.10197.1.401", "SM3"},
      {"1.2.156.10197.1.501", "SM2_Sig/SM3"},
      {"1.2.156.10197.1.504", "RSA/EMSA3(SM3)"},
      {"1.2.250.1.223.101.256.1", "frp256v1"},
      {"1.2.392.200011.61.1.1.1.2", "Camellia-128/CBC"},
      {"1.2.392.200011.61.1.1.1.3", "Camellia-192/CBC"},
      {"1.2.392.200011.61.1.1.1.4", "Camellia-256/CBC"},
      {"1.2.410.200004.1.100.4.3", "ECKCDSA/SHA-1"},
      {"1.2.410.200004.1.100.4.4", "ECKCDSA/SHA-224"},
      {"1.2.410.200004.1.100.4.5", "ECKCDSA/SHA-256"},
      {"1.2.410.200004.1.4", "SEED/CBC"},
      {"1.2.643.100.1", "GOST.OGRN"},
      {"1.2.643.100.111", "GOST.SubjectSigningTool"},
      {"1.2.643.100.112", "GOST.IssuerSigningTool"},
      {"1.2.643.2.2.19", "GOST-34.10"},
      {"1.2.643.2.2.3", "GOST-34.10/GOST-R-34.11-94"},
      {"1.2.643.2.2.35.1", "gost_256A"},
      {"1.2.643.2.2.36.0", "gost_256A"},
      {"1.2.643.3.131.1.1", "GOST.INN"},
      {"1.2.643.7.1.1.1.1", "GOST-34.10-2012-256"},
      {"1.2.643.7.1.1.1.2", "GOST-34.10-2012-512"},
      {"1.2.643.7.1.1.2.2", "Streebog-256"},
      {"1.2.643.7.1.1.2.3", "Streebog-512"},
      {"1.2.643.7.1.1.3.2", "GOST-34.10-2012-256/Streebog-256"},
      {"1.2.643.7.1.1.3.3", "GOST-34.10-2012-512/Streebog-512"},
      {"1.2.643.7.1.2.1.1.1", "gost_256A"},
      {"1.2.643.7.1.2.1.1.2", "gost_256B"},
      {"1.2.643.7.1.2.1.2.1", "gost_512A"},
      {"1.2.643.7.1.2.1.2.2", "gost_512B"},
      {"1.2.840.10040.4.1", "DSA"},
      {"1.2.840.10040.4.3", "DSA/SHA-1"},
      {"1.2.840.10045.2.1", "ECDSA"},
      {"1.2.840.10045.3.1.1", "secp192r1"},
      {"1.2.840.10045.3.1.2", "x962_p192v2"},
      {"1.2.840.10045.3.1.3", "x962_p192v3"},
      {"1.2.840.10045.3.1.4", "x962_p239v1"},
      {"1.2.840.10045.3.1.5", "x962_p239v2"},
      {"1.2.840.10045.3.1.6", "x962_p239v3"},
      {"1.2.840.10045.3.1.7", "secp256r1"},
      {"1.2.840.10045.4.1", "ECDSA/SHA-1"},
      {"1.2.840.10045.4.3.1", "ECDSA/SHA-224"},
      {"1.2.840.10045.4.3.2", "ECDSA/SHA-256"},
      {"1.2.840.10045.4.3.3", "ECDSA/SHA-384"},
      {"1.2.840.10045.4.3.4", "ECDSA/SHA-512"},
      {"1.2.840.10046.2.1", "DH"},
      {"1.2.840.113533.7.66.10", "CAST-128/CBC"},
      {"1.2.840.113533.7.66.15", "KeyWrap.CAST-128"},
      {"1.2.840.113549.1.1.1", "RSA"},
      {"1.2.840.113549.1.1.10", "RSA/EMSA4"},
      {"1.2.840.113549.1.1.11", "RSA/EMSA3(SHA-256)"},
      {"1.2.840.113549.1.1.12", "RSA/EMSA3(SHA-384)"},
      {"1.2.840.113549.1.1.13", "RSA/EMSA3(SHA-512)"},
      {"1.2.840.113549.1.1.14", "RSA/EMSA3(SHA-224)"},
      {"1.2.840.113549.1.1.16", "RSA/EMSA3(SHA-512-256)"},
      {"1.2.840.113549.1.1.2", "RSA/EMSA3(MD2)"},
      {"1.2.840.113549.1.1.4", "RSA/EMSA3(MD5)"},
      {"1.2.840.113549.1.1.5", "RSA/EMSA3(SHA-1)"},
      {"1.2.840.113549.1.1.7", "RSA/OAEP"},
      {"1.2.840.113549.1.1.8", "MGF1"},
      {"1.2.840.113549.1.5.12", "PKCS5.PBKDF2"},
      {"1.2.840.113549.1.5.13", "PBE-PKCS5v20"},
      {"1.2.840.113549.1.9.1", "PKCS9.EmailAddress"},
      {"1.2.840.113549.1.9.14", "PKCS9.ExtensionRequest"},
      {"1.2.840.113549.1.9.16.3.17", "HSS-LMS"},
      {"1.2.840.113549.1.9.16.3.18", "ChaCha20Poly1305"},
      {"1.2.840.113549.1.9.16.3.6", "KeyWrap.TripleDES"},
      {"1.2.840.113549.1.9.16.3.8", "Compression.Zlib"},
      {"1.2.840.113549.1.9.2", "PKCS9.UnstructuredName"},
      {"1.2.840.113549.1.9.3", "PKCS9.ContentType"},
      {"1.2.840.113549.1.9.4", "PKCS9.MessageDigest"},
      {"1.2.840.113549.1.9.7", "PKCS9.ChallengePassword"},
      {"1.2.840.113549.2.10", "HMAC(SHA-384)"},
      {"1.2.840.113549.2.11", "HMAC(SHA-512)"},
      {"1.2.840.113549.2.13", "HMAC(SHA-512-256)"},
      {"1.2.840.113549.2.5", "MD5"},
      {"1.2.840.113549.2.7", "HMAC(SHA-1)"},
      {"1.2.840.113549.2.8", "HMAC(SHA-224)"},
      {"1.2.840.113549.2.9", "HMAC(SHA-256)"},
      {"1.2.840.113549.3.7", "TripleDES/CBC"},
      {"1.3.101.110", "X25519"},
      {"1.3.101.111", "X448"},
      {"1.3.101.112", "Ed25519"},
      {"1.3.101.113", "Ed448"},
      {"1.3.132.0.10", "secp256k1"},
      {"1.3.132.0.30", "secp160r2"},
      {"1.3.132.0.31", "secp192k1"},
      {"1.3.132.0.32", "secp224k1"},
      {"1.3.132.0.33", "secp224r1"},
      {"1.3.132.0.34", "secp384r1"},
      {"1.3.132.0.35", "secp521r1"},
      {"1.3.132.0.8", "secp160r1"},
      {"1.3.132.0.9", "secp160k1"},
      {"1.3.132.1.12", "ECDH"},
      {"1.3.14.3.2.26", "SHA-1"},
      {"1.3.14.3.2.7", "DES/CBC"},
      {"1.3.36.3.2.1", "RIPEMD-160"},
      {"1.3.36.3.3.1.2", "RSA/EMSA3(RIPEMD-160)"},
      {"1.3.36.3.3.2.5.2.1", "ECGDSA"},
      {"1.3.36.3.3.2.5.4.1", "ECGDSA/RIPEMD-160"},
      {"1.3.36.3.3.2.5.4.2", "ECGDSA/SHA-1"},
      {"1.3.36.3.3.2.5.4.3", "ECGDSA/SHA-224"},
      {"1.3.36.3.3.2.5.4.4", "ECGDSA/SHA-256"},
      {"1.3.36.3.3.2.5.4.5", "ECGDSA/SHA-384"},
      {"1.3.36.3.3.2.5.4.6", "ECGDSA/SHA-512"},
      {"1.3.36.3.3.2.8.1.1.1", "brainpool160r1"},
      {"1.3.36.3.3.2.8.1.1.11", "brainpool384r1"},
      {"1.3.36.3.3.2.8.1.1.13", "brainpool512r1"},
      {"1.3.36.3.3.2.8.1.1.3", "brainpool192r1"},
      {"1.3.36.3.3.2.8.1.1.5", "brainpool224r1"},
      {"1.3.36.3.3.2.8.1.1.7", "brainpool256r1"},
      {"1.3.36.3.3.2.8.1.1.9", "brainpool320r1"},
      {"1.3.6.1.4.1.11591.15.1", "OpenPGP.Ed25519"},
      {"1.3.6.1.4.1.11591.4.11", "Scrypt"},
      {"1.3.6.1.4.1.25258.1.10.1", "Dilithium-4x4-AES-r3"},
      {"1.3.6.1.4.1.25258.1.10.2", "Dilithium-6x5-AES-r3"},
      {"1.3.6.1.4.1.25258.1.10.3", "Dilithium-8x7-AES-r3"},
      {"1.3.6.1.4.1.25258.1.11.1", "Kyber-512-90s-r3"},
      {"1.3.6.1.4.1.25258.1.11.2", "Kyber-768-90s-r3"},
      {"1.3.6.1.4.1.25258.1.11.3", "Kyber-1024-90s-r3"},
      {"1.3.6.1.4.1.25258.1.12.1.1", "SphincsPlus-shake-128s-r3.1"},
      {"1.3.6.1.4.1.25258.1.12.1.2", "SphincsPlus-shake-128f-r3.1"},
      {"1.3.6.1.4.1.25258.1.12.1.3", "SphincsPlus-shake-192s-r3.1"},
      {"1.3.6.1.4.1.25258.1.12.1.4", "SphincsPlus-shake-192f-r3.1"},
      {"1.3.6.1.4.1.25258.1.12.1.5", "SphincsPlus-shake-256s-r3.1"},
      {"1.3.6.1.4.1.25258.1.12.1.6", "SphincsPlus-shake-256f-r3.1"},
      {"1.3.6.1.4.1.25258.1.12.2.1", "SphincsPlus-sha2-128s-r3.1"},
      {"1.3.6.1.4.1.25258.1.12.2.2", "SphincsPlus-sha2-128f-r3.1"},
      {"1.3.6.1.4.1.25258.1.12.2.3", "SphincsPlus-sha2-192s-r3.1"},
      {"1.3.6.1.4.1.25258.1.12.2.4", "SphincsPlus-sha2-192f-r3.1"},
      {"1.3.6.1.4.1.25258.1.12.2.5", "SphincsPlus-sha2-256s-r3.1"},
      {"1.3.6.1.4.1.25258.1.12.2.6", "SphincsPlus-sha2-256f-r3.1"},
      {"1.3.6.1.4.1.25258.1.12.3.1", "SphincsPlus-haraka-128s-r3.1"},
      {"1.3.6.1.4.1.25258.1.12.3.2", "SphincsPlus-haraka-128f-r3.1"},
      {"1.3.6.1.4.1.25258.1.12.3.3", "SphincsPlus-haraka-192s-r3.1"},
      {"1.3.6.1.4.1.25258.1.12.3.4", "SphincsPlus-haraka-192f-r3.1"},
      {"1.3.6.1.4.1.25258.1.12.3.5", "SphincsPlus-haraka-256s-r3.1"},
      {"1.3.6.1.4.1.25258.1.12.3.6", "SphincsPlus-haraka-256f-r3.1"},
      {"1.3.6.1.4.1.25258.1.13", "HSS-LMS-Private-Key"},
      {"1.3.6.1.4.1.25258.1.14.1", "FrodoKEM-640-SHAKE"},
      {"1.3.6.1.4.1.25258.1.14.2", "FrodoKEM-976-SHAKE"},
      {"1.3.6.1.4.1.25258.1.14.3", "FrodoKEM-1344-SHAKE"},
      {"1.3.6.1.4.1.25258.1.15.1", "FrodoKEM-640-AES"},
      {"1.3.6.1.4.1.25258.1.15.2", "FrodoKEM-976-AES"},
      {"1.3.6.1.4.1.25258.1.15.3", "FrodoKEM-1344-AES"},
      {"1.3.6.1.4.1.25258.1.16.1", "eFrodoKEM-640-SHAKE"},
      {"1.3.6.1.4.1.25258.1.16.2", "eFrodoKEM-976-SHAKE"},
      {"1.3.6.1.4.1.25258.1.16.3", "eFrodoKEM-1344-SHAKE"},
      {"1.3.6.1.4.1.25258.1.17.1", "eFrodoKEM-640-AES"},
      {"1.3.6.1.4.1.25258.1.17.2", "eFrodoKEM-976-AES"},
      {"1.3.6.1.4.1.25258.1.17.3", "eFrodoKEM-1344-AES"},
      {"1.3.6.1.4.1.25258.1.3", "McEliece"},
      {"1.3.6.1.4.1.25258.1.5", "XMSS-draft6"},
      {"1.3.6.1.4.1.25258.1.6.1", "GOST-34.10-2012-256/SHA-256"},
      {"1.3.6.1.4.1.25258.1.7.1", "Kyber-512-r3"},
      {"1.3.6.1.4.1.25258.1.7.2", "Kyber-768-r3"},
      {"1.3.6.1.4.1.25258.1.7.3", "Kyber-1024-r3"},
      {"1.3.6.1.4.1.25258.1.8", "XMSS-draft12"},
      {"1.3.6.1.4.1.25258.1.9.1", "Dilithium-4x4-r3"},
      {"1.3.6.1.4.1.25258.1.9.2", "Dilithium-6x5-r3"},
      {"1.3.6.1.4.1.25258.1.9.3", "Dilithium-8x7-r3"},
      {"1.3.6.1.4.1.25258.3.1", "Serpent/CBC"},
      {"1.3.6.1.4.1.25258.3.101", "Serpent/GCM"},
      {"1.3.6.1.4.1.25258.3.102", "Twofish/GCM"},
      {"1.3.6.1.4.1.25258.3.2", "Threefish-512/CBC"},
      {"1.3.6.1.4.1.25258.3.2.1", "AES-128/OCB"},
      {"1.3.6.1.4.1.25258.3.2.2", "AES-192/OCB"},
      {"1.3.6.1.4.1.25258.3.2.3", "AES-256/OCB"},
      {"1.3.6.1.4.1.25258.3.2.4", "Serpent/OCB"},
      {"1.3.6.1.4.1.25258.3.2.5", "Twofish/OCB"},
      {"1.3.6.1.4.1.25258.3.2.6", "Camellia-128/OCB"},
      {"1.3.6.1.4.1.25258.3.2.7", "Camellia-192/OCB"},
      {"1.3.6.1.4.1.25258.3.2.8", "Camellia-256/OCB"},
      {"1.3.6.1.4.1.25258.3.3", "Twofish/CBC"},
      {"1.3.6.1.4.1.25258.3.4.1", "AES-128/SIV"},
      {"1.3.6.1.4.1.25258.3.4.2", "AES-192/SIV"},
      {"1.3.6.1.4.1.25258.3.4.3", "AES-256/SIV"},
      {"1.3.6.1.4.1.25258.3.4.4", "Serpent/SIV"},
      {"1.3.6.1.4.1.25258.3.4.5", "Twofish/SIV"},
      {"1.3.6.1.4.1.25258.3.4.6", "Camellia-128/SIV"},
      {"1.3.6.1.4.1.25258.3.4.7", "Camellia-192/SIV"},
      {"1.3.6.1.4.1.25258.3.4.8", "Camellia-256/SIV"},
      {"1.3.6.1.4.1.25258.3.4.9", "SM4/SIV"},
      {"1.3.6.1.4.1.25258.4.1", "numsp256d1"},
      {"1.3.6.1.4.1.25258.4.2", "numsp384d1"},
      {"1.3.6.1.4.1.25258.4.3", "numsp512d1"},
      {"1.3.6.1.4.1.3029.1.2.1", "ElGamal"},
      {"1.3.6.1.4.1.3029.1.5.1", "OpenPGP.Curve25519"},
      {"1.3.6.1.4.1.311.20.2.2", "Microsoft SmartcardLogon"},
      {"1.3.6.1.4.1.311.20.2.3", "Microsoft UPN"},
      {"1.3.6.1.4.1.8301.3.1.2.9.0.38", "secp521r1"},
      {"1.3.6.1.5.5.7.1.1", "PKIX.AuthorityInformationAccess"},
      {"1.3.6.1.5.5.7.1.26", "PKIX.TNAuthList"},
      {"1.3.6.1.5.5.7.3.1", "PKIX.ServerAuth"},
      {"1.3.6.1.5.5.7.3.2", "PKIX.ClientAuth"},
      {"1.3.6.1.5.5.7.3.3", "PKIX.CodeSigning"},
      {"1.3.6.1.5.5.7.3.4", "PKIX.EmailProtection"},
      {"1.3.6.1.5.5.7.3.5", "PKIX.IPsecEndSystem"},
      {"1.3.6.1.5.5.7.3.6", "PKIX.IPsecTunnel"},
      {"1.3.6.1.5.5.7.3.7", "PKIX.IPsecUser"},
      {"1.3.6.1.5.5.7.3.8", "PKIX.TimeStamping"},
      {"1.3.6.1.5.5.7.3.9", "PKIX.OCSPSigning"},
      {"1.3.6.1.5.5.7.48.1", "PKIX.OCSP"},
      {"1.3.6.1.5.5.7.48.1.1", "PKIX.OCSP.BasicResponse"},
      {"1.3.6.1.5.5.7.48.1.5", "PKIX.OCSP.NoCheck"},
      {"1.3.6.1.5.5.7.48.2", "PKIX.CertificateAuthorityIssuers"},
      {"1.3.6.1.5.5.7.8.5", "PKIX.XMPPAddr"},
      {"2.16.840.1.101.3.4.1.2", "AES-128/CBC"},
      {"2.16.840.1.101.3.4.1.22", "AES-192/CBC"},
      {"2.16.840.1.101.3.4.1.25", "KeyWrap.AES-192"},
      {"2.16.840.1.101.3.4.1.26", "AES-192/GCM"},
      {"2.16.840.1.101.3.4.1.27", "AES-192/CCM"},
      {"2.16.840.1.101.3.4.1.42", "AES-256/CBC"},
      {"2.16.840.1.101.3.4.1.45", "KeyWrap.AES-256"},
      {"2.16.840.1.101.3.4.1.46", "AES-256/GCM"},
      {"2.16.840.1.101.3.4.1.47", "AES-256/CCM"},
      {"2.16.840.1.101.3.4.1.5", "KeyWrap.AES-128"},
      {"2.16.840.1.101.3.4.1.6", "AES-128/GCM"},
      {"2.16.840.1.101.3.4.1.7", "AES-128/CCM"},
      {"2.16.840.1.101.3.4.2.1", "SHA-256"},
      {"2.16.840.1.101.3.4.2.10", "SHA-3(512)"},
      {"2.16.840.1.101.3.4.2.11", "SHAKE-128"},
      {"2.16.840.1.101.3.4.2.12", "SHAKE-256"},
      {"2.16.840.1.101.3.4.2.2", "SHA-384"},
      {"2.16.840.1.101.3.4.2.3", "SHA-512"},
      {"2.16.840.1.101.3.4.2.4", "SHA-224"},
      {"2.16.840.1.101.3.4.2.6", "SHA-512-256"},
      {"2.16.840.1.101.3.4.2.7", "SHA-3(224)"},
      {"2.16.840.1.101.3.4.2.8", "SHA-3(256)"},
      {"2.16.840.1.101.3.4.2.9", "SHA-3(384)"},
      {"2.16.840.1.101.3.4.3.1", "DSA/SHA-224"},
      {"2.16.840.1.101.3.4.3.10", "ECDSA/SHA-3(256)"},
      {"2.16.840.1.101.3.4.3.11", "ECDSA/SHA-3(384)"},
      {"2.16.840.1.101.3.4.3.12", "ECDSA/SHA-3(512)"},
      {"2.16.840.1.101.3.4.3.13", "RSA/EMSA3(SHA-3(224))"},
      {"2.16.840.1.101.3.4.3.14", "RSA/EMSA3(SHA-3(256))"},
      {"2.16.840.1.101.3.4.3.15", "RSA/EMSA3(SHA-3(384))"},
      {"2.16.840.1.101.3.4.3.16", "RSA/EMSA3(SHA-3(512))"},
      {"2.16.840.1.101.3.4.3.17", "ML-DSA-4x4"},
      {"2.16.840.1.101.3.4.3.18", "ML-DSA-6x5"},
      {"2.16.840.1.101.3.4.3.19", "ML-DSA-8x7"},
      {"2.16.840.1.101.3.4.3.2", "DSA/SHA-256"},
      {"2.16.840.1.101.3.4.3.20", "SLH-DSA-SHA2-128s"},
      {"2.16.840.1.101.3.4.3.21", "SLH-DSA-SHA2-128f"},
      {"2.16.840.1.101.3.4.3.22", "SLH-DSA-SHA2-192s"},
      {"2.16.840.1.101.3.4.3.23", "SLH-DSA-SHA2-192f"},
      {"2.16.840.1.101.3.4.3.24", "SLH-DSA-SHA2-256s"},
      {"2.16.840.1.101.3.4.3.25", "SLH-DSA-SHA2-256f"},
      {"2.16.840.1.101.3.4.3.26", "SLH-DSA-SHAKE-128s"},
      {"2.16.840.1.101.3.4.3.27", "SLH-DSA-SHAKE-128f"},
      {"2.16.840.1.101.3.4.3.28", "SLH-DSA-SHAKE-192s"},
      {"2.16.840.1.101.3.4.3.29", "SLH-DSA-SHAKE-192f"},
      {"2.16.840.1.101.3.4.3.3", "DSA/SHA-384"},
      {"2.16.840.1.101.3.4.3.30", "SLH-DSA-SHAKE-256s"},
      {"2.16.840.1.101.3.4.3.31", "SLH-DSA-SHAKE-256f"},
      {"2.16.840.1.101.3.4.3.4", "DSA/SHA-512"},
      {"2.16.840.1.101.3.4.3.5", "DSA/SHA-3(224)"},
      {"2.16.840.1.101.3.4.3.6", "DSA/SHA-3(256)"},
      {"2.16.840.1.101.3.4.3.7", "DSA/SHA-3(384)"},
      {"2.16.840.1.101.3.4.3.8", "DSA/SHA-3(512)"},
      {"2.16.840.1.101.3.4.3.9", "ECDSA/SHA-3(224)"},
      {"2.16.840.1.101.3.4.4.1", "ML-KEM-512"},
      {"2.16.840.1.101.3.4.4.2", "ML-KEM-768"},
      {"2.16.840.1.101.3.4.4.3", "ML-KEM-1024"},
      {"2.16.840.1.113730.1.13", "Certificate Comment"},
      {"2.5.29.14", "X509v3.SubjectKeyIdentifier"},
      {"2.5.29.15", "X509v3.KeyUsage"},
      {"2.5.29.16", "X509v3.PrivateKeyUsagePeriod"},
      {"2.5.29.17", "X509v3.SubjectAlternativeName"},
      {"2.5.29.18", "X509v3.IssuerAlternativeName"},
      {"2.5.29.19", "X509v3.BasicConstraints"},
      {"2.5.29.20", "X509v3.CRLNumber"},
      {"2.5.29.21", "X509v3.ReasonCode"},
      {"2.5.29.23", "X509v3.HoldInstructionCode"},
      {"2.5.29.24", "X509v3.InvalidityDate"},
      {"2.5.29.28", "X509v3.CRLIssuingDistributionPoint"},
      {"2.5.29.30", "X509v3.NameConstraints"},
      {"2.5.29.31", "X509v3.CRLDistributionPoints"},
      {"2.5.29.32", "X509v3.CertificatePolicies"},
      {"2.5.29.32.0", "X509v3.AnyPolicy"},
      {"2.5.29.35", "X509v3.AuthorityKeyIdentifier"},
      {"2.5.29.36", "X509v3.PolicyConstraints"},
      {"2.5.29.37", "X509v3.ExtendedKeyUsage"},
      {"2.5.4.10", "X520.Organization"},
      {"2.5.4.11", "X520.OrganizationalUnit"},
      {"2.5.4.12", "X520.Title"},
      {"2.5.4.3", "X520.CommonName"},
      {"2.5.4.4", "X520.Surname"},
      {"2.5.4.42", "X520.GivenName"},
      {"2.5.4.43", "X520.Initials"},
      {"2.5.4.44", "X520.GenerationalQualifier"},
      {"2.5.4.46", "X520.DNQualifier"},
      {"2.5.4.5", "X520.SerialNumber"},
      {"2.5.4.6", "X520.Country"},
      {"2.5.4.65", "X520.Pseudonym"},
      {"2.5.4.7", "X520.Locality"},
      {"2.5.4.8", "X520.State"},
      {"2.5.4.9", "X520.StreetAddress"},
      {"2.5.8.1.1", "RSA"}};
}

std::unordered_map<std::string, OID> OID_Map::load_str2oid_map() {
   return std::unordered_map<std::string, OID>{

      {"AES-128/CBC", OID({2, 16, 840, 1, 101, 3, 4, 1, 2})},
      {"AES-128/CCM", OID({2, 16, 840, 1, 101, 3, 4, 1, 7})},
      {"AES-128/GCM", OID({2, 16, 840, 1, 101, 3, 4, 1, 6})},
      {"AES-128/OCB", OID({1, 3, 6, 1, 4, 1, 25258, 3, 2, 1})},
      {"AES-128/SIV", OID({1, 3, 6, 1, 4, 1, 25258, 3, 4, 1})},
      {"AES-192/CBC", OID({2, 16, 840, 1, 101, 3, 4, 1, 22})},
      {"AES-192/CCM", OID({2, 16, 840, 1, 101, 3, 4, 1, 27})},
      {"AES-192/GCM", OID({2, 16, 840, 1, 101, 3, 4, 1, 26})},
      {"AES-192/OCB", OID({1, 3, 6, 1, 4, 1, 25258, 3, 2, 2})},
      {"AES-192/SIV", OID({1, 3, 6, 1, 4, 1, 25258, 3, 4, 2})},
      {"AES-256/CBC", OID({2, 16, 840, 1, 101, 3, 4, 1, 42})},
      {"AES-256/CCM", OID({2, 16, 840, 1, 101, 3, 4, 1, 47})},
      {"AES-256/GCM", OID({2, 16, 840, 1, 101, 3, 4, 1, 46})},
      {"AES-256/OCB", OID({1, 3, 6, 1, 4, 1, 25258, 3, 2, 3})},
      {"AES-256/SIV", OID({1, 3, 6, 1, 4, 1, 25258, 3, 4, 3})},
      {"CAST-128/CBC", OID({1, 2, 840, 113533, 7, 66, 10})},
      {"Camellia-128/CBC", OID({1, 2, 392, 200011, 61, 1, 1, 1, 2})},
      {"Camellia-128/GCM", OID({0, 3, 4401, 5, 3, 1, 9, 6})},
      {"Camellia-128/OCB", OID({1, 3, 6, 1, 4, 1, 25258, 3, 2, 6})},
      {"Camellia-128/SIV", OID({1, 3, 6, 1, 4, 1, 25258, 3, 4, 6})},
      {"Camellia-192/CBC", OID({1, 2, 392, 200011, 61, 1, 1, 1, 3})},
      {"Camellia-192/GCM", OID({0, 3, 4401, 5, 3, 1, 9, 26})},
      {"Camellia-192/OCB", OID({1, 3, 6, 1, 4, 1, 25258, 3, 2, 7})},
      {"Camellia-192/SIV", OID({1, 3, 6, 1, 4, 1, 25258, 3, 4, 7})},
      {"Camellia-256/CBC", OID({1, 2, 392, 200011, 61, 1, 1, 1, 4})},
      {"Camellia-256/GCM", OID({0, 3, 4401, 5, 3, 1, 9, 46})},
      {"Camellia-256/OCB", OID({1, 3, 6, 1, 4, 1, 25258, 3, 2, 8})},
      {"Camellia-256/SIV", OID({1, 3, 6, 1, 4, 1, 25258, 3, 4, 8})},
      {"Certificate Comment", OID({2, 16, 840, 1, 113730, 1, 13})},
      {"ChaCha20Poly1305", OID({1, 2, 840, 113549, 1, 9, 16, 3, 18})},
      {"Compression.Zlib", OID({1, 2, 840, 113549, 1, 9, 16, 3, 8})},
      {"Curve25519", OID({1, 3, 101, 110})},
      {"DES/CBC", OID({1, 3, 14, 3, 2, 7})},
      {"DH", OID({1, 2, 840, 10046, 2, 1})},
      {"DSA", OID({1, 2, 840, 10040, 4, 1})},
      {"DSA/SHA-1", OID({1, 2, 840, 10040, 4, 3})},
      {"DSA/SHA-224", OID({2, 16, 840, 1, 101, 3, 4, 3, 1})},
      {"DSA/SHA-256", OID({2, 16, 840, 1, 101, 3, 4, 3, 2})},
      {"DSA/SHA-3(224)", OID({2, 16, 840, 1, 101, 3, 4, 3, 5})},
      {"DSA/SHA-3(256)", OID({2, 16, 840, 1, 101, 3, 4, 3, 6})},
      {"DSA/SHA-3(384)", OID({2, 16, 840, 1, 101, 3, 4, 3, 7})},
      {"DSA/SHA-3(512)", OID({2, 16, 840, 1, 101, 3, 4, 3, 8})},
      {"DSA/SHA-384", OID({2, 16, 840, 1, 101, 3, 4, 3, 3})},
      {"DSA/SHA-512", OID({2, 16, 840, 1, 101, 3, 4, 3, 4})},
      {"Dilithium-4x4-AES-r3", OID({1, 3, 6, 1, 4, 1, 25258, 1, 10, 1})},
      {"Dilithium-4x4-r3", OID({1, 3, 6, 1, 4, 1, 25258, 1, 9, 1})},
      {"Dilithium-6x5-AES-r3", OID({1, 3, 6, 1, 4, 1, 25258, 1, 10, 2})},
      {"Dilithium-6x5-r3", OID({1, 3, 6, 1, 4, 1, 25258, 1, 9, 2})},
      {"Dilithium-8x7-AES-r3", OID({1, 3, 6, 1, 4, 1, 25258, 1, 10, 3})},
      {"Dilithium-8x7-r3", OID({1, 3, 6, 1, 4, 1, 25258, 1, 9, 3})},
      {"ECDH", OID({1, 3, 132, 1, 12})},
      {"ECDSA", OID({1, 2, 840, 10045, 2, 1})},
      {"ECDSA/SHA-1", OID({1, 2, 840, 10045, 4, 1})},
      {"ECDSA/SHA-224", OID({1, 2, 840, 10045, 4, 3, 1})},
      {"ECDSA/SHA-256", OID({1, 2, 840, 10045, 4, 3, 2})},
      {"ECDSA/SHA-3(224)", OID({2, 16, 840, 1, 101, 3, 4, 3, 9})},
      {"ECDSA/SHA-3(256)", OID({2, 16, 840, 1, 101, 3, 4, 3, 10})},
      {"ECDSA/SHA-3(384)", OID({2, 16, 840, 1, 101, 3, 4, 3, 11})},
      {"ECDSA/SHA-3(512)", OID({2, 16, 840, 1, 101, 3, 4, 3, 12})},
      {"ECDSA/SHA-384", OID({1, 2, 840, 10045, 4, 3, 3})},
      {"ECDSA/SHA-512", OID({1, 2, 840, 10045, 4, 3, 4})},
      {"ECGDSA", OID({1, 3, 36, 3, 3, 2, 5, 2, 1})},
      {"ECGDSA/RIPEMD-160", OID({1, 3, 36, 3, 3, 2, 5, 4, 1})},
      {"ECGDSA/SHA-1", OID({1, 3, 36, 3, 3, 2, 5, 4, 2})},
      {"ECGDSA/SHA-224", OID({1, 3, 36, 3, 3, 2, 5, 4, 3})},
      {"ECGDSA/SHA-256", OID({1, 3, 36, 3, 3, 2, 5, 4, 4})},
      {"ECGDSA/SHA-384", OID({1, 3, 36, 3, 3, 2, 5, 4, 5})},
      {"ECGDSA/SHA-512", OID({1, 3, 36, 3, 3, 2, 5, 4, 6})},
      {"ECKCDSA", OID({1, 0, 14888, 3, 0, 5})},
      {"ECKCDSA/SHA-1", OID({1, 2, 410, 200004, 1, 100, 4, 3})},
      {"ECKCDSA/SHA-224", OID({1, 2, 410, 200004, 1, 100, 4, 4})},
      {"ECKCDSA/SHA-256", OID({1, 2, 410, 200004, 1, 100, 4, 5})},
      {"Ed25519", OID({1, 3, 101, 112})},
      {"Ed448", OID({1, 3, 101, 113})},
      {"ElGamal", OID({1, 3, 6, 1, 4, 1, 3029, 1, 2, 1})},
      {"FrodoKEM-1344-AES", OID({1, 3, 6, 1, 4, 1, 25258, 1, 15, 3})},
      {"FrodoKEM-1344-SHAKE", OID({1, 3, 6, 1, 4, 1, 25258, 1, 14, 3})},
      {"FrodoKEM-640-AES", OID({1, 3, 6, 1, 4, 1, 25258, 1, 15, 1})},
      {"FrodoKEM-640-SHAKE", OID({1, 3, 6, 1, 4, 1, 25258, 1, 14, 1})},
      {"FrodoKEM-976-AES", OID({1, 3, 6, 1, 4, 1, 25258, 1, 15, 2})},
      {"FrodoKEM-976-SHAKE", OID({1, 3, 6, 1, 4, 1, 25258, 1, 14, 2})},
      {"GOST-34.10", OID({1, 2, 643, 2, 2, 19})},
      {"GOST-34.10-2012-256", OID({1, 2, 643, 7, 1, 1, 1, 1})},
      {"GOST-34.10-2012-256/SHA-256", OID({1, 3, 6, 1, 4, 1, 25258, 1, 6, 1})},
      {"GOST-34.10-2012-256/Streebog-256", OID({1, 2, 643, 7, 1, 1, 3, 2})},
      {"GOST-34.10-2012-512", OID({1, 2, 643, 7, 1, 1, 1, 2})},
      {"GOST-34.10-2012-512/Streebog-512", OID({1, 2, 643, 7, 1, 1, 3, 3})},
      {"GOST-34.10/GOST-R-34.11-94", OID({1, 2, 643, 2, 2, 3})},
      {"GOST.INN", OID({1, 2, 643, 3, 131, 1, 1})},
      {"GOST.IssuerSigningTool", OID({1, 2, 643, 100, 112})},
      {"GOST.OGRN", OID({1, 2, 643, 100, 1})},
      {"GOST.SubjectSigningTool", OID({1, 2, 643, 100, 111})},
      {"HMAC(SHA-1)", OID({1, 2, 840, 113549, 2, 7})},
      {"HMAC(SHA-224)", OID({1, 2, 840, 113549, 2, 8})},
      {"HMAC(SHA-256)", OID({1, 2, 840, 113549, 2, 9})},
      {"HMAC(SHA-384)", OID({1, 2, 840, 113549, 2, 10})},
      {"HMAC(SHA-512)", OID({1, 2, 840, 113549, 2, 11})},
      {"HMAC(SHA-512-256)", OID({1, 2, 840, 113549, 2, 13})},
      {"HSS-LMS", OID({1, 2, 840, 113549, 1, 9, 16, 3, 17})},
      {"HSS-LMS-Private-Key", OID({1, 3, 6, 1, 4, 1, 25258, 1, 13})},
      {"KeyWrap.AES-128", OID({2, 16, 840, 1, 101, 3, 4, 1, 5})},
      {"KeyWrap.AES-192", OID({2, 16, 840, 1, 101, 3, 4, 1, 25})},
      {"KeyWrap.AES-256", OID({2, 16, 840, 1, 101, 3, 4, 1, 45})},
      {"KeyWrap.CAST-128", OID({1, 2, 840, 113533, 7, 66, 15})},
      {"KeyWrap.TripleDES", OID({1, 2, 840, 113549, 1, 9, 16, 3, 6})},
      {"Kyber-1024-90s-r3", OID({1, 3, 6, 1, 4, 1, 25258, 1, 11, 3})},
      {"Kyber-1024-r3", OID({1, 3, 6, 1, 4, 1, 25258, 1, 7, 3})},
      {"Kyber-512-90s-r3", OID({1, 3, 6, 1, 4, 1, 25258, 1, 11, 1})},
      {"Kyber-512-r3", OID({1, 3, 6, 1, 4, 1, 25258, 1, 7, 1})},
      {"Kyber-768-90s-r3", OID({1, 3, 6, 1, 4, 1, 25258, 1, 11, 2})},
      {"Kyber-768-r3", OID({1, 3, 6, 1, 4, 1, 25258, 1, 7, 2})},
      {"MD5", OID({1, 2, 840, 113549, 2, 5})},
      {"MGF1", OID({1, 2, 840, 113549, 1, 1, 8})},
      {"ML-DSA-4x4", OID({2, 16, 840, 1, 101, 3, 4, 3, 17})},
      {"ML-DSA-6x5", OID({2, 16, 840, 1, 101, 3, 4, 3, 18})},
      {"ML-DSA-8x7", OID({2, 16, 840, 1, 101, 3, 4, 3, 19})},
      {"ML-KEM-1024", OID({2, 16, 840, 1, 101, 3, 4, 4, 3})},
      {"ML-KEM-512", OID({2, 16, 840, 1, 101, 3, 4, 4, 1})},
      {"ML-KEM-768", OID({2, 16, 840, 1, 101, 3, 4, 4, 2})},
      {"McEliece", OID({1, 3, 6, 1, 4, 1, 25258, 1, 3})},
      {"Microsoft SmartcardLogon", OID({1, 3, 6, 1, 4, 1, 311, 20, 2, 2})},
      {"Microsoft UPN", OID({1, 3, 6, 1, 4, 1, 311, 20, 2, 3})},
      {"OpenPGP.Curve25519", OID({1, 3, 6, 1, 4, 1, 3029, 1, 5, 1})},
      {"OpenPGP.Ed25519", OID({1, 3, 6, 1, 4, 1, 11591, 15, 1})},
      {"PBE-PKCS5v20", OID({1, 2, 840, 113549, 1, 5, 13})},
      {"PBES2", OID({1, 2, 840, 113549, 1, 5, 13})},
      {"PKCS5.PBKDF2", OID({1, 2, 840, 113549, 1, 5, 12})},
      {"PKCS9.ChallengePassword", OID({1, 2, 840, 113549, 1, 9, 7})},
      {"PKCS9.ContentType", OID({1, 2, 840, 113549, 1, 9, 3})},
      {"PKCS9.EmailAddress", OID({1, 2, 840, 113549, 1, 9, 1})},
      {"PKCS9.ExtensionRequest", OID({1, 2, 840, 113549, 1, 9, 14})},
      {"PKCS9.MessageDigest", OID({1, 2, 840, 113549, 1, 9, 4})},
      {"PKCS9.UnstructuredName", OID({1, 2, 840, 113549, 1, 9, 2})},
      {"PKIX.AuthorityInformationAccess", OID({1, 3, 6, 1, 5, 5, 7, 1, 1})},
      {"PKIX.CertificateAuthorityIssuers", OID({1, 3, 6, 1, 5, 5, 7, 48, 2})},
      {"PKIX.ClientAuth", OID({1, 3, 6, 1, 5, 5, 7, 3, 2})},
      {"PKIX.CodeSigning", OID({1, 3, 6, 1, 5, 5, 7, 3, 3})},
      {"PKIX.EmailProtection", OID({1, 3, 6, 1, 5, 5, 7, 3, 4})},
      {"PKIX.IPsecEndSystem", OID({1, 3, 6, 1, 5, 5, 7, 3, 5})},
      {"PKIX.IPsecTunnel", OID({1, 3, 6, 1, 5, 5, 7, 3, 6})},
      {"PKIX.IPsecUser", OID({1, 3, 6, 1, 5, 5, 7, 3, 7})},
      {"PKIX.OCSP", OID({1, 3, 6, 1, 5, 5, 7, 48, 1})},
      {"PKIX.OCSP.BasicResponse", OID({1, 3, 6, 1, 5, 5, 7, 48, 1, 1})},
      {"PKIX.OCSP.NoCheck", OID({1, 3, 6, 1, 5, 5, 7, 48, 1, 5})},
      {"PKIX.OCSPSigning", OID({1, 3, 6, 1, 5, 5, 7, 3, 9})},
      {"PKIX.ServerAuth", OID({1, 3, 6, 1, 5, 5, 7, 3, 1})},
      {"PKIX.TNAuthList", OID({1, 3, 6, 1, 5, 5, 7, 1, 26})},
      {"PKIX.TimeStamping", OID({1, 3, 6, 1, 5, 5, 7, 3, 8})},
      {"PKIX.XMPPAddr", OID({1, 3, 6, 1, 5, 5, 7, 8, 5})},
      {"RIPEMD-160", OID({1, 3, 36, 3, 2, 1})},
      {"RSA", OID({1, 2, 840, 113549, 1, 1, 1})},
      {"RSA/EMSA3(MD2)", OID({1, 2, 840, 113549, 1, 1, 2})},
      {"RSA/EMSA3(MD5)", OID({1, 2, 840, 113549, 1, 1, 4})},
      {"RSA/EMSA3(RIPEMD-160)", OID({1, 3, 36, 3, 3, 1, 2})},
      {"RSA/EMSA3(SHA-1)", OID({1, 2, 840, 113549, 1, 1, 5})},
      {"RSA/EMSA3(SHA-224)", OID({1, 2, 840, 113549, 1, 1, 14})},
      {"RSA/EMSA3(SHA-256)", OID({1, 2, 840, 113549, 1, 1, 11})},
      {"RSA/EMSA3(SHA-3(224))", OID({2, 16, 840, 1, 101, 3, 4, 3, 13})},
      {"RSA/EMSA3(SHA-3(256))", OID({2, 16, 840, 1, 101, 3, 4, 3, 14})},
      {"RSA/EMSA3(SHA-3(384))", OID({2, 16, 840, 1, 101, 3, 4, 3, 15})},
      {"RSA/EMSA3(SHA-3(512))", OID({2, 16, 840, 1, 101, 3, 4, 3, 16})},
      {"RSA/EMSA3(SHA-384)", OID({1, 2, 840, 113549, 1, 1, 12})},
      {"RSA/EMSA3(SHA-512)", OID({1, 2, 840, 113549, 1, 1, 13})},
      {"RSA/EMSA3(SHA-512-256)", OID({1, 2, 840, 113549, 1, 1, 16})},
      {"RSA/EMSA3(SM3)", OID({1, 2, 156, 10197, 1, 504})},
      {"RSA/EMSA4", OID({1, 2, 840, 113549, 1, 1, 10})},
      {"RSA/OAEP", OID({1, 2, 840, 113549, 1, 1, 7})},
      {"SEED/CBC", OID({1, 2, 410, 200004, 1, 4})},
      {"SHA-1", OID({1, 3, 14, 3, 2, 26})},
      {"SHA-224", OID({2, 16, 840, 1, 101, 3, 4, 2, 4})},
      {"SHA-256", OID({2, 16, 840, 1, 101, 3, 4, 2, 1})},
      {"SHA-3(224)", OID({2, 16, 840, 1, 101, 3, 4, 2, 7})},
      {"SHA-3(256)", OID({2, 16, 840, 1, 101, 3, 4, 2, 8})},
      {"SHA-3(384)", OID({2, 16, 840, 1, 101, 3, 4, 2, 9})},
      {"SHA-3(512)", OID({2, 16, 840, 1, 101, 3, 4, 2, 10})},
      {"SHA-384", OID({2, 16, 840, 1, 101, 3, 4, 2, 2})},
      {"SHA-512", OID({2, 16, 840, 1, 101, 3, 4, 2, 3})},
      {"SHA-512-256", OID({2, 16, 840, 1, 101, 3, 4, 2, 6})},
      {"SHAKE-128", OID({2, 16, 840, 1, 101, 3, 4, 2, 11})},
      {"SHAKE-256", OID({2, 16, 840, 1, 101, 3, 4, 2, 12})},
      {"SLH-DSA-SHA2-128f", OID({2, 16, 840, 1, 101, 3, 4, 3, 21})},
      {"SLH-DSA-SHA2-128s", OID({2, 16, 840, 1, 101, 3, 4, 3, 20})},
      {"SLH-DSA-SHA2-192f", OID({2, 16, 840, 1, 101, 3, 4, 3, 23})},
      {"SLH-DSA-SHA2-192s", OID({2, 16, 840, 1, 101, 3, 4, 3, 22})},
      {"SLH-DSA-SHA2-256f", OID({2, 16, 840, 1, 101, 3, 4, 3, 25})},
      {"SLH-DSA-SHA2-256s", OID({2, 16, 840, 1, 101, 3, 4, 3, 24})},
      {"SLH-DSA-SHAKE-128f", OID({2, 16, 840, 1, 101, 3, 4, 3, 27})},
      {"SLH-DSA-SHAKE-128s", OID({2, 16, 840, 1, 101, 3, 4, 3, 26})},
      {"SLH-DSA-SHAKE-192f", OID({2, 16, 840, 1, 101, 3, 4, 3, 29})},
      {"SLH-DSA-SHAKE-192s", OID({2, 16, 840, 1, 101, 3, 4, 3, 28})},
      {"SLH-DSA-SHAKE-256f", OID({2, 16, 840, 1, 101, 3, 4, 3, 31})},
      {"SLH-DSA-SHAKE-256s", OID({2, 16, 840, 1, 101, 3, 4, 3, 30})},
      {"SM2", OID({1, 2, 156, 10197, 1, 301, 1})},
      {"SM2_Enc", OID({1, 2, 156, 10197, 1, 301, 3})},
      {"SM2_Kex", OID({1, 2, 156, 10197, 1, 301, 2})},
      {"SM2_Sig", OID({1, 2, 156, 10197, 1, 301, 1})},
      {"SM2_Sig/SM3", OID({1, 2, 156, 10197, 1, 501})},
      {"SM3", OID({1, 2, 156, 10197, 1, 401})},
      {"SM4/CBC", OID({1, 2, 156, 10197, 1, 104, 2})},
      {"SM4/GCM", OID({1, 2, 156, 10197, 1, 104, 8})},
      {"SM4/OCB", OID({1, 2, 156, 10197, 1, 104, 100})},
      {"SM4/SIV", OID({1, 3, 6, 1, 4, 1, 25258, 3, 4, 9})},
      {"Scrypt", OID({1, 3, 6, 1, 4, 1, 11591, 4, 11})},
      {"Serpent/CBC", OID({1, 3, 6, 1, 4, 1, 25258, 3, 1})},
      {"Serpent/GCM", OID({1, 3, 6, 1, 4, 1, 25258, 3, 101})},
      {"Serpent/OCB", OID({1, 3, 6, 1, 4, 1, 25258, 3, 2, 4})},
      {"Serpent/SIV", OID({1, 3, 6, 1, 4, 1, 25258, 3, 4, 4})},
      {"SphincsPlus-haraka-128f-r3.1", OID({1, 3, 6, 1, 4, 1, 25258, 1, 12, 3, 2})},
      {"SphincsPlus-haraka-128s-r3.1", OID({1, 3, 6, 1, 4, 1, 25258, 1, 12, 3, 1})},
      {"SphincsPlus-haraka-192f-r3.1", OID({1, 3, 6, 1, 4, 1, 25258, 1, 12, 3, 4})},
      {"SphincsPlus-haraka-192s-r3.1", OID({1, 3, 6, 1, 4, 1, 25258, 1, 12, 3, 3})},
      {"SphincsPlus-haraka-256f-r3.1", OID({1, 3, 6, 1, 4, 1, 25258, 1, 12, 3, 6})},
      {"SphincsPlus-haraka-256s-r3.1", OID({1, 3, 6, 1, 4, 1, 25258, 1, 12, 3, 5})},
      {"SphincsPlus-sha2-128f-r3.1", OID({1, 3, 6, 1, 4, 1, 25258, 1, 12, 2, 2})},
      {"SphincsPlus-sha2-128s-r3.1", OID({1, 3, 6, 1, 4, 1, 25258, 1, 12, 2, 1})},
      {"SphincsPlus-sha2-192f-r3.1", OID({1, 3, 6, 1, 4, 1, 25258, 1, 12, 2, 4})},
      {"SphincsPlus-sha2-192s-r3.1", OID({1, 3, 6, 1, 4, 1, 25258, 1, 12, 2, 3})},
      {"SphincsPlus-sha2-256f-r3.1", OID({1, 3, 6, 1, 4, 1, 25258, 1, 12, 2, 6})},
      {"SphincsPlus-sha2-256s-r3.1", OID({1, 3, 6, 1, 4, 1, 25258, 1, 12, 2, 5})},
      {"SphincsPlus-shake-128f-r3.1", OID({1, 3, 6, 1, 4, 1, 25258, 1, 12, 1, 2})},
      {"SphincsPlus-shake-128s-r3.1", OID({1, 3, 6, 1, 4, 1, 25258, 1, 12, 1, 1})},
      {"SphincsPlus-shake-192f-r3.1", OID({1, 3, 6, 1, 4, 1, 25258, 1, 12, 1, 4})},
      {"SphincsPlus-shake-192s-r3.1", OID({1, 3, 6, 1, 4, 1, 25258, 1, 12, 1, 3})},
      {"SphincsPlus-shake-256f-r3.1", OID({1, 3, 6, 1, 4, 1, 25258, 1, 12, 1, 6})},
      {"SphincsPlus-shake-256s-r3.1", OID({1, 3, 6, 1, 4, 1, 25258, 1, 12, 1, 5})},
      {"Streebog-256", OID({1, 2, 643, 7, 1, 1, 2, 2})},
      {"Streebog-512", OID({1, 2, 643, 7, 1, 1, 2, 3})},
      {"Threefish-512/CBC", OID({1, 3, 6, 1, 4, 1, 25258, 3, 2})},
      {"TripleDES/CBC", OID({1, 2, 840, 113549, 3, 7})},
      {"Twofish/CBC", OID({1, 3, 6, 1, 4, 1, 25258, 3, 3})},
      {"Twofish/GCM", OID({1, 3, 6, 1, 4, 1, 25258, 3, 102})},
      {"Twofish/OCB", OID({1, 3, 6, 1, 4, 1, 25258, 3, 2, 5})},
      {"Twofish/SIV", OID({1, 3, 6, 1, 4, 1, 25258, 3, 4, 5})},
      {"X25519", OID({1, 3, 101, 110})},
      {"X448", OID({1, 3, 101, 111})},
      {"X509v3.AnyPolicy", OID({2, 5, 29, 32, 0})},
      {"X509v3.AuthorityKeyIdentifier", OID({2, 5, 29, 35})},
      {"X509v3.BasicConstraints", OID({2, 5, 29, 19})},
      {"X509v3.CRLDistributionPoints", OID({2, 5, 29, 31})},
      {"X509v3.CRLIssuingDistributionPoint", OID({2, 5, 29, 28})},
      {"X509v3.CRLNumber", OID({2, 5, 29, 20})},
      {"X509v3.CertificatePolicies", OID({2, 5, 29, 32})},
      {"X509v3.ExtendedKeyUsage", OID({2, 5, 29, 37})},
      {"X509v3.HoldInstructionCode", OID({2, 5, 29, 23})},
      {"X509v3.InvalidityDate", OID({2, 5, 29, 24})},
      {"X509v3.IssuerAlternativeName", OID({2, 5, 29, 18})},
      {"X509v3.KeyUsage", OID({2, 5, 29, 15})},
      {"X509v3.NameConstraints", OID({2, 5, 29, 30})},
      {"X509v3.PolicyConstraints", OID({2, 5, 29, 36})},
      {"X509v3.PrivateKeyUsagePeriod", OID({2, 5, 29, 16})},
      {"X509v3.ReasonCode", OID({2, 5, 29, 21})},
      {"X509v3.SubjectAlternativeName", OID({2, 5, 29, 17})},
      {"X509v3.SubjectKeyIdentifier", OID({2, 5, 29, 14})},
      {"X520.CommonName", OID({2, 5, 4, 3})},
      {"X520.Country", OID({2, 5, 4, 6})},
      {"X520.DNQualifier", OID({2, 5, 4, 46})},
      {"X520.GenerationalQualifier", OID({2, 5, 4, 44})},
      {"X520.GivenName", OID({2, 5, 4, 42})},
      {"X520.Initials", OID({2, 5, 4, 43})},
      {"X520.Locality", OID({2, 5, 4, 7})},
      {"X520.Organization", OID({2, 5, 4, 10})},
      {"X520.OrganizationalUnit", OID({2, 5, 4, 11})},
      {"X520.Pseudonym", OID({2, 5, 4, 65})},
      {"X520.SerialNumber", OID({2, 5, 4, 5})},
      {"X520.State", OID({2, 5, 4, 8})},
      {"X520.StreetAddress", OID({2, 5, 4, 9})},
      {"X520.Surname", OID({2, 5, 4, 4})},
      {"X520.Title", OID({2, 5, 4, 12})},
      {"XMSS", OID({0, 4, 0, 127, 0, 15, 1, 1, 13, 0})},
      {"XMSS-draft12", OID({1, 3, 6, 1, 4, 1, 25258, 1, 8})},
      {"XMSS-draft6", OID({1, 3, 6, 1, 4, 1, 25258, 1, 5})},
      {"brainpool160r1", OID({1, 3, 36, 3, 3, 2, 8, 1, 1, 1})},
      {"brainpool192r1", OID({1, 3, 36, 3, 3, 2, 8, 1, 1, 3})},
      {"brainpool224r1", OID({1, 3, 36, 3, 3, 2, 8, 1, 1, 5})},
      {"brainpool256r1", OID({1, 3, 36, 3, 3, 2, 8, 1, 1, 7})},
      {"brainpool320r1", OID({1, 3, 36, 3, 3, 2, 8, 1, 1, 9})},
      {"brainpool384r1", OID({1, 3, 36, 3, 3, 2, 8, 1, 1, 11})},
      {"brainpool512r1", OID({1, 3, 36, 3, 3, 2, 8, 1, 1, 13})},
      {"eFrodoKEM-1344-AES", OID({1, 3, 6, 1, 4, 1, 25258, 1, 17, 3})},
      {"eFrodoKEM-1344-SHAKE", OID({1, 3, 6, 1, 4, 1, 25258, 1, 16, 3})},
      {"eFrodoKEM-640-AES", OID({1, 3, 6, 1, 4, 1, 25258, 1, 17, 1})},
      {"eFrodoKEM-640-SHAKE", OID({1, 3, 6, 1, 4, 1, 25258, 1, 16, 1})},
      {"eFrodoKEM-976-AES", OID({1, 3, 6, 1, 4, 1, 25258, 1, 17, 2})},
      {"eFrodoKEM-976-SHAKE", OID({1, 3, 6, 1, 4, 1, 25258, 1, 16, 2})},
      {"frp256v1", OID({1, 2, 250, 1, 223, 101, 256, 1})},
      {"gost_256A", OID({1, 2, 643, 7, 1, 2, 1, 1, 1})},
      {"gost_256B", OID({1, 2, 643, 7, 1, 2, 1, 1, 2})},
      {"gost_512A", OID({1, 2, 643, 7, 1, 2, 1, 2, 1})},
      {"gost_512B", OID({1, 2, 643, 7, 1, 2, 1, 2, 2})},
      {"numsp256d1", OID({1, 3, 6, 1, 4, 1, 25258, 4, 1})},
      {"numsp384d1", OID({1, 3, 6, 1, 4, 1, 25258, 4, 2})},
      {"numsp512d1", OID({1, 3, 6, 1, 4, 1, 25258, 4, 3})},
      {"secp160k1", OID({1, 3, 132, 0, 9})},
      {"secp160r1", OID({1, 3, 132, 0, 8})},
      {"secp160r2", OID({1, 3, 132, 0, 30})},
      {"secp192k1", OID({1, 3, 132, 0, 31})},
      {"secp192r1", OID({1, 2, 840, 10045, 3, 1, 1})},
      {"secp224k1", OID({1, 3, 132, 0, 32})},
      {"secp224r1", OID({1, 3, 132, 0, 33})},
      {"secp256k1", OID({1, 3, 132, 0, 10})},
      {"secp256r1", OID({1, 2, 840, 10045, 3, 1, 7})},
      {"secp384r1", OID({1, 3, 132, 0, 34})},
      {"secp521r1", OID({1, 3, 132, 0, 35})},
      {"sm2p256v1", OID({1, 2, 156, 10197, 1, 301})},
      {"x962_p192v2", OID({1, 2, 840, 10045, 3, 1, 2})},
      {"x962_p192v3", OID({1, 2, 840, 10045, 3, 1, 3})},
      {"x962_p239v1", OID({1, 2, 840, 10045, 3, 1, 4})},
      {"x962_p239v2", OID({1, 2, 840, 10045, 3, 1, 5})},
      {"x962_p239v3", OID({1, 2, 840, 10045, 3, 1, 6})}};
}

}  // namespace Botan
