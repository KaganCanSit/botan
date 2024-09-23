/*
* (C) 2023 Jack Lloyd
*     2023 Fabian Albert, René Meusel, Amos Treiber - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "test_rng.h"
#include "tests.h"

#if(defined(BOTAN_HAS_SPHINCS_PLUS_WITH_SHA2) || defined(BOTAN_HAS_SPHINCS_PLUS_WITH_SHAKE)) && defined(BOTAN_HAS_AES)

   #include <botan/assert.h>
   #include <botan/hash.h>
   #include <botan/pk_algs.h>
   #include <botan/pubkey.h>
   #include <botan/secmem.h>
   #include <botan/sp_parameters.h>
   #include <botan/sphincsplus.h>
   #include <botan/internal/loadstor.h>
   #include <botan/internal/sp_hash.h>

   #include "test_pubkey.h"

namespace Botan_Tests {

/**
 * Test all implemented SPHINCS+ instances using the data of the KAT files
 * generated by the reference implementation (Round 3.1
 *  (https://github.com/sphincs/sphincsplus/))
 */
class SPHINCS_Plus_Test final : public Text_Based_Test {
   public:
      SPHINCS_Plus_Test() : Text_Based_Test("pubkey/sphincsplus.vec", "SphincsParameterSet,seed,pk,sk,msg,HashSig") {}

      bool skip_this_test(const std::string&, const VarMap& vars) override {
         auto params = Botan::Sphincs_Parameters::create(vars.get_req_str("SphincsParameterSet"));

   #if not defined(BOTAN_HAS_SPHINCS_PLUS_WITH_SHAKE)
         if(params.hash_type() == Botan::Sphincs_Hash_Type::Shake256) {
            return true;
         }
   #endif

   #if not defined(BOTAN_HAS_SPHINCS_PLUS_WITH_SHA2)
         if(params.hash_type() == Botan::Sphincs_Hash_Type::Sha256) {
            return true;
         }
   #endif

         // Execute the small (slow) instances only with --run-long-tests
         switch(params.parameter_set()) {
            case Botan::Sphincs_Parameter_Set::Sphincs128Fast:
            case Botan::Sphincs_Parameter_Set::Sphincs192Fast:
            case Botan::Sphincs_Parameter_Set::Sphincs256Fast:
            case Botan::Sphincs_Parameter_Set::SLHDSA128Fast:
            case Botan::Sphincs_Parameter_Set::SLHDSA192Fast:
            case Botan::Sphincs_Parameter_Set::SLHDSA256Fast:
               return false;
            case Botan::Sphincs_Parameter_Set::Sphincs128Small:
            case Botan::Sphincs_Parameter_Set::Sphincs192Small:
            case Botan::Sphincs_Parameter_Set::Sphincs256Small:
            case Botan::Sphincs_Parameter_Set::SLHDSA128Small:
            case Botan::Sphincs_Parameter_Set::SLHDSA192Small:
            case Botan::Sphincs_Parameter_Set::SLHDSA256Small:
               return !Test::run_long_tests();
         }
         BOTAN_ASSERT_UNREACHABLE();
      }

      Test::Result run_one_test(const std::string&, const VarMap& vars) final {
         Test::Result result("SPHINCS+ ");

         auto params = Botan::Sphincs_Parameters::create(vars.get_req_str("SphincsParameterSet"));

         const std::vector<uint8_t> seed_ref = vars.get_req_bin("seed");
         const std::vector<uint8_t> msg_ref = vars.get_req_bin("msg");
         const std::vector<uint8_t> pk_ref = vars.get_req_bin("pk");
         const std::vector<uint8_t> sk_ref = vars.get_req_bin("sk");
         const std::vector<uint8_t> sig_hash = vars.get_req_bin("HashSig");

         // Depending on the SPHINCS+ configuration the resulting signature is
         // hashed either with SHA-3 or SHA-256 to reduce the inner dependencies
         // on other hash function modules.
         auto hash_algo_spec = [&]() -> std::string {
            if(params.hash_type() == Botan::Sphincs_Hash_Type::Shake256) {
               return "SHA-3(256)";
            } else {
               return "SHA-256";
            }
         }();
         auto hash = Botan::HashFunction::create(hash_algo_spec);

         /*
          * To get sk_seed || sk_prf || pk_seed and opt_rand from the given seed
          * (from KAT), we create a CTR_DRBG_AES256 rng and "simulate" the
          * invocation-pattern in the reference. We feed the created randomness
          * to the fixed output rng, to allow for our (slightly different)
          * invocation-pattern.
          */
         auto kat_rng = CTR_DRBG_AES256(seed_ref);
         Fixed_Output_RNG fixed_rng;
         fixed_rng.add_entropy(kat_rng.random_vec<std::vector<uint8_t>>(3 * params.n()));

         // push the entropy used for signing twice, as we want to perform two
         // signing operations
         const auto entropy_for_signing = kat_rng.random_vec<std::vector<uint8_t>>(1 * params.n());
         fixed_rng.add_entropy(entropy_for_signing);
         fixed_rng.add_entropy(entropy_for_signing);

         // Generate Keypair
         Botan::SphincsPlus_PrivateKey priv_key(fixed_rng, params);

         result.test_is_eq("public key bits", priv_key.public_key_bits(), pk_ref);
         result.test_is_eq("private key bits", unlock(priv_key.private_key_bits()), sk_ref);

         // Signature with generated Keypair
         auto signer = Botan::PK_Signer(priv_key, fixed_rng, "Randomized");  // TODO: No KAT for 'deterministic'?
         auto signature = signer.sign_message(msg_ref.data(), msg_ref.size(), fixed_rng);

         result.test_is_eq("signature creation", unlock(hash->process(signature)), sig_hash);

         // Verification with generated Keypair
         Botan::PK_Verifier verifier(*priv_key.public_key(), params.algorithm_identifier());
         bool verify_success =
            verifier.verify_message(msg_ref.data(), msg_ref.size(), signature.data(), signature.size());
         result.confirm("verification of valid signature", verify_success);

         // Run additional parsing and re-verification tests on one parameter
         // set only to save test runtime. Given the current test vector we will
         // run this exactly once per hash function.
         if(params.parameter_set() == Botan::Sphincs_Parameter_Set::Sphincs128Fast) {
            // Deserialization of Keypair from test vector
            Botan::SphincsPlus_PrivateKey deserialized_priv_key(sk_ref, params);
            Botan::SphincsPlus_PublicKey deserialized_pub_key(pk_ref, params);

            // Signature with deserialized Keypair
            auto deserialized_signer = Botan::PK_Signer(deserialized_priv_key, fixed_rng, "Randomized");
            auto deserialized_signature = deserialized_signer.sign_message(msg_ref.data(), msg_ref.size(), fixed_rng);

            result.test_is_eq(
               "signature creation after deserialization", unlock(hash->process(deserialized_signature)), sig_hash);

            // Verification with deserialized Keypair
            Botan::PK_Verifier deserialized_verifier(deserialized_pub_key, params.algorithm_identifier());
            bool verify_success_deserialized =
               deserialized_verifier.verify_message(msg_ref.data(), msg_ref.size(), signature.data(), signature.size());
            result.confirm("verification of valid signature after deserialization", verify_success_deserialized);

            // Verification of invalid signature
            auto broken_sig = Test::mutate_vec(deserialized_signature, this->rng());
            bool verify_fail = deserialized_verifier.verify_message(
               msg_ref.data(), msg_ref.size(), broken_sig.data(), broken_sig.size());
            result.confirm("verification of invalid signature", !verify_fail);

            bool verify_success_after_fail =
               deserialized_verifier.verify_message(msg_ref.data(), msg_ref.size(), signature.data(), signature.size());
            result.confirm("verification of valid signature after broken signature", verify_success_after_fail);
         }

         return result;
      }
};

class SPHINCS_Plus_Keygen_Tests final : public PK_Key_Generation_Test {
   public:
      std::vector<std::string> keygen_params() const override {
         // clang-format off
         return {
   #if defined(BOTAN_HAS_SPHINCS_PLUS_WITH_SHAKE)
            "SphincsPlus-shake-128s-r3.1",
            "SphincsPlus-shake-128f-r3.1",
            "SphincsPlus-shake-192s-r3.1",
            "SphincsPlus-shake-192f-r3.1",
            "SphincsPlus-shake-256s-r3.1",
            "SphincsPlus-shake-256f-r3.1",
   #endif
   #if defined(BOTAN_HAS_SPHINCS_PLUS_WITH_SHA2)
            "SphincsPlus-sha2-128s-r3.1",
            "SphincsPlus-sha2-128f-r3.1",
            "SphincsPlus-sha2-192s-r3.1",
            "SphincsPlus-sha2-192f-r3.1",
            "SphincsPlus-sha2-256s-r3.1",
            "SphincsPlus-sha2-256f-r3.1",
   #endif
         };
         // clang-format on
      }

      std::string algo_name() const override { return "SPHINCS+"; }

      std::unique_ptr<Botan::Public_Key> public_key_from_raw(std::string_view keygen_params,
                                                             std::string_view /* provider */,
                                                             std::span<const uint8_t> raw_pk) const override {
         return std::make_unique<Botan::SphincsPlus_PublicKey>(raw_pk,
                                                               Botan::Sphincs_Parameters::create(keygen_params));
      }
};

BOTAN_REGISTER_TEST("pubkey", "sphincsplus", SPHINCS_Plus_Test);
BOTAN_REGISTER_TEST("pubkey", "sphincsplus_keygen", SPHINCS_Plus_Keygen_Tests);

}  // namespace Botan_Tests

#endif  // BOTAN_HAS_SPHINCS_PLUS
