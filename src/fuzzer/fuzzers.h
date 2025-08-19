/*
* (C) 2015,2016,2017 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_FUZZER_DRIVER_H_
#define BOTAN_FUZZER_DRIVER_H_

#include <botan/chacha_rng.h>
#include <botan/exceptn.h>
#include <botan/internal/target_info.h>
#include <fstream>
#include <iostream>
#include <source_location>
#include <stdint.h>
#include <stdlib.h>  // for setenv
#include <vector>

static constexpr size_t max_fuzzer_input_size = 8192;

extern void fuzz(std::span<const uint8_t> in);

// Need to declare these before defining them;
extern "C" int LLVMFuzzerInitialize(int* argc, char*** argv);
extern "C" int LLVMFuzzerTestOneInput(const uint8_t in[], size_t len);

// NOLINTNEXTLINE(*-definitions-in-headers)
extern "C" int LLVMFuzzerInitialize(int* /*argc*/, char*** /*argv*/) {
   /*
   * This disables the mlock pool, as overwrites within the pool are
   * opaque to ASan or other instrumentation.
   */
   ::setenv("BOTAN_MLOCK_POOL_SIZE", "0", 1);
   return 0;
}

// Called by main() in libFuzzer or in main for AFL below
// NOLINTNEXTLINE(*-definitions-in-headers)
extern "C" int LLVMFuzzerTestOneInput(const uint8_t in[], size_t len) {
   if(len <= max_fuzzer_input_size) {
      try {
         fuzz(std::span<const uint8_t>(in, len));
      } catch(std::exception& e) {
         std::cerr << "Uncaught exception from fuzzer driver " << e.what() << "\n";
         abort();
      } catch(...) {
         std::cerr << "Uncaught exception from fuzzer driver (unknown type)\n";
         abort();
      }
   }
   return 0;
}

// Some helpers for the fuzzer jigs

inline std::shared_ptr<Botan::RandomNumberGenerator> fuzzer_rng_as_shared() {
   static std::shared_ptr<Botan::ChaCha_RNG> rng =
      std::make_shared<Botan::ChaCha_RNG>(Botan::secure_vector<uint8_t>(32));
   return rng;
}

inline Botan::RandomNumberGenerator& fuzzer_rng() {
   return *fuzzer_rng_as_shared();
}

inline void FUZZER_WRITE_AND_CRASH(const std::string_view expr_str,
                                   const std::source_location& loc = std::source_location::current()) noexcept {
   std::cerr << expr_str << " @ Line " << loc.line() << " in " << loc.file_name() << "\n";
   std::cerr.flush();
   std::abort();
}

// TODO: Macro require until C++ gains reflection capabilities (possibly C++26)
template <typename T, typename Y, std::size_t x_str_size, std::size_t y_str_size>
inline void fuzzer_assert_equal_impl(const T& x,
                                     const Y& y,
                                     const char (&x_str)[x_str_size],  // Compile-time size, zero strlen
                                     const char (&y_str)[y_str_size],  // Compile-time size, zero strlen
                                     const std::source_location& loc = std::source_location::current()) noexcept {
   if(x != y) {
      std::cerr << std::string_view{x_str, x_str_size - 1} << " = " << x
                << " != " << std::string_view{y_str, y_str_size - 1} << " = " << y << " @ Line " << loc.line() << " in "
                << loc.file_name() << "\n";
      std::cerr.flush();
      std::abort();
   }
}

#define FUZZER_ASSERT_EQUAL(x, y) fuzzer_assert_equal_impl(x, y, #x, #y, std::source_location::current());

// TODO: Macro require until C++ gains reflection capabilities (possibly C++26)
template <typename T, std::size_t expr_str_size>
inline void fuzzer_assert_true_impl(const T& condition,
                                    const char(&expr_str){expr_str_size},  // Compile-time size, zero strlen
                                    const std::source_location& loc = std::source_location::current()) noexcept {
   if(!condition) {
      std::cerr << "Expression " << std::string_view{expr_str, expr_str_size - 1} << " was false @ Line " << loc.line()
                << " in " << loc.file_name() << "\n";
      std::cerr.flush();
      std::abort();
   }
}

#define FUZZER_ASSERT_TRUE(e) fuzzer_assert_true_impl(e, #e, std::source_location::current());

#if defined(BOTAN_FUZZER_IS_TEST)

inline int fuzz_files(char* files[]) {
   for(size_t i = 0; files[i] != nullptr; ++i) {
      std::ifstream in(files[i]);

      if(in.good()) {
         std::vector<uint8_t> buf(max_fuzzer_input_size);
         in.read(reinterpret_cast<char*>(buf.data()), static_cast<std::streamsize>(buf.size()));
         const size_t got = in.gcount();
         buf.resize(got);
         buf.shrink_to_fit();

         LLVMFuzzerTestOneInput(buf.data(), got);
      }
   }

   return 0;
}

#endif

#if defined(BOTAN_FUZZER_IS_AFL) || defined(BOTAN_FUZZER_IS_TEST)

   /* Stub for AFL */

   #if defined(BOTAN_FUZZER_IS_AFL) && !defined(__AFL_COMPILER)
      #error "Build configured for AFL but not being compiled by AFL compiler"
   #endif

// NOLINTNEXTLINE(*-definitions-in-headers)
int main(int argc, char* argv[]) {
   LLVMFuzzerInitialize(&argc, &argv);

   #if defined(BOTAN_FUZZER_IS_TEST)
   if(argc > 1) {
      return fuzz_files(&argv[1]);
   }
   #endif

   #if defined(__AFL_LOOP)
   while(__AFL_LOOP(1000))
   #endif
   {
      std::vector<uint8_t> buf(max_fuzzer_input_size);
      std::cin.read(reinterpret_cast<char*>(buf.data()), static_cast<std::streamsize>(buf.size()));
      const size_t got = std::cin.gcount();

      buf.resize(got);
      buf.shrink_to_fit();

      LLVMFuzzerTestOneInput(buf.data(), got);
   }
}

#elif defined(BOTAN_FUZZER_IS_KLEE)

   #include <klee/klee.h>

// NOLINTNEXTLINE(*-definitions-in-headers)
int main(int argc, char* argv[]) {
   LLVMFuzzerInitialize(&argc, &argv);

   uint8_t input[max_fuzzer_input_size] = {0};
   klee_make_symbolic(&input, sizeof(input), "input");

   size_t input_len = klee_range(0, sizeof(input), "input_len");

   LLVMFuzzerTestOneInput(input, input_len);
}

#endif

#endif
