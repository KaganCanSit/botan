/**
* TLS Connection 
* (C) 2004-2006 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#ifndef BOTAN_TLS_CONNECTION_H__
#define BOTAN_TLS_CONNECTION_H__

#include <botan/x509cert.h>
#include <vector>

namespace Botan {

/**
* TLS Connection
*/
class BOTAN_DLL TLS_Connection
   {
   public:
      virtual u32bit read(byte[], u32bit) = 0;
      virtual void write(const byte[], u32bit) = 0;
      u32bit read(byte& in) { return read(&in, 1); }
      void write(byte out) { write(&out, 1); }

      virtual std::vector<X509_Certificate> peer_cert_chain() const = 0;

      virtual void close() = 0;

      virtual ~TLS_Connection() {}
   };

}

#endif
