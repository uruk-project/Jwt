using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using JsonWebToken;

namespace JwkSample
{
    class Program
    {
        static void Main()
        {
            GenerateKeys();

            ReadKeyFromJson();
            ReadKeyFromPem();
            ReadKeyFromX509Certificate();
            ReadSymmetricKeyFromBase64Url();
            ReadSymmetricKeyFromByteArray();
            ReadKeysFromJwksEndpoint();
        }

        private static void GenerateKeys()
        {
            // The GenerateKey method creates a new crypto-random asymmetric key for elliptic curve algorithms
            var ecKey = ECJwk.GenerateKey(EllipticalCurve.P521, withPrivateKey: true, SignatureAlgorithm.EcdsaSha512);
            ecKey.Kid = "Generated-ES512";
            Console.WriteLine("Asymmetric generated JWK for elliptic curve P-521, for ES512 signature algorithm:");
            Console.WriteLine(ecKey);
            Console.WriteLine();

            // The GenerateKey method creates a new crypto-random asymmetric key for RSA algorithms
            var rsaKey = RsaJwk.GenerateKey(2048, withPrivateKey: true, SignatureAlgorithm.RsaSsaPssSha384);
            rsaKey.Kid = "Generated-PS384";
            Console.WriteLine("Asymmetric generated JWK of 2048 bits for RSA, for PS384 signature algorithm:");
            Console.WriteLine(rsaKey);
            Console.WriteLine();

            // The GenerateKey method creates a new crypto-random symmetric key for symmetric algorithms
            var symmetricKey = SymmetricJwk.GenerateKey(128, SignatureAlgorithm.HmacSha256);
            symmetricKey.Kid = "Generated-HS256";
            Console.WriteLine("Symmetric generated JWK of 128 bits, for HS256 signature algorithm:");
            Console.WriteLine(symmetricKey);
            Console.WriteLine();

            // The GenerateKey method creates a new crypto-random aymmetric key for RSA algorithms
            var symmetricKey2 = SymmetricJwk.GenerateKey(256);
            Console.WriteLine("Symmetric generated JWK of 256 bits, without specified signature algorithm, without key identifier:");
            Console.WriteLine(symmetricKey2);
            Console.WriteLine();
        }

        private static void ReadKeyFromJson()
        {
            // The Jwk.FromJson method accept a JSON-encoded string as input
            string json = File.ReadAllText(@".\public_ec_key.json");
            var keyFromJson = Jwk.FromJson(json);
            keyFromJson.Kid = "JSON";
            Console.WriteLine("JWK read from a JSON string:");
            Console.WriteLine(keyFromJson);
            Console.WriteLine();
        }

        private static void ReadSymmetricKeyFromByteArray()
        {

            // The SymmetricJwk.FromBase64Url method accept a Base64-URL encoded string as input
            var binaryKey = new byte[32] { 71, 211, 50, 89, 161, 40, 202, 35, 24, 86, 37, 86, 163, 193, 100, 225, 53, 6, 90, 36, 168, 105, 110, 148, 214, 115, 170, 94, 184, 188, 253, 117 };
            var binarySymmetricKey = SymmetricJwk.FromByteArray(binaryKey);
            binarySymmetricKey.Kid = "binary";
            Console.WriteLine("JWK from byte array:");
            Console.WriteLine(binarySymmetricKey);
            Console.WriteLine();
        }

        private static void ReadKeyFromPem()
        {

            // The Jwk.FromPem method accept a PEM-encoded string as input
            string pem = File.ReadAllText(@".\private_rsa_key.pem");
            var keyFromPem = Jwk.FromPem(pem);
            keyFromPem.Kid = "PEM";
            Console.WriteLine("JWK read from a PEM file:");
            Console.WriteLine(keyFromPem);
            Console.WriteLine();
        }

        private static void ReadKeyFromX509Certificate()
        {
            // The Jwk.FromPem method accept a PEM-encoded string as input
            X509Certificate2 certificate = new X509Certificate2(@".\ValidbasicConstraintsNotCriticalTest4EE.crt");
            var keyFromCertificate = Jwk.FromX509Certificate(certificate, false);
            keyFromCertificate.Kid = "X509";
            Console.WriteLine("JWK read from a X509 certificate:");
            Console.WriteLine(keyFromCertificate);
            Console.WriteLine();
        }

        private static void ReadSymmetricKeyFromBase64Url()
        {
            // The SymmetricJwk.FromBase64Url method accept a Base64-URL encoded string as input
            var b64SymmetricKey = SymmetricJwk.FromBase64Url("R9MyWaEoyiMYViVWo8Fk4TUGWiSoaW6U1nOqXri8_XU");
            b64SymmetricKey.Kid = "B64";
            Console.WriteLine("JWK from Base64-URL:");
            Console.WriteLine(b64SymmetricKey);
            Console.WriteLine();
        }

        private static void ReadKeysFromJwksEndpoint()
        {
            // The JwksKeyProvider retrieve the JWKs from an HTTP endpoint. The JkuKeyProvider & X5uKeyProvider do the same for differents formats.
            var jwksProvider = new JwksKeyProvider("https://login.microsoftonline.com/common/discovery/v2.0/keys"); // you may provide an HttpClientHandler with if you are behind a proxy.
            var keys = jwksProvider.GetKeys();
            Console.WriteLine("JWK from internet faced JWKS:");
            foreach (var key in keys)
            {
                Console.WriteLine(key);
                Console.WriteLine();
            }
        }
    }
}