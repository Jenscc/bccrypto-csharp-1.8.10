using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.X509;
using System;
using System.IO;

namespace crypto_test
{
	public class CryptoTest
	{
		/// <summary>
		/// The main entry point for the application.
		/// </summary>
		[STAThread]
		static void Main(string[] args)
		{
            //DateTime before = DateTime.Now;

            //try
            //{
            //    Org.BouncyCastle.Asn1.Tests.RegressionTest.Main(args);
            //    Org.BouncyCastle.Bcpg.OpenPgp.Tests.Dsa2Test.?
            //    Org.BouncyCastle.Bcpg.OpenPgp.Tests.RegressionTest.Main(args);
            //    Org.BouncyCastle.Bcpg.OpenPgp.Examples.Tests.AllTests.Main(args);
            //    Org.BouncyCastle.Cms.Tests.AllTests.Main(args);
            //    Org.BouncyCastle.Crypto.Agreement.Tests.AllTests.Main(args);
            //    Org.BouncyCastle.Crypto.Tests.RegressionTest.Main(args);
            //    Org.BouncyCastle.Crypto.IO.Tests.AllTests.Main(args);
            //    Org.BouncyCastle.Math.Tests.AllTests.Main(args);
            //    Org.BouncyCastle.Math.EC.Tests.AllTests.Main(args);
            //    Org.BouncyCastle.Ocsp.Tests.AllTests.Main(args);
            //    Org.BouncyCastle.Pkcs.Tests.?
            //    Org.BouncyCastle.Pkcs.Tests.EncryptedPrivateKeyInfoTest.Main(args);
            //    Org.BouncyCastle.Pkcs.Tests.Pkcs10Test.Main(args);
            //    Org.BouncyCastle.Pkcs.Tests.Pkcs12StoreTest.Main(args);
            //    Org.BouncyCastle.OpenSsl.Tests.?
            //    Org.BouncyCastle.OpenSsl.Tests.ReaderTest.Main(args);
            //    Org.BouncyCastle.OpenSsl.Tests.WriterTest.Main(args);
            //    Org.BouncyCastle.Security.Tests.?
            //    Org.BouncyCastle.Tests.RegressionTest.Main(args);
            //    Org.BouncyCastle.Tsp.Tests.AllTests.Main(args);
            //    Org.BouncyCastle.X509.Tests.?

            //}
            //catch (Exception e)
            //{
            //    Console.WriteLine("Tests failed with exception: " + e.Message);
            //    Console.WriteLine(e.StackTrace);
            //}

            //DateTime after = DateTime.Now;
            //long elapsedTicks = after.Ticks - before.Ticks;

            //Console.WriteLine("Done in {0}ms.", elapsedTicks / TimeSpan.TicksPerMillisecond);

            //string n = "c5062b58d8539c765e1e5dbaf14cf75dd56c2e13105fecfd1a930bbb5948ff328f126abe779359ca59bca752c308d281573bc6178b6c0fef7dc445e4f826430437b9f9d790581de5749c2cb9cb26d42b2fee15b6b26f09c99670336423b86bc5bec71113157be2d944d7ff3eebffb28413143ea36755db0ae62ff5b724eecb3d316b6bac67e89cacd8171937e2ab19bd353a89acea8c36f81c89a620d5fd2effea896601c7f9daca7f033f635a3a943331d1b1b4f5288790b53af352f1121ca1bef205f40dc012c412b40bdd27585b946466d75f7ee0a7f9d549b4bece6f43ac3ee65fe7fd37123359d9f1a850ad450aaf5c94eb11dea3fc0fc6e9856b1805ef";
            //string e = "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000086c94f";
            //string S = "7e628bcbe6ff83a937b8961197d8bdbb322818aa8bdf30cdfb67ca6bf025ef6f09a99dba4c3ee2807d0b7c77776cfeff33b68d7e3fa859c4688626b2441897d26e5d6b559dd72a596e7dad7def9278419db375f7c67cee0740394502212ebdd4a6c8d3af6ee2fd696d8523de6908492b7cbf2254f15a348956c19840dc15a3d732ef862b62ede022290de3af11ca5e79a3392fff06f75aca8c88a2de1858b35a216d8f73fd70e9d67958ed39a6f8976fb94ec6e61f238a52f9d42241e8354f89e3ece94d6fa5bfbba1eeb70e1698bff31a685fbe799fb44efe21338ed6eea2129155aabc0943bc9f69a8e58897db6a8abcc2879d5d0c5d3e6dc5eb48cf16dac8";
            //string M = "37ddd9901478ae5c16878702cea4a19e786d35582de44ae65a16cd5370fbe3ffdd9e7ee83c7d2f27c8333bbe1754f090059939b1ee3d71e020a675528f48fdb2cbc72c65305b65125c796162e7b07e044ed15af52f52a1febcf4237e6aa42a69e99f0a9159daf924bba12176a57ef4013a5cc0ab5aec83471648005d67d7122e";
            //string digest = "SHA224";
            //string padding = "PSS";
            ////string signature = Convert.ToBase64String(Hex.Decode(S));
            //string signature = Convert.ToBase64String(Hex.Decode("1F2FAD3F97C8282264A8F9873D404AD1776A6DE09CE1DE9D6A4BA9F1E3E3FB457A54E8718AA8491C1C61F15F114EA879FACD078ADC182C18B7987B7BBA06E3EC3E242BA48C0B12690D145D1FFB13C2823FFDFC6D2C4A3E87E0E7D7427D0425FF78A66E8B07A1F380BD3D3DECFD589156D827AD1D70C397D26CEDB2B3D01796DAEED440E34D51252B0436F84991793363046BABAF1DF5F1E33CB24C239DD45B85AD32B30E6913EFA042279D331EF483CA065C2C0E5218634994FA8FE6A9B8D48A8200EAF11BB228642B352FD409DC80FDB8B2ADCCBBEE629C0332BBCBEBB2CDCEE3FBBCD79AD8431A2AF25DFDEB7EA8EAF332C546638BB5C484CD4ED15ACC6777"));
            //Verify(M, signature, n, e, digest, padding);

            //var path = @"C:\Users\test\Desktop\erjiCAyewu.cer";


            //FileStream reader = new FileStream(path, FileMode.Open);

            //X509Certificate signcert = new X509CertificateParser().ReadCertificate(reader);

            SM2Signer sM2Signer = new SM2Signer();
            sM2Signer.Init(true, )
        }
        private static RsaKeyParameters MakeKey(String modulusHexString, String exponentHexString, bool isPrivateKey)
        {
            var modulus = new Org.BouncyCastle.Math.BigInteger(modulusHexString, 16);
            var exponent = new Org.BouncyCastle.Math.BigInteger(exponentHexString, 16);

            return new RsaKeyParameters(isPrivateKey, modulus, exponent);
        }
        public static bool Verify(string data, string signature, string modulus, string publicExponent, string digest, string padding)
        {
            // Build Public Key
            RsaKeyParameters key = MakeKey(modulus, publicExponent, false);

            string alg = null;
            if (padding == "PSS")
            {
                alg = digest + "withRSA" + "/" + "PSS";
            }
            else
            {
                alg = digest + "withRSA";
            }


            /* Init alg */
            ISigner signer = SignerUtilities.GetSigner(alg);
            signer.Init(false, key);

            var sigBytes = Convert.FromBase64String(signature);
            var dataBytes = Hex.Decode(data);

            signer.BlockUpdate(dataBytes, 0, dataBytes.Length);

            return signer.VerifySignature(sigBytes);
        }
    }
}
