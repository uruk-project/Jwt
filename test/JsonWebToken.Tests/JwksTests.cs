using System.Collections.Generic;
using Xunit;

namespace JsonWebToken.Tests
{
    public class JwksTests
    {

        [Theory]
        [MemberData(nameof(GetJwks))]
        public void ReadJwks_Valid(string origin, int count, string json)
        {
            var jwks = Jwks.FromJson(json);

            Assert.Equal(count, jwks.Keys.Count);
        }

        public static IEnumerable<object[]> GetJwks()
        {
            yield return new object[]
            {
                "https://login.salesforce.com/id/keys", 3,
                @"{
  ""keys"": [
    {
      ""kty"": ""RSA"",
      ""n"": ""zZ6iZhgNHEgGA_U2ipme9C9qDJRTxSzTwjAE0g2-zZg7KBsTcJ7zNKcCS9b-9J-l5y500_75IAsnC-c7qUHw46SYqPWBZKosg5cEGyC_pB1coQzPq1NNbmSfg4gRwThCmmyp_bypK22-F5hdJp3dRZn7_moQ71hPstTc9MTZgyD5xi9l-PFuD5iDhtAqXKP9yE8ktVAvU8FRcf2DeA1DD3EzjtV-to23_rbynXfY3Bv42lLEstMIbZ0tQ_K4XxCSoc0GP4tp1JAXEIpPXNY6Zt2a0wk5MSmZkvQk9ty-r94SA-0rYmXQ6VOt_WaWufIynJBhKqKn_CvQl4EDXBbEBhG16dgs8vYhj_JAP83syY5XDVWAkHs05nMZoE4rfAw3meb-AyDwOCi-MV11GBslRIfJPmxVitIdHnO2_6YzXAu53fIuC5i7eqBxqOju7GNaceaQDSFDSxr4pUR5DuskDiNrQ3YmoSLgdGITIfzdYsbWj2QdeO9nPy9SlngPZYv73rvXF7eghCNvOo8hptG_h4G5ScmJ8wPUDH2VuLtdIbyg476oY3elAWu3YtTT3SGos-Mk4rxwAjWbddoOrMFnK6ShWahZwxEyBA9xPddAM7hJXq8FuJenANg2waKqhIFuWre7JylezAFOXKZW0rzhF6jurCYui7p79YyZqHugEiE"",
      ""e"": ""AQAB"",
      ""alg"": ""RS256"",
      ""use"": ""sig"",
      ""kid"": ""216""
    },
    {
      ""kty"": ""RSA"",
      ""n"": ""yb3JETE4C4THs29DLZlysUhv1Ftwqck7-WBEPNqFEy5UmwP26DZ3spSjY0iG7Zp9-gTfMLF1ygLUqT-7FBSjx1nJkx3rda8xJUUsqLmrZok7K623dvd6E8kbAyGnpgRsqTL-KTketHv-aDy8Sg9DvITLrp9_5oYqp4i_7jLQuJyHrFwgP7U7HJzPaNdgu1wQ4UkZobc4qt2aw4ux7F0cLw8gmUBzCLos1xe8_RzxkYYQv3j5Q3aNxlpDGFLZlFGJLSwbV3aNLMacAEDHrZNyyE_DvHj8VingSXLl68C3iRR2vGKIxoyG1MWn7a2E0ruwnr9djMHyFD97l85OHNk_wx_uHBisX44KRnW24qQSptgk4g_5ZEI-Mjwk0_MyAoaEhoFplarhMm87bFZTlEb0UvWr6oQN4ZqYIriRDEQwHFk17P2YzD5OvmihyyfsBHURYKYTEOVgSgQZIhmfmrf8DXbAXuvQz0rSfu2gGq2li4Y0sPUR9pnuRyCeZGJ3N4iYSTiTFhLXvq3Xjv4TUReDICoxpQLRnX2wFBC5erts0bmscMt15w1ZqyRtSN77hkKwRpcCSH_Frd1MP5GduyUyfZGsCp45D-9LEhnLSMSNDtQj0mqx3F7opyphqz6675P99qQALF0tQBN4mUYVapuNWvWgDtrYOHIswx3fPHYmBi8"",
      ""e"": ""AQAB"",
      ""alg"": ""RS256"",
      ""use"": ""sig"",
      ""kid"": ""220""
    },
    {
      ""kty"": ""RSA"",
      ""n"": ""oDkKtNtFuHrGXiQOZmeKJvFot5NggosQf37wpxM5Mwem575SyI4y8aZsZB5W9-5fIdWwANljYEKbRYscIG2F8v6Cp4CHSMdx4e6U26zY-6aJ9msyefghlgnGegPgEYqS8oPBgWBQ7C6D8tmfvr9OZ6UpD7BoKgmhELlxUiR-3wmBfhBW_OZQIJ6l4dk5lyf1I9bCWY7rLkg8VSpkihAwewPhN3FvP-zngxkUgUG-ayuwP77VSSu3dwfs4wTbjrL0juXINXOU0CwHp49JpIr184ofWY6UfrsfvIMXenCBkuzAUaGSSKSixNM-bXFq3lxGbJINZ-GiF0wNGKXTRQmGQYWTHdIJkEvYxFUo90Mqcd_IHJpPfb3_9vM1jbB5DWl1YgrAoXR3U1bIEZ3AAaqP5XynhbKu-XJI4YwC0pvhICEjs3lSxKN9Wt1Ivl33K-Tlgg6ukqpgB2yqSb3TRRYD4c98N0zGEP_Wt7RHKtf7vdeo2i7WYk-hI8Lh1ljxVJKruZoIRpDJYIwpvar89UEe3F1q_oqFE0o1SYBM3zW_mkgeUx4e1Ijerd5fKYStJ4he9pn8pIb-e9kBKG9RjzwbbDkar5DiqGIj_C77ezlewLw4Cr5zoDp7l4lANmG4mYMdCvilthB3dQVftrJdPq8gHUALD3oheBvCpRw0-D3VYxc"",
      ""e"": ""AQAB"",
      ""alg"": ""RS256"",
      ""use"": ""sig"",
      ""kid"": ""218""
    }
  ]
}" };

            yield return new object[]
           {
               "https://login.microsoftonline.com/common/discovery/v2.0/keys", 5,
               @"{""keys"":[{""kty"":""RSA"",""use"":""sig"",""kid"":""-sxMJMLCIDWMTPvZyJ6tx-CDxw0"",""x5t"":""-sxMJMLCIDWMTPvZyJ6tx-CDxw0"",""n"":""rxlPnqW6fNuCbdrhDEzwGJVux3iPvtt_8r-uHHIKa7C_b_ux5hewNMS91SgUPZOrsqb54uHj_7INWKqKEtFc4YP83Fhss_uO_mT97czENs4zWaSN9Eww_Fz36xq_uZ65750lHKwXQJ1A_pe-VOgNlPg8ECi7meQDJ05r838eu1jpKFjxkQrdRFTLgYtRQ7TxX-zzRyoRR8iqJc6Rvnijh19-YfWtBsCI1r127SFakUBrY_ZKsKyE9KNWUL7H65EyFRNgK80XfYvhQlGw3-Ajf28fi71wW-BypK1bTCArzwX7zgF3H6P1u8PKosSOSN_Q9-Qc9X-R_Y-3bOpOIiLOvw"",""e"":""AQAB"",""x5c"":[""MIIDBTCCAe2gAwIBAgIQKOfEJNDyDplBSXKYcM6UcjANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTE4MTIyMjAwMDAwMFoXDTIwMTIyMjAwMDAwMFowLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAK8ZT56lunzbgm3a4QxM8BiVbsd4j77bf/K/rhxyCmuwv2/7seYXsDTEvdUoFD2Tq7Km+eLh4/+yDViqihLRXOGD/NxYbLP7jv5k/e3MxDbOM1mkjfRMMPxc9+sav7meue+dJRysF0CdQP6XvlToDZT4PBAou5nkAydOa/N/HrtY6ShY8ZEK3URUy4GLUUO08V/s80cqEUfIqiXOkb54o4dffmH1rQbAiNa9du0hWpFAa2P2SrCshPSjVlC+x+uRMhUTYCvNF32L4UJRsN/gI39vH4u9cFvgcqStW0wgK88F+84Bdx+j9bvDyqLEjkjf0PfkHPV/kf2Pt2zqTiIizr8CAwEAAaMhMB8wHQYDVR0OBBYEFC//HOy7pEIKtnpMj4bEMA3oJ39uMA0GCSqGSIb3DQEBCwUAA4IBAQAIYxZXIpwUX8HjSKWUMiyQEn0gRizAyqQhC5wdWOFCBIZPJs8efOkGTsBg/hA+X1fvN6htcBbJRfFfDlP/LkLIVNv2zX4clGM20YhY8FQQh9FWs5qchlnP4lSk7UmScxgT3a6FG3OcLToukNoK722Om2yQ1ayWtn9K82hvZl5L3P8zYaG1gbHPGW5VlNXds60jIpcSWLdU2hacYmwz4pPQyvNOW68aK/Y/tWrJ3DKrf1feDbmm7O5kpWVYWRpah+i6ePjELNkc2Jr+2DchBQTIh9Fxe8sz+9iOyLh9tubMJ+7RTs/ksK0sQ1NVScGFxK+o5hFOOMK7y/F5r467jHez""],""issuer"":""https://login.microsoftonline.com/{tenantid}/v2.0""},{""kty"":""RSA"",""use"":""sig"",""kid"":""N-lC0n-9DALqwhuHYnHQ63GeCXc"",""x5t"":""N-lC0n-9DALqwhuHYnHQ63GeCXc"",""n"":""t3J1hnS4aRZaZGq5JUw1iKsHynCUV9lMBe2MDArXGeQlN-w8Xw9vU6InqmPVvJsUVyUkKE0jzn4dYLcwbTuttQ0hmN-lzNfGol04KKMIVdtTs1P0wo_-VyJ88EuWM3lvDxyTw1PLim14UJ1856zdp2_kZLOSy-B46K96ENJ8b2yCP_VHRTd3GgNTrx-xeU66WJdlon6SSkxI85KIAzOR4vxrl2XZZx_DkVcsAHa8KXQRkbMw82F2SHAbgJTv8qjSHR_WXjoGs3Wgds9UUqgNDXSK6qTjoG53zj8-faRkK0Px4wRD9rVXt-pPcGaul3TEkUVhpe8SyrLWETFexJesSQ"",""e"":""AQAB"",""x5c"":[""MIIDBTCCAe2gAwIBAgIQP8sUV4hf2ZxPfw5DB0O9CjANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTE5MDIwMTAwMDAwMFoXDTIxMDIwMTAwMDAwMFowLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALdydYZ0uGkWWmRquSVMNYirB8pwlFfZTAXtjAwK1xnkJTfsPF8Pb1OiJ6pj1bybFFclJChNI85+HWC3MG07rbUNIZjfpczXxqJdOCijCFXbU7NT9MKP/lcifPBLljN5bw8ck8NTy4pteFCdfOes3adv5GSzksvgeOivehDSfG9sgj/1R0U3dxoDU68fsXlOuliXZaJ+kkpMSPOSiAMzkeL8a5dl2Wcfw5FXLAB2vCl0EZGzMPNhdkhwG4CU7/Ko0h0f1l46BrN1oHbPVFKoDQ10iuqk46Bud84/Pn2kZCtD8eMEQ/a1V7fqT3Bmrpd0xJFFYaXvEsqy1hExXsSXrEkCAwEAAaMhMB8wHQYDVR0OBBYEFH5JQzlFI3FE9VxkkUbFT9XQDxifMA0GCSqGSIb3DQEBCwUAA4IBAQCb7re2PWF5ictaUCi4Ki2AWE6fGbmVRUdf0GkI06KdHWSiOgkPdB7Oka1Fv/j4GCs/ezHa1+oAx8uU96GECBBEMnCYPqkjmNKdLYkIUrcwEe9qz12MOCKJkCuYsDdLUqv+e4wHssbAnJn2+L13UmfAb6FM1VTaKIQtPs4yZsdhnk4M+Ee2EpcvgwOl2na+m58ovspieEyI6II/TolzwP9NWbvHw5VlF0IYttQprjmQU3tQ2E6j3HpZ31B0nrnFWglUB7lEC+0mkyJUGzovNECsr+BIEMhTlCp2/rbruCCbZBppYAlbWlTFwXA8TqfE4DNATYgm90ObQANcTnHJeRV1""],""issuer"":""https://login.microsoftonline.com/{tenantid}/v2.0""},{""kty"":""RSA"",""use"":""sig"",""kid"":""M6pX7RHoraLsprfJeRCjSxuURhc"",""x5t"":""M6pX7RHoraLsprfJeRCjSxuURhc"",""n"":""xHScZMPo8FifoDcrgncWQ7mGJtiKhrsho0-uFPXg-OdnRKYudTD7-Bq1MDjcqWRf3IfDVjFJixQS61M7wm9wALDj--lLuJJ9jDUAWTA3xWvQLbiBM-gqU0sj4mc2lWm6nPfqlyYeWtQcSC0sYkLlayNgX4noKDaXivhVOp7bwGXq77MRzeL4-9qrRYKjuzHfZL7kNBCsqO185P0NI2Jtmw-EsqYsrCaHsfNRGRrTvUHUq3hWa859kK_5uNd7TeY2ZEwKVD8ezCmSfR59ZzyxTtuPpkCSHS9OtUvS3mqTYit73qcvprjl3R8hpjXLb8oftfpWr3hFRdpxrwuoQEO4QQ"",""e"":""AQAB"",""x5c"":[""MIIC8TCCAdmgAwIBAgIQfEWlTVc1uINEc9RBi6qHMjANBgkqhkiG9w0BAQsFADAjMSEwHwYDVQQDExhsb2dpbi5taWNyb3NvZnRvbmxpbmUudXMwHhcNMTgxMDE0MDAwMDAwWhcNMjAxMDE0MDAwMDAwWjAjMSEwHwYDVQQDExhsb2dpbi5taWNyb3NvZnRvbmxpbmUudXMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDEdJxkw+jwWJ+gNyuCdxZDuYYm2IqGuyGjT64U9eD452dEpi51MPv4GrUwONypZF/ch8NWMUmLFBLrUzvCb3AAsOP76Uu4kn2MNQBZMDfFa9AtuIEz6CpTSyPiZzaVabqc9+qXJh5a1BxILSxiQuVrI2BfiegoNpeK+FU6ntvAZervsxHN4vj72qtFgqO7Md9kvuQ0EKyo7Xzk/Q0jYm2bD4SypiysJoex81EZGtO9QdSreFZrzn2Qr/m413tN5jZkTApUPx7MKZJ9Hn1nPLFO24+mQJIdL061S9LeapNiK3vepy+muOXdHyGmNctvyh+1+laveEVF2nGvC6hAQ7hBAgMBAAGjITAfMB0GA1UdDgQWBBQ5TKadw06O0cvXrQbXW0Nb3M3h/DANBgkqhkiG9w0BAQsFAAOCAQEAI48JaFtwOFcYS/3pfS5+7cINrafXAKTL+/+he4q+RMx4TCu/L1dl9zS5W1BeJNO2GUznfI+b5KndrxdlB6qJIDf6TRHh6EqfA18oJP5NOiKhU4pgkF2UMUw4kjxaZ5fQrSoD9omjfHAFNjradnHA7GOAoF4iotvXDWDBWx9K4XNZHWvD11Td66zTg5IaEQDIZ+f8WS6nn/98nAVMDtR9zW7Te5h9kGJGfe6WiHVaGRPpBvqC4iypGHjbRwANwofZvmp5wP08hY1CsnKY5tfP+E2k/iAQgKKa6QoxXToYvP7rsSkglak8N5g/+FJGnq4wP6cOzgZpjdPMwaVt5432GA==""],""issuer"":""https://login.microsoftonline.com/{tenantid}/v2.0""},{""kty"":""RSA"",""use"":""sig"",""kid"":""1LTMzakihiRla_8z2BEJVXeWMqo"",""x5t"":""1LTMzakihiRla_8z2BEJVXeWMqo"",""n"":""3sKcJSD4cHwTY5jYm5lNEzqk3wON1CaARO5EoWIQt5u-X-ZnW61CiRZpWpfhKwRYU153td5R8p-AJDWT-NcEJ0MHU3KiuIEPmbgJpS7qkyURuHRucDM2lO4L4XfIlvizQrlyJnJcd09uLErZEO9PcvKiDHoois2B4fGj7CsAe5UZgExJvACDlsQSku2JUyDmZUZP2_u_gCuqNJM5o0hW7FKRI3MFoYCsqSEmHnnumuJ2jF0RHDRWQpodhlAR6uKLoiWHqHO3aG7scxYMj5cMzkpe1Kq_Dm5yyHkMCSJ_JaRhwymFfV_SWkqd3n-WVZT0ADLEq0RNi9tqZ43noUnO_w"",""e"":""AQAB"",""x5c"":[""MIIDYDCCAkigAwIBAgIJAIB4jVVJ3BeuMA0GCSqGSIb3DQEBCwUAMCkxJzAlBgNVBAMTHkxpdmUgSUQgU1RTIFNpZ25pbmcgUHVibGljIEtleTAeFw0xNjA0MDUxNDQzMzVaFw0yMTA0MDQxNDQzMzVaMCkxJzAlBgNVBAMTHkxpdmUgSUQgU1RTIFNpZ25pbmcgUHVibGljIEtleTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAN7CnCUg+HB8E2OY2JuZTRM6pN8DjdQmgETuRKFiELebvl/mZ1utQokWaVqX4SsEWFNed7XeUfKfgCQ1k/jXBCdDB1NyoriBD5m4CaUu6pMlEbh0bnAzNpTuC+F3yJb4s0K5ciZyXHdPbixK2RDvT3Lyogx6KIrNgeHxo+wrAHuVGYBMSbwAg5bEEpLtiVMg5mVGT9v7v4ArqjSTOaNIVuxSkSNzBaGArKkhJh557pridoxdERw0VkKaHYZQEerii6Ilh6hzt2hu7HMWDI+XDM5KXtSqvw5ucsh5DAkifyWkYcMphX1f0lpKnd5/llWU9AAyxKtETYvbameN56FJzv8CAwEAAaOBijCBhzAdBgNVHQ4EFgQU9IdLLpbC2S8Wn1MCXsdtFac9SRYwWQYDVR0jBFIwUIAU9IdLLpbC2S8Wn1MCXsdtFac9SRahLaQrMCkxJzAlBgNVBAMTHkxpdmUgSUQgU1RTIFNpZ25pbmcgUHVibGljIEtleYIJAIB4jVVJ3BeuMAsGA1UdDwQEAwIBxjANBgkqhkiG9w0BAQsFAAOCAQEAXk0sQAib0PGqvwELTlflQEKS++vqpWYPW/2gCVCn5shbyP1J7z1nT8kE/ZDVdl3LvGgTMfdDHaRF5ie5NjkTHmVOKbbHaWpTwUFbYAFBJGnx+s/9XSdmNmW9GlUjdpd6lCZxsI6888r0ptBgKINRRrkwMlq3jD1U0kv4JlsIhafUIOqGi4+hIDXBlY0F/HJPfUU75N885/r4CCxKhmfh3PBM35XOch/NGC67fLjqLN+TIWLoxnvil9m3jRjqOA9u50JUeDGZABIYIMcAdLpI2lcfru4wXcYXuQul22nAR7yOyGKNOKULoOTE4t4AeGRqCogXSxZgaTgKSBhvhE+MGg==""],""issuer"":""https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0""},{""kty"":""RSA"",""use"":""sig"",""kid"":""xP_zn6I1YkXcUUmlBoPuXTGsaxk"",""x5t"":""xP_zn6I1YkXcUUmlBoPuXTGsaxk"",""n"":""2pWatafeb3mB0A73-Z-URwrubwDldWvivRu19GNC61MBOb3fZ4I4lyhUhNuS7aJRPJIFB6zl-HFx1nHpGg74BHe0z9skODHYZEACd2iKBIet55DdduIe1CXsZ9keyEmNaGv3XS4OW_7IDM0j5wR9OHugUifkH3PQIcFvTYanHmXojTmgjIOWoz7y0okpyN9-FbZRzdfx-ej-njaj5gR8r69muwO5wlTbIG20V40R6zYh-QODMUpayy7jDGFGw5vjFH9Ca0tLZcNQq__JKE_mp-0fODOAQobOrBUoASFkyCd95BVW7KJrndvW7ofRWaCTuZZOy5SnU4asbjMrgxFZFw"",""e"":""AQAB"",""x5c"":[""MIIDYDCCAkigAwIBAgIJAJzCyTLC+DjJMA0GCSqGSIb3DQEBCwUAMCkxJzAlBgNVBAMTHkxpdmUgSUQgU1RTIFNpZ25pbmcgUHVibGljIEtleTAeFw0xNjA3MTMyMDMyMTFaFw0yMTA3MTIyMDMyMTFaMCkxJzAlBgNVBAMTHkxpdmUgSUQgU1RTIFNpZ25pbmcgUHVibGljIEtleTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANqVmrWn3m95gdAO9/mflEcK7m8A5XVr4r0btfRjQutTATm932eCOJcoVITbku2iUTySBQes5fhxcdZx6RoO+AR3tM/bJDgx2GRAAndoigSHreeQ3XbiHtQl7GfZHshJjWhr910uDlv+yAzNI+cEfTh7oFIn5B9z0CHBb02Gpx5l6I05oIyDlqM+8tKJKcjffhW2Uc3X8fno/p42o+YEfK+vZrsDucJU2yBttFeNEes2IfkDgzFKWssu4wxhRsOb4xR/QmtLS2XDUKv/yShP5qftHzgzgEKGzqwVKAEhZMgnfeQVVuyia53b1u6H0Vmgk7mWTsuUp1OGrG4zK4MRWRcCAwEAAaOBijCBhzAdBgNVHQ4EFgQU11z579/IePwuc4WBdN4L0ljG4CUwWQYDVR0jBFIwUIAU11z579/IePwuc4WBdN4L0ljG4CWhLaQrMCkxJzAlBgNVBAMTHkxpdmUgSUQgU1RTIFNpZ25pbmcgUHVibGljIEtleYIJAJzCyTLC+DjJMAsGA1UdDwQEAwIBxjANBgkqhkiG9w0BAQsFAAOCAQEAiASLEpQseGNahE+9f9PQgmX3VgjJerNjXr1zXWXDJfFE31DxgsxddjcIgoBL9lwegOHHvwpzK1ecgH45xcJ0Z/40OgY8NITqXbQRfdgLrEGJCoyOQEbjb5PW5k2aOdn7LBxvDsH6Y8ax26v+EFMPh3G+xheh6bfoIRSK1b+44PfoDZoJ9NfJibOZ4Cq+wt/yOvpMYQDB/9CNo18wmA3RCLYjf2nAc7RO0PDYHSIq5QDWV+1awmXDKgIdRpYPpRtn9KFXQkpCeEc/lDTG+o6n7nC40wyjioyR6QmHGvNkMR4VfSoTKCTnFATyDpI1bqU2K7KNjUEsCYfwybFB8d6mjQ==""],""issuer"":""https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0""}]}"
           };

            yield return new object[]
            {
                "https://api.paypal.com/v1/oauth2/certs", 2,
                @"{
 ""keys"": [
  {
   ""kty"": ""RSA"",
   ""alg"": ""RS256"",
   ""use"": ""sig"",
   ""kid"": ""16e6c7334cf754186f877ff1f4a0bc128e1c97ca"",
   ""n"": ""ALk6-zOoZqVpGNvuEcJWBzDsPdwGwxl8M-c2acIMFkqPPdP9IJt0W3KUd5fHdyl1v_pO05kzQPGkKfgTrAL6X0dD2_48xzkkLN2ieiemc-DcfN971XX5Z0ITprPM1BiofYx_h_pJMiydHLQSJ485oyt0ZHPGysHa8w00x7D1OtqMToxfiwFsxcCyBlcPMOs7aijVWz7NGZxpgTb8OJZmOzVF0oVIhjek0oqXIQzQRlivBLhU4yYPnGdQ1g0Lcj5lkry5sZrNVijqn2E3yHDgiBSk-mKhLhCNwj3pQ4EfP42Kv_o-Gg-l2FRqQ1M0DJMcZiYv_vCteJY-HLpClS-BeF8"",
   ""e"": ""AQAB""
  },
  {
   ""kty"": ""RSA"",
   ""alg"": ""RS256"",
   ""use"": ""sig"",
   ""kid"": ""f75b64243cd5243febeb9540c3afd7b7ad15f291"",
   ""n"": ""AIqA49-acaWGnxQf-U9VCaMsPVkzd4Qw3DocPRmtP-L1jVNV_Dm7FCFsg3jfF0uCSw9C6o9vSkmhtOKRUHwKG34AZuwK9XmcwFTVtXIzxRR8f1y30x7bygTWyEEa4NlENQuXiLXFVqpgKRD6iegusuuyglnAPJsAefDXiBBsuzIP607YDmmGMYWq__FjDpkzvN1v-6GcqmMMDmIeT_qUuEh6uTzzA1DJNj3GBSeDCGmUabaPt8UMhBqkrg-w3WW6zFC4JJfNxLEbMHDvLCKIukp9hH0apZVkX8NPo_NX3Kn9HatoFXXVbquPIGsnCz1DB_EB4Il3aPyXgZoMKhsB3b0"",
   ""e"": ""AQAB""
  }
 ]
}"
            };
            yield return new object[]
            {
                "https://www.googleapis.com/oauth2/v3/certs", 2,
                @"{
  ""keys"": [
    {
      ""kid"": ""6fb05f742366ee4cf4bcf49f984c487e45c8c83d"", 
      ""e"": ""AQAB"",
      ""kty"": ""RSA"",
      ""alg"": ""RS256"",
      ""n"": ""48Or9wBEvmkgLBHCjkH3ave8R3aC7Nts0On-xVG9WejR1zt2WZhP7grwMx2jNUWwjkodSQe1EX0XxxBYPwJuy28hyLbNmt0jyXtKKIyzDIW3vB2eR12UA87vjLZZISryXJ1wV35zj_J-KZCJgNLRKsKIyJ1jVTKZev10selGI75S13bQ77eb5sGs5IDl5DxOMhHUBopPWPy4JQA_9-UGlTEBTtnXpgBuvVJFlOmHfCRaFZ85T145A4C3Hyblov9aZLVHuTEZ_MQDzXMm4NyaggBGIk8KLg6f-gMdqHa1-c_p0NU73cgxfvOStPigtVknKf-CxdmYQsQLj_PjVE95Qw"",
      ""use"": ""sig""
    },
    {
      ""use"": ""sig"",
      ""kid"": ""7c309e3a1c1999cb0404ab7125ee40b7cdbcaf7d"",
      ""e"": ""AQAB"",
      ""kty"": ""RSA"",
      ""alg"": ""RS256"",
      ""n"": ""3MdFK4pXPvehMipDL_COfqn6o9soHgSaq_V1o8U_5gTZ-j9DxO9PV7BVncXBgHFctnp3JQ1QTDF7txeHeuLOS4KziRw5r4ohaj2WoOTqXh7lqVMR2YDAcBK46asS177NpkQ1CqHIsy3kNfqhXLwTaKfdlwdA_XUfRbKORWbq0kDxV35egx35nHl5qJ6aP6fcpsnnPvHf7KWO0zkdvwuR-IX79HjqUAEg5UERd5FK4y06PRbxuXHjAgVhHu_sk4reNXNp1HRuTYtQ26DFbVaIjsWb8-nQC8-7FkTjlw9FteAwLVGOm9sTLFp73jAf0pWLh7sJ02pBxZKjsxLO1Lvg7w""
    }
  ]
}"
            };
        }
    }
}
