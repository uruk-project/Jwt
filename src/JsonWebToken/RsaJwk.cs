using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace JsonWebToken
{
    public class RsaJwk : AsymmetricJwk
    {
        private string _dp;
        private string _dq;
        private string _e;
        private string _n;
        private string _p;
        private string _q;
        private string _qi;

        public RSAParameters CreateRsaParameters()
        {
            if (N == null || E == null)
            {
                throw new ArgumentException(ErrorMessages.FormatInvariant(ErrorMessages.InvalidRsaKey, Kid));
            }

            RSAParameters parameters = new RSAParameters();
            parameters.D = RawD;
            parameters.DP = RawDP;
            parameters.DQ = RawDQ;
            parameters.InverseQ = RawQI;
            parameters.P = RawP;
            parameters.Q = RawQ;
            parameters.Exponent = RawE;
            parameters.Modulus = RawN;

            return parameters;
        }

        public override bool IsSupportedAlgorithm(string algorithm)
        {
            switch (algorithm)
            {
                case SecurityAlgorithms.RsaSha256:
                case SecurityAlgorithms.RsaSha384:
                case SecurityAlgorithms.RsaSha512:
                case SecurityAlgorithms.RsaOAEP:
                case SecurityAlgorithms.RsaPKCS1:
                    return true;
            }

            return false;
        }

        public override SignatureProvider CreateSignatureProvider(string algorithm, bool willCreateSignatures)
        {
            if (IsSupportedAlgorithm(algorithm))
            {
                return new RsaSignatureProvider(this, algorithm, willCreateSignatures);
            }

            return null;
        }

        public override KeyWrapProvider CreateKeyWrapProvider(string algorithm)
        {
            if (IsSupportedAlgorithm(algorithm))
            {
                return new RsaKeyWrapProvider(this, algorithm);
            }

            return null;
        }

        public override bool HasPrivateKey => D != null && DP != null && DQ != null && P != null && Q != null && QI != null;

        public override int KeySize => RawN?.Length != 0 ? RawN.Length << 3 : 0;

        /// <summary>
        /// Gets or sets the 'dp' (First Factor CRT Exponent).
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = JsonWebKeyParameterNames.DP, Required = Required.Default)]
        public string DP
        {
            get => _dp;
            set
            {
                _dp = value;
                if (value != null)
                {
                    RawDP = Base64Url.DecodeBytes(value);
                }
                else
                {
                    RawDP = null;
                }
            }
        }

        [JsonIgnore]
        public byte[] RawDP { get; private set; }

        /// <summary>
        /// Gets or sets the 'dq' (Second Factor CRT Exponent).
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = JsonWebKeyParameterNames.DQ, Required = Required.Default)]
        public string DQ
        {
            get => _dq;
            set
            {
                _dq = value;
                if (value != null)
                {
                    RawDQ = Base64Url.DecodeBytes(value);
                }
                else
                {
                    RawDQ = null;
                }
            }
        }

        [JsonIgnore]
        public byte[] RawDQ { get; private set; }

        /// <summary>
        /// Gets or sets the 'e' ( Exponent).
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = JsonWebKeyParameterNames.E, Required = Required.Default)]
        public string E
        {
            get => _e;
            set
            {
                _e = value;
                if (value != null)
                {
                    RawE = Base64Url.DecodeBytes(value);
                }
                else
                {
                    RawE = null;
                }
            }
        }

        [JsonIgnore]
        public byte[] RawE { get; private set; }

        /// <summary>
        /// Gets or sets the 'n' (Modulus).
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = JsonWebKeyParameterNames.N, Required = Required.Default)]
        public string N
        {
            get => _n;
            set
            {
                _n = value;
                if (value != null)
                {
                    RawN = Base64Url.DecodeBytes(value);
                }
                else
                {
                    RawN = null;
                }
            }
        }

        [JsonIgnore]
        public byte[] RawN { get; private set; }

        /// <summary>
        /// Gets or sets the 'oth' (Other Primes Info).
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = JsonWebKeyParameterNames.Oth, Required = Required.Default)]
        public IList<string> Oth { get; set; }

        /// <summary>
        /// Gets or sets the 'p' (First Prime Factor).
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = JsonWebKeyParameterNames.P, Required = Required.Default)]
        public string P
        {
            get => _p;
            set
            {
                _p = value;
                if (value != null)
                {
                    RawP = Base64Url.DecodeBytes(value);
                }
                else
                {
                    RawP = null;
                }
            }
        }

        [JsonIgnore]
        public byte[] RawP { get; private set; }

        /// <summary>
        /// Gets or sets the 'q' (Second  Prime Factor).
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = JsonWebKeyParameterNames.Q, Required = Required.Default)]
        public string Q
        {
            get => _q;
            set
            {
                _q = value;
                if (value != null)
                {
                    RawQ = Base64Url.DecodeBytes(value);
                }
                else
                {
                    RawQ = null;
                }
            }
        }

        [JsonIgnore]
        public byte[] RawQ { get; private set; }

        /// <summary>
        /// Gets or sets the 'qi' (First CRT Coefficient).
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = JsonWebKeyParameterNames.QI, Required = Required.Default)]
        public string QI
        {
            get => _qi;
            set
            {
                _qi = value;
                if (value != null)
                {
                    RawQI = Base64Url.DecodeBytes(value);
                }
                else
                {
                    RawQI = null;
                }
            }
        }

        [JsonIgnore]
        public byte[] RawQI { get; private set; }
    }
}
