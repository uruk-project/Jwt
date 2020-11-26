using System.Collections.Generic;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Diagnosers;
using JsonWebToken.Cryptography;

namespace JsonWebToken.Performance
{
    [MemoryDiagnoser]
    public class ValueTypeParameters
    {
        [Benchmark(Baseline = true)]
        public void Class_Standard()
        {
            var value = ParamClass.Aes128CbcHmacSha256;
            MethodStandard(value);
        }

        [Benchmark]
        public void Struct_Standard()
        {
            var value = ParamStruct.Aes128CbcHmacSha256;
            MethodStandard(value);
        }

        [Benchmark]
        public void StructReadonly_Standard()
        {
            var value = ParamReadonlyStruct.Aes128CbcHmacSha256;
            MethodStandard(value);
        }

        [Benchmark]
        public void StructRefReadonly_Standard()
        {
            var value = ParamRefReadonlyStruct.Aes128CbcHmacSha256;
            MethodStandard(value);
        }

        [Benchmark]
        public void Class_In()
        {
            var value = ParamClass.Aes128CbcHmacSha256;
            MethodIn(value);
        }
        [Benchmark]
        public void Struct_In()
        {
            var value = ParamStruct.Aes128CbcHmacSha256;
            MethodIn(value);
        }
        [Benchmark]
        public void StructReadonly_In()
        {
            var value = ParamReadonlyStruct.Aes128CbcHmacSha256;
            MethodIn(value);
        }
        [Benchmark]
        public void StructRefReadonly_In()
        {
            var value = ParamRefReadonlyStruct.Aes128CbcHmacSha256;
            MethodIn(value);
        }

        [Benchmark]
        public void Class_In2()
        {
            var value = ParamClass.Aes128CbcHmacSha256;
            MethodIn(in value);
        }
        [Benchmark]
        public void Struct_In2()
        {
            var value = ParamStruct.Aes128CbcHmacSha256;
            MethodIn(in value);
        }
        [Benchmark]
        public void StructReadonly_In2()
        {
            var value = ParamReadonlyStruct.Aes128CbcHmacSha256;
            MethodIn(in value);
        }
        [Benchmark]
        public void StructRefReadonly_In2()
        {
            var value = ParamRefReadonlyStruct.Aes128CbcHmacSha256;
            MethodIn(in value);
        }

        [Benchmark]
        public void Class_Ref()
        {
            var value = ParamClass.Aes128CbcHmacSha256;
            MethodRef(ref value);
        }
        [Benchmark]
        public void Struct_Ref()
        {
            var value = ParamStruct.Aes128CbcHmacSha256;
            MethodRef(ref value);
        }
        [Benchmark]
        public void StructReadonly_Ref()
        {
            var value = ParamReadonlyStruct.Aes128CbcHmacSha256;
            MethodRef(ref value);
        }
        [Benchmark]
        public void StructRefReadonly_Ref()
        {
            var value = ParamRefReadonlyStruct.Aes128CbcHmacSha256;
            MethodRef(ref value);
        }

        private int MethodStandard(ParamClass value)
        {
            return value.RequiredKeySizeInBytes + 2;
        }
        private int MethodStandard(ParamStruct value)
        {
            return value.RequiredKeySizeInBytes + 2;
        }
        private int MethodStandard(ParamReadonlyStruct value)
        {
            return value.RequiredKeySizeInBytes + 2;
        }
        private int MethodStandard(ParamRefReadonlyStruct value)
        {
            return value.RequiredKeySizeInBytes + 2;
        }

        private int MethodIn(in ParamClass value)
        {
            return value.RequiredKeySizeInBytes + 2;
        }
        private int MethodIn(in ParamStruct value)
        {
            return value.RequiredKeySizeInBytes + 2;
        }
        private int MethodIn(in ParamReadonlyStruct value)
        {
            return value.RequiredKeySizeInBytes + 2;
        }
        private int MethodIn(in ParamRefReadonlyStruct value)
        {
            return value.RequiredKeySizeInBytes + 2;
        }

        private int MethodRef(ref ParamClass value)
        {
            return value.RequiredKeySizeInBytes + 2;
        }
        private int MethodRef(ref ParamStruct value)
        {
            return value.RequiredKeySizeInBytes + 2;
        }
        private int MethodRef(ref ParamReadonlyStruct value)
        {
            return value.RequiredKeySizeInBytes + 2;
        }
        private int MethodRef(ref ParamRefReadonlyStruct value)
        {
            return value.RequiredKeySizeInBytes + 2;
        }

        public readonly ref struct ParamRefReadonlyStruct
        {
            public static ParamRefReadonlyStruct Aes128CbcHmacSha256 => new ParamRefReadonlyStruct(id: 11, EncryptionAlgorithm.A128CbcHS256.Name.ToString(), requiredKeySizeInBytes: 32, SignatureAlgorithm.HS256, requiredKeyWrappedSizeInBytes: 40, EncryptionType.AesHmac);

            public static readonly IDictionary<string, EncryptionAlgorithm> AdditionalAlgorithms = new Dictionary<string, EncryptionAlgorithm>();

            private readonly long _id;

            public readonly int RequiredKeySizeInBytes;
            public readonly int RequiredKeyWrappedSizeInBytes;
            public readonly SignatureAlgorithm SignatureAlgorithm;
            public readonly EncryptionType Category;
            public readonly string Name;

            private ParamRefReadonlyStruct(long id, string name, int requiredKeySizeInBytes, SignatureAlgorithm hashAlgorithm, int requiredKeyWrappedSizeInBytes, EncryptionType encryptionType)
            {
                _id = id;
                Name = name;
                RequiredKeySizeInBytes = requiredKeySizeInBytes;
                SignatureAlgorithm = hashAlgorithm;
                RequiredKeyWrappedSizeInBytes = requiredKeyWrappedSizeInBytes;
                Category = encryptionType;
            }
        }
        public readonly struct ParamReadonlyStruct
        {
            public static readonly ParamReadonlyStruct Aes128CbcHmacSha256 = new ParamReadonlyStruct(id: 11, EncryptionAlgorithm.A128CbcHS256.Name.ToString(), requiredKeySizeInBytes: 32, SignatureAlgorithm.HS256, requiredKeyWrappedSizeInBytes: 40, EncryptionType.AesHmac);

            public static readonly IDictionary<string, EncryptionAlgorithm> AdditionalAlgorithms = new Dictionary<string, EncryptionAlgorithm>();

            private readonly long _id;

            public readonly int RequiredKeySizeInBytes;
            public readonly int RequiredKeyWrappedSizeInBytes;
            public readonly SignatureAlgorithm SignatureAlgorithm;
            public readonly EncryptionType Category;
            public readonly string Name;

            private ParamReadonlyStruct(long id, string name, int requiredKeySizeInBytes, SignatureAlgorithm hashAlgorithm, int requiredKeyWrappedSizeInBytes, EncryptionType encryptionType)
            {
                _id = id;
                Name = name;
                RequiredKeySizeInBytes = requiredKeySizeInBytes;
                SignatureAlgorithm = hashAlgorithm;
                RequiredKeyWrappedSizeInBytes = requiredKeyWrappedSizeInBytes;
                Category = encryptionType;
            }
        }
        public struct ParamStruct
        {
            public static readonly ParamStruct Aes128CbcHmacSha256 = new ParamStruct(id: 11, EncryptionAlgorithm.A128CbcHS256.Name.ToString(), requiredKeySizeInBytes: 32, SignatureAlgorithm.HS256, requiredKeyWrappedSizeInBytes: 40, EncryptionType.AesHmac);

            public static readonly IDictionary<string, EncryptionAlgorithm> AdditionalAlgorithms = new Dictionary<string, EncryptionAlgorithm>();

            private readonly long _id;

            public readonly int RequiredKeySizeInBytes;
            public readonly int RequiredKeyWrappedSizeInBytes;
            public readonly SignatureAlgorithm SignatureAlgorithm;
            public readonly EncryptionType Category;
            public readonly string Name;

            private ParamStruct(long id, string name, int requiredKeySizeInBytes, SignatureAlgorithm hashAlgorithm, int requiredKeyWrappedSizeInBytes, EncryptionType encryptionType)
            {
                _id = id;
                Name = name;
                RequiredKeySizeInBytes = requiredKeySizeInBytes;
                SignatureAlgorithm = hashAlgorithm;
                RequiredKeyWrappedSizeInBytes = requiredKeyWrappedSizeInBytes;
                Category = encryptionType;
            }
        }

        public class ParamClass
        {
            public static readonly ParamClass Aes128CbcHmacSha256 = new ParamClass(id: 11, EncryptionAlgorithm.A128CbcHS256.Name.ToString(), requiredKeySizeInBytes: 32, SignatureAlgorithm.HS256, requiredKeyWrappedSizeInBytes: 40, EncryptionType.AesHmac);

            public static readonly IDictionary<string, EncryptionAlgorithm> AdditionalAlgorithms = new Dictionary<string, EncryptionAlgorithm>();

            private readonly long _id;

            public readonly int RequiredKeySizeInBytes;
            public readonly int RequiredKeyWrappedSizeInBytes;
            public readonly SignatureAlgorithm SignatureAlgorithm;
            public readonly EncryptionType Category;
            public readonly string Name;

            private ParamClass(long id, string name, int requiredKeySizeInBytes, SignatureAlgorithm hashAlgorithm, int requiredKeyWrappedSizeInBytes, EncryptionType encryptionType)
            {
                _id = id;
                Name = name;
                RequiredKeySizeInBytes = requiredKeySizeInBytes;
                SignatureAlgorithm = hashAlgorithm;
                RequiredKeyWrappedSizeInBytes = requiredKeyWrappedSizeInBytes;
                Category = encryptionType;
            }
        }
    }
}