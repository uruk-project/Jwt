// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

#if !NETSTANDARD2_0 && !NET461 && !NETCOREAPP2_1
using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics;

namespace JsonWebToken.Internal
{
    internal struct Aes256Keys
    {
        private const int Count = 15;

        public Vector128<byte> Key0;
        public Vector128<byte> Key1;
        public Vector128<byte> Key2;
        public Vector128<byte> Key3;
        public Vector128<byte> Key4;
        public Vector128<byte> Key5;
        public Vector128<byte> Key6;
        public Vector128<byte> Key7;
        public Vector128<byte> Key8;
        public Vector128<byte> Key9;
        public Vector128<byte> Key10;
        public Vector128<byte> Key11;
        public Vector128<byte> Key12;
        public Vector128<byte> Key13;
        public Vector128<byte> Key14;

        public void Clear()
        {
            ref byte that = ref Unsafe.As<Aes256Keys, byte>(ref Unsafe.AsRef(this));
            Unsafe.InitBlock(ref that, 0, Count * 16);
        }
    }
}
#endif