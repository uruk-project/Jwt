using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Text;
using BenchmarkDotNet.Attributes;

namespace JsonWebToken.Performance
{
    public unsafe class UnsafeComparisonBenchmark
    {
        // L0000: sub rsp, 0x28
        // L0004: mov eax, [rdx+0x8]
        // L0007: cmp eax, 0x0
        // L000a: jbe L0039
        // L000c: cmp byte [rdx+0x10], 0x44
        // L0010: jnz L0032
        // L0012: cmp eax, 0x1
        // L0015: jbe L0039
        // L0017: cmp byte [rdx+0x11], 0x45
        // L001b: jnz L0032
        // L001d: cmp eax, 0x2
        // L0020: jbe L0039
        // L0022: cmp byte [rdx+0x12], 0x46
        // L0026: jnz L0032
        // L0028: mov eax, 0xc
        // L002d: add rsp, 0x28
        // L0031: ret
        // L0032: xor eax, eax
        // L0034: add rsp, 0x28
        // L0038: ret
        // L0039: call 0x7ffec7e51e00
        // L003e: int3
        [Benchmark(Baseline = true)]
        [ArgumentsSource(nameof(GetData3))]
        public uint Loop3(byte[] v)
        {
            if (v[0] == (byte)'D' && v[1] == (byte)'E' && v[2] == (byte)'F')
            {
                return 12;
            }

            return 0;
        }

        // L0000: sub rsp, 0x28
        // L0004: mov eax, [rdx+0x8]
        // L0007: cmp eax, 0x0
        // L000a: jbe L0065
        // L000c: cmp byte [rdx+0x10], 0x41
        // L0010: jnz L005e
        // L0012: cmp eax, 0x1
        // L0015: jbe L0065
        // L0017: cmp byte [rdx+0x11], 0x31
        // L001b: jnz L005e
        // L001d: cmp eax, 0x2
        // L0020: jbe L0065
        // L0022: cmp byte [rdx+0x12], 0x32
        // L0026: jnz L005e
        // L0028: cmp eax, 0x3
        // L002b: jbe L0065
        // L002d: cmp byte [rdx+0x13], 0x38
        // L0031: jnz L005e
        // L0033: cmp eax, 0x4
        // L0036: jbe L0065
        // L0038: cmp byte [rdx+0x14], 0x47
        // L003c: jnz L005e
        // L003e: cmp eax, 0x5
        // L0041: jbe L0065
        // L0043: cmp byte [rdx+0x15], 0x43
        // L0047: jnz L005e
        // L0049: cmp eax, 0x6
        // L004c: jbe L0065
        // L004e: cmp byte [rdx+0x16], 0x4d
        // L0052: jnz L005e
        // L0054: mov eax, 0xc
        // L0059: add rsp, 0x28
        // L005d: ret
        // L005e: xor eax, eax
        // L0060: add rsp, 0x28
        // L0064: ret
        // L0065: call 0x7ffec7e51e00
        // L006a: int3
        [Benchmark]
        [ArgumentsSource(nameof(GetData7))]
        public uint Loop7(byte[] v)
        {
            if (v[0] == (byte)'A' && v[1] == (byte)'1' && v[2] == (byte)'2' && v[3] == (byte)'8' && v[4] == (byte)'G' && v[5] == (byte)'C' && v[6] == (byte)'M')
            {
                return 12;
            }

            return 0;
        }

        // L0000: push ebp
        // L0001: mov ebp, esp
        // L0003: push eax
        // L0004: xor eax, eax
        // L0006: mov [ebp-0x4], eax
        // L0009: mov [ebp-0x4], edx
        // L000c: test edx, edx
        // L000e: jz L0016
        // L0010: cmp dword [edx+0x4], 0x0
        // L0014: jnz L001a
        // L0016: xor eax, eax
        // L0018: jmp L0023
        // L001a: cmp dword [edx+0x4], 0x0
        // L001e: jbe L0044
        // L0020: lea eax, [edx+0x8]
        // L0023: cmp byte [eax], 0x44
        // L0026: jnz L0039
        // L0028: cmp word [eax+0x1], 0x4645
        // L002e: jnz L0039
        // L0030: mov eax, 0xc
        // L0035: mov esp, ebp
        // L0037: pop ebp
        // L0038: ret
        // L0039: xor edx, edx
        // L003b: mov [ebp-0x4], edx
        // L003e: xor eax, eax
        // L0040: mov esp, ebp
        // L0042: pop ebp
        // L0043: ret
        // L0044: call 0x73103480
        // L0049: int3
        [Benchmark]
        [ArgumentsSource(nameof(GetData3))]
        public uint ByteAndUShortWithoutBitMask(byte[] v)
        {
            fixed (byte* pValue = v)
            {
                if (*pValue == (byte)'D' && *(ushort*)(pValue + 1) == 17989u)
                {
                    return 12;
                }
            }

            return 0;
        }

        // L0000: push ebp
        // L0001: mov ebp, esp
        // L0003: push eax
        // L0004: xor eax, eax
        // L0006: mov [ebp-0x4], eax
        // L0009: mov [ebp-0x4], edx
        // L000c: test edx, edx
        // L000e: jz L0016
        // L0010: cmp dword [edx+0x4], 0x0
        // L0014: jnz L001a
        // L0016: xor eax, eax
        // L0018: jmp L0023
        // L001a: cmp dword [edx+0x4], 0x0
        // L001e: jbe L0047
        // L0020: lea eax, [edx+0x8]
        // L0023: mov edx, [eax]
        // L0025: and edx, 0xffffff
        // L002b: cmp edx, 0x464544
        // L0031: jnz L003c
        // L0033: mov eax, 0xc
        // L0038: mov esp, ebp
        // L003a: pop ebp
        // L003b: ret
        // L003c: xor edx, edx
        // L003e: mov [ebp-0x4], edx
        // L0041: xor eax, eax
        // L0043: mov esp, ebp
        // L0045: pop ebp
        // L0046: ret
        // L0047: call 0x73103480
        // L004c: int3
        [Benchmark]
        [ArgumentsSource(nameof(GetData3))]
        public uint UintWithBitMask(byte[] v)
        {
            fixed (byte* pValue = v)
            {
                if ((*((uint*)pValue) & 0x00ffffff) == 4605252u)
                {
                    return 12;
                }
            }

            return 0;
        }

        // L0000: push ebp
        // L0001: mov ebp, esp
        // L0003: push eax
        // L0004: xor eax, eax
        // L0006: mov [ebp-0x4], eax
        // L0009: mov [ebp-0x4], edx
        // L000c: test edx, edx
        // L000e: jz L0016
        // L0010: cmp dword [edx+0x4], 0x0
        // L0014: jnz L001a
        // L0016: xor eax, eax
        // L0018: jmp L0023
        // L001a: cmp dword [edx+0x4], 0x0
        // L001e: jbe L0048
        // L0020: lea eax, [edx+0x8]
        // L0023: cmp dword [eax], 0x38323141
        // L0029: jnz L003d
        // L002b: cmp dword [eax+0x3], 0x4d434738
        // L0032: jnz L003d
        // L0034: mov eax, 0xc
        // L0039: mov esp, ebp
        // L003b: pop ebp
        // L003c: ret
        // L003d: xor edx, edx
        // L003f: mov [ebp-0x4], edx
        // L0042: xor eax, eax
        // L0044: mov esp, ebp
        // L0046: pop ebp
        // L0047: ret
        // L0048: call 0x73103480
        // L004d: int3
        [Benchmark]
        [ArgumentsSource(nameof(GetData7))]

        public uint DoubleIntWithoutBitMask(byte[] v)
        {
            fixed (byte* pValue = v)
            {
                if ((*(uint*)pValue) == 942813505u && *(uint*)(pValue + 3) == 1296254776u)
                {
                    return 12;
                }
            }

            return 0;
        }

        // L0000: push ebp
        // L0001: mov ebp, esp
        // L0003: push esi
        // L0004: push eax
        // L0005: xor eax, eax
        // L0007: mov [ebp-0x8], eax
        // L000a: mov [ebp-0x8], edx
        // L000d: test edx, edx
        // L000f: jz L0017
        // L0011: cmp dword [edx+0x4], 0x0
        // L0015: jnz L001b
        // L0017: xor esi, esi
        // L0019: jmp L0026
        // L001b: cmp dword [edx+0x4], 0x0
        // L001f: jbe L0054
        // L0021: lea eax, [edx+0x8]
        // L0024: mov esi, eax
        // L0026: mov eax, [esi]
        // L0028: mov edx, [esi+0x4]
        // L002b: and edx, 0xffff
        // L0031: cmp edx, 0x4d4347
        // L0037: jnz L0049
        // L0039: cmp eax, 0x38323141
        // L003e: jnz L0049
        // L0040: mov eax, 0xc
        // L0045: pop ecx
        // L0046: pop esi
        // L0047: pop ebp
        // L0048: ret
        // L0049: xor edx, edx
        // L004b: mov [ebp-0x8], edx
        // L004e: xor eax, eax
        // L0050: pop ecx
        // L0051: pop esi
        // L0052: pop ebp
        // L0053: ret
        // L0054: call 0x73103480
        // L0059: int3

        [Benchmark]
        [ArgumentsSource(nameof(GetData7))]
        public uint ULongWithBitMask(byte[] v)
        {
            fixed (byte* pValue = v)
            {
                if ((*((ulong*)pValue) & 0x00ffffffFFFFFF) == 21747546371273025u)
                {
                    return 12;
                }
            }

            return 0;
        }

        // L0000: push ebp
        // L0001: mov ebp, esp
        // L0003: cmp dword [edx+0x4], 0x0
        // L0007: jbe L0025
        // L0009: lea eax, [edx+0x8]
        // L000c: mov eax, [eax]
        // L000e: and eax, 0xffffff
        // L0013: cmp eax, 0x464544
        // L0018: jnz L0021
        // L001a: mov eax, 0xc
        // L001f: pop ebp
        // L0020: ret
        // L0021: xor eax, eax
        // L0023: pop ebp
        // L0024: ret
        // L0025: call 0x73103480
        // L002a: int3
        [Benchmark]
        [ArgumentsSource(nameof(GetData3))]
        public uint UnsafeAsUIntWithBitMask(byte[] v)
        {
            if ((Unsafe.As<byte, uint>(ref v[0]) & 0x00ffffff) == 4605252u)
            {
                return 12;
            }

            return 0;
        }

        // L0000: push ebp
        // L0001: mov ebp, esp
        // L0003: cmp dword [edx+0x4], 0x0
        // L0007: jbe L0025
        // L0009: lea eax, [edx+0x8]
        // L000c: mov eax, [eax]
        // L000e: and eax, 0xffffff
        // L0013: cmp eax, 0x464544
        // L0018: jnz L0021
        // L001a: mov eax, 0xc
        // L001f: pop ebp
        // L0020: ret
        // L0021: xor eax, eax
        // L0023: pop ebp
        // L0024: ret
        // L0025: call 0x73103480
        // L002a: int3
        [Benchmark]
        [ArgumentsSource(nameof(GetData7))]
        public uint UnsafeAsULongWithBitMask(byte[] v)
        {
            if ((Unsafe.As<byte, ulong>(ref v[0]) & 0x00ffffffFFFFFF) == 21747546371273025u)
            {
                return 12;
            }

            return 0;
        }

        // L0000: push ebp
        // L0001: mov ebp, esp
        // L0003: cmp dword [edx+0x4], 0x0
        // L0007: jbe L0025
        // L0009: lea eax, [edx+0x8]
        // L000c: mov eax, [eax]
        // L000e: and eax, 0xffffff
        // L0013: cmp eax, 0x464544
        // L0018: jnz L0021
        // L001a: mov eax, 0xc
        // L001f: pop ebp
        // L0020: ret
        // L0021: xor eax, eax
        // L0023: pop ebp
        // L0024: ret
        // L0025: call 0x73103480
        // L002a: int3
        [Benchmark]
        [ArgumentsSource(nameof(GetData3))]
        public uint UnsafeReadUnaligedUIntWithBitMask(byte[] v)
        {
            if ((Unsafe.ReadUnaligned<uint>(ref v[0]) & 0x00ffffff) == 4605252u)
            {
                return 12;
            }

            return 0;
        }

        // L0000: push ebp
        // L0001: mov ebp, esp
        // L0003: cmp dword [edx+0x4], 0x0
        // L0007: jbe L0025
        // L0009: lea eax, [edx+0x8]
        // L000c: mov eax, [eax]
        // L000e: and eax, 0xffffff
        // L0013: cmp eax, 0x464544
        // L0018: jnz L0021
        // L001a: mov eax, 0xc
        // L001f: pop ebp
        // L0020: ret
        // L0021: xor eax, eax
        // L0023: pop ebp
        // L0024: ret
        // L0025: call 0x73103480
        // L002a: int3
        [Benchmark]
        [ArgumentsSource(nameof(GetData7))]
        public uint UnsafeReadUnaligedULongWithBitMask(byte[] v)
        {
            if ((Unsafe.ReadUnaligned<ulong>(ref v[0]) & 0x00ffffffFFFFFF) == 21747546371273025u)
            {
                return 12;
            }

            return 0;
        }

        public IEnumerable<byte[]> GetData3()
        {
            yield return Encoding.UTF8.GetBytes("DEF\0");
            yield return Encoding.UTF8.GetBytes("DEF");
            yield return Encoding.UTF8.GetBytes("FAKE");
        }
        public IEnumerable<byte[]> GetData7()
        {
            yield return Encoding.UTF8.GetBytes("A128GCM\0");
            yield return Encoding.UTF8.GetBytes("A128GCM");
            yield return Encoding.UTF8.GetBytes("A128GCMFAKE");
        }
    }
}
