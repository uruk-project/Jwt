``` ini

BenchmarkDotNet=v0.10.14, OS=Windows 7 SP1 (6.1.7601.0)
Intel Core i7-5600U CPU 2.60GHz (Broadwell), 1 CPU, 4 logical and 2 physical cores
Frequency=2533242 Hz, Resolution=394.7511 ns, Timer=TSC
.NET Core SDK=2.1.300
  [Host]     : .NET Core 2.1.0 (CoreCLR 4.6.26515.07, CoreFX 4.6.26515.06), 64bit RyuJIT
  Job-XDKKFQ : .NET Core 2.1.0 (CoreCLR 4.6.26515.07, CoreFX 4.6.26515.06), 64bit RyuJIT

Runtime=Core  Server=True  Toolchain=.NET Core 2.1  
RunStrategy=Throughput  

```
|     Method |      token |          Mean |       Error |      StdDev |        Median |       Op/s | Scaled | ScaledSD |     Gen 0 |     Gen 1 |     Gen 2 | Allocated |
|----------- |----------- |--------------:|------------:|------------:|--------------:|-----------:|-------:|---------:|----------:|----------:|----------:|----------:|
|        **Jwt** |        **big** |    **789.053 us** |  **16.3877 us** |  **40.5063 us** |    **778.857 us** |   **1,267.34** |   **1.00** |     **0.00** |  **191.4063** |  **189.4531** |  **189.4531** |  **877353 B** |
|     Wilson |        big |  3,481.311 us |  69.4407 us | 108.1108 us |  3,465.332 us |     287.25 |   4.42 |     0.25 |  316.4063 |  316.4063 |  316.4063 | 1433229 B |
| JoseDotNet |        big |  2,844.530 us |  92.7671 us | 261.6513 us |  2,721.369 us |     351.55 |   3.61 |     0.38 |  500.0000 |  496.0938 |  496.0938 | 2036108 B |
|  JwtDotNet |        big |  1,218.311 us |  39.2518 us |  48.2048 us |  1,203.622 us |     820.81 |   1.55 |     0.10 |  271.4844 |  269.5313 |  269.5313 | 1197806 B |
|            |            |               |             |             |               |            |        |          |           |           |           |           |
|        **Jwt** |      **empty** |      **2.933 us** |   **0.1122 us** |   **0.2510 us** |      **2.855 us** | **340,987.23** |   **1.00** |     **0.00** |    **0.2480** |         **-** |         **-** |    **6000 B** |
|     Wilson |      empty |      6.464 us |   0.1572 us |   0.4196 us |      6.328 us | 154,710.24 |   2.22 |     0.21 |    0.3128 |         - |         - |    7624 B |
| JoseDotNet |      empty |     13.228 us |   0.2596 us |   0.4042 us |     13.065 us |  75,598.19 |   4.54 |     0.34 |    0.4120 |    0.0305 |         - |   10472 B |
|  JwtDotNet |      empty |      1.409 us |   0.0233 us |   0.0206 us |      1.400 us | 709,874.74 |   0.48 |     0.03 |    0.1373 |         - |         - |    3360 B |
|            |            |               |             |             |               |            |        |          |           |           |           |           |
|        **Jwt** |    **enc-big** |  **2,322.587 us** |  **30.8469 us** |  **27.3450 us** |  **2,311.846 us** |     **430.55** |   **1.00** |     **0.00** |  **351.5625** |  **351.5625** |  **351.5625** | **1713104 B** |
|     Wilson |    enc-big | 10,555.586 us | 209.9773 us | 373.2344 us | 10,502.538 us |      94.74 |   4.55 |     0.17 | 1078.1250 | 1062.5000 | 1062.5000 | 4510663 B |
| JoseDotNet |    enc-big |            NA |          NA |          NA |            NA |         NA |      ? |        ? |       N/A |       N/A |       N/A |       N/A |
|            |            |               |             |             |               |            |        |          |           |           |           |           |
|        **Jwt** |  **enc-empty** |     **51.958 us** |   **1.0191 us** |   **1.6164 us** |     **51.986 us** |  **19,246.14** |   **1.00** |     **0.00** |    **0.9766** |    **0.1221** |         **-** |   **24768 B** |
|     Wilson |  enc-empty |     84.905 us |   1.8022 us |   4.3179 us |     83.135 us |  11,777.86 |   1.64 |     0.10 |    1.8311 |    0.1221 |         - |   44177 B |
| JoseDotNet |  enc-empty |            NA |          NA |          NA |            NA |         NA |      ? |        ? |       N/A |       N/A |       N/A |       N/A |
|            |            |               |             |             |               |            |        |          |           |           |           |           |
|        **Jwt** | **enc-medium** |     **73.723 us** |   **1.5238 us** |   **3.5012 us** |     **71.996 us** |  **13,564.35** |   **1.00** |     **0.00** |    **1.3428** |    **0.1221** |         **-** |   **36400 B** |
|     Wilson | enc-medium |    151.561 us |   0.3208 us |   0.2679 us |    151.492 us |   6,598.02 |   2.06 |     0.09 |    3.1738 |    0.2441 |         - |   81969 B |
| JoseDotNet | enc-medium |            NA |          NA |          NA |            NA |         NA |      ? |        ? |       N/A |       N/A |       N/A |       N/A |
|            |            |               |             |             |               |            |        |          |           |           |           |           |
|        **Jwt** |  **enc-small** |     **61.738 us** |   **1.7006 us** |   **4.8519 us** |     **59.825 us** |  **16,197.41** |   **1.00** |     **0.00** |    **1.0376** |    **0.1221** |         **-** |   **27056 B** |
|     Wilson |  enc-small |    121.326 us |   4.8544 us |  14.3134 us |    124.296 us |   8,242.24 |   1.98 |     0.27 |    1.9531 |         - |         - |   55289 B |
| JoseDotNet |  enc-small |            NA |          NA |          NA |            NA |         NA |      ? |        ? |       N/A |       N/A |       N/A |       N/A |
|            |            |               |             |             |               |            |        |          |           |           |           |           |
|        **Jwt** |     **medium** |     **16.535 us** |   **0.1601 us** |   **0.1419 us** |     **16.483 us** |  **60,476.46** |   **1.00** |     **0.00** |    **0.4883** |         **-** |         **-** |   **12392 B** |
|     Wilson |     medium |     30.706 us |   0.7238 us |   0.6770 us |     30.550 us |  32,567.25 |   1.86 |     0.04 |    0.6104 |         - |         - |   16208 B |
| JoseDotNet |     medium |     34.342 us |   0.7407 us |   1.3729 us |     33.831 us |  29,118.56 |   2.08 |     0.08 |    0.9766 |         - |         - |   24528 B |
|  JwtDotNet |     medium |     23.661 us |   0.4409 us |   0.3908 us |     23.567 us |  42,264.30 |   1.43 |     0.03 |    0.7629 |         - |         - |   18176 B |
|            |            |               |             |             |               |            |        |          |           |           |           |           |
|        **Jwt** |      **small** |      **6.405 us** |   **0.1237 us** |   **0.1097 us** |      **6.416 us** | **156,137.83** |   **1.00** |     **0.00** |    **0.2823** |         **-** |         **-** |    **7048 B** |
|     Wilson |      small |     12.540 us |   0.2461 us |   0.4972 us |     12.309 us |  79,744.14 |   1.96 |     0.08 |    0.3662 |         - |         - |    9528 B |
| JoseDotNet |      small |     19.288 us |   0.3835 us |   0.8812 us |     19.023 us |  51,846.46 |   3.01 |     0.15 |    0.5188 |         - |         - |   13448 B |
|  JwtDotNet |      small |      7.003 us |   0.1393 us |   0.1710 us |      6.970 us | 142,797.68 |   1.09 |     0.03 |    0.2670 |         - |         - |    6736 B |

Benchmarks with issues:
  ReadToken.JoseDotNet: Job-XDKKFQ(Runtime=Core, Server=True, Toolchain=.NET Core 2.1, RunStrategy=Throughput) [token=enc-big]
  ReadToken.JoseDotNet: Job-XDKKFQ(Runtime=Core, Server=True, Toolchain=.NET Core 2.1, RunStrategy=Throughput) [token=enc-empty]
  ReadToken.JoseDotNet: Job-XDKKFQ(Runtime=Core, Server=True, Toolchain=.NET Core 2.1, RunStrategy=Throughput) [token=enc-medium]
  ReadToken.JoseDotNet: Job-XDKKFQ(Runtime=Core, Server=True, Toolchain=.NET Core 2.1, RunStrategy=Throughput) [token=enc-small]
