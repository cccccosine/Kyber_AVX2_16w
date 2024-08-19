# Kyber_AVX2_16w

This is one of the artifacts of the paper titled "Multi-way High-throughput Implementation of Kyber", which has been accepted to [ISC 2024](https://isc24.cs.gmu.edu/). The other artifact is [the 32-way Implementation of Kyber on AVX512](https://github.com/cccccosine/Kyber_AVX512_32w).

## Platform
Operating system: Ubuntu 22.04  
CPU: 11th Gen Intel(R) Core(TM) i7-11700K CPU(Rocket Lake)  

### How to run?

Files:
* main.c : clock cycles and throughput test file
* test_vectors.c : correctness test file

```
#compile and run
make main; ./main  // compile the speed test files and run
make test_vectors; ./test_vectors  //  compile the correctness test files and run
```
