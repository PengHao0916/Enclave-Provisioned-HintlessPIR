# Historical README — legacy claims, not current validation results

This file is archived from the previous implementation. Its claimed security,
novelty, bandwidth, throughput, and storage properties have not been validated
for the current protocol. See ../local_material/README.md for the active local
prototype, measured accounting, and evidence boundaries.

This repository contains the implementation of the paper **"Dual-Side Optimization for HintlessPIR: Achieving Practical Bidirectional Communication Efficiency"**.

Built upon the [HintlessPIR](https://eprint.iacr.org/2023/1733) framework, this project addresses the critical bidirectional communication bottlenecks in single-server Private Information Retrieval (PIR). By introducing a dual-side optimization strategy, we achieve significant bandwidth reductions and throughput improvements while maintaining the "hintless" property (i.e., no database-dependent client storage).

## 🚀 Key Contributions

While the original HintlessPIR eliminates client-side storage, it fundamentally shifts the burden to the network, causing a "bandwidth explosion." Our work resolves this via two core optimizations:

1.  **Downlink Optimization (Asymmetric Response Decomposition):**
    * **Mechanism:** Structurally isolates static public components from the response ciphertext and offloads them to an offline phase.
    * **Impact:** Mathematically guarantees a **50% reduction** in the online response payload.

2.  **Uplink Optimization (Session-Based Key Caching):**
    * **Mechanism:** Implements server-side caching for homomorphic evaluation keys, treating them as session-invariant.
    * **Impact:** Reduces uplink query sizes by up to **74%** for subsequent requests.

## 📊 Performance

Our approach establishes a new practical equilibrium between throughput and communication efficiency.

### Bandwidth Reduction (1 GB Database)
| Metric | Baseline (HintlessPIR) | **Ours (Dual-Side Optimized)** | Improvement |
| :--- | :--- | :--- | :--- |
| **Response Size (Download)** | ~1.45 MB | **~0.76 MB** | 📉 **-50%** |
| **Query Size (Upload)** | ~365 KB | **~95 KB** | 📉 **-74%** |

### Throughput
By eliminating redundant computations of static artifacts, our scheme achieves a **1.17× improvement** in server throughput compared to the baseline.

## 🧩 Background: HintlessPIR

Private Information Retrieval (PIR) allows a client to retrieve a record from a database without revealing which record was selected.

* **Single-Server PIR:** Uses Homomorphic Encryption (HE) to process encrypted queries over the database.
* **Hintless Setting:** The client stores no database-dependent state ("hint"), and the server stores no client-specific state. This simplifies database updates and client deployment.

This library is based on the original [HintlessPIR implementation](https://github.com/google/hintless_pir) by Li et al., which utilizes LWE-based SimplePIR and outsources hint computation to the server via LinPIR.

## 🛠️ Installation & Build

This project uses [Bazel](https://bazel.build/) for building and testing.

### Prerequisites
* Bazel
* C++17 compatible compiler

### Building
Clone the repository and run the tests to verify the installation:

```bash
# Run all tests
bazel test //...

# Run benchmarks
bazel run -c opt //hintless_simplepir:hintless_simplepir_benchmarks
