# Viking: Spartan with R1CS-Lite

Viking is an experimental fork of [Spartan](https://github.com/microsoft/Spartan) that replaces arbitrary three-matrix R1CS with the two-matrix R1CS-Lite representation described in [Lunar](https://eprint.iacr.org/2020/1069). It retains Spartan's transparent setup and proof architecture while making the output matrix a fixed, verifier-derived projection.

Read [R1CS-Lite in Viking](docs/r1cs-lite.md) for the algebra, implementation, measured value, compatibility limits, and soundness requirements. The main benefit is a smaller and simpler statement representation with less explicit matrix commitment work. It does not remove a third of total proving time, and historical end-to-end timing changes are modest and workload-dependent.

Viking is a research prototype and has not received a security review or audit. Do not use it in production.

See [Viking_Report.pdf](Viking_Report.pdf) for the original theoretical and technical report.

## Historical performance comparison

| Constraint Size | Spartan Proof (ms) | Viking Proof (ms) | Spartan Verify (ms) | Viking Verify (ms) |
|------------------|---------------------|--------------------|----------------------|---------------------|
| $2^{10}$         | 21.946              | 21.395             | 7.1222               | 7.1775              |
| $2^{11}$         | 32.516              | 32.037             | 8.6966               | 8.2115              |
| $2^{12}$         | 50.715              | 49.684             | 10.190               | 9.6508              |
| $2^{13}$         | 84.063              | 83.324             | 12.813               | 12.009              |
| $2^{14}$         | 149.970             | 149.070            | 16.113               | 15.825              |
| $2^{15}$         | 268.650             | 266.770            | 24.390               | 23.215              |
| $2^{16}$         | 509.460             | 506.370            | 38.181               | 36.762              |
| $2^{17}$         | 888.150             | 889.030            | 62.904               | 62.260              |
| $2^{18}$         | 1,750.700           | 1,744.100          | 112.900              | 113.470             |
| $2^{19}$         | 3,140.600           | 3,115.100          | 208.780              | 209.470             |
| $2^{20}$         | 6,243.300           | 6,305.700          | 400.220              | 408.920             |

- Times are in milliseconds and constraint sizes are powers of two.
- These historical measurements are machine- and workload-specific, not a guarantee of improvement. Viking is faster at many sizes and slower at some; most differences are within a few percent.
- The structural saving is clearer than the timing table: Viking stores and commits to two application-specific sparse matrices rather than materializing an identity-like third matrix.

## Highlights

We now highlight Spartan's distinctive features.

- **No "toxic" waste:** Spartan is a _transparent_ zkSNARK and does not require a trusted setup. So, it does not involve any trapdoors that must be kept secret or require a multi-party ceremony to produce public parameters.

- **Output-form constraints:** Viking supports R1CS-Lite instances whose multiplication outputs occupy designated witness positions. Importing arbitrary three-matrix R1CS requires a frontend transformation; see the design note for details.

- **Sub-linear verification costs:** Spartan is the first transparent proof system with sub-linear verification costs for arbitrary NP statements (e.g., R1CS).

- **Standardized security:** Spartan's security relies on the hardness of computing discrete logarithms (a standard cryptographic assumption) in the random oracle model. `libspartan` uses `ristretto255`, a prime-order group abstraction atop `curve25519` (a high-speed elliptic curve). We use [`curve25519-dalek`](https://docs.rs/curve25519-dalek) for arithmetic over `ristretto255`.

- **State-of-the-art performance:**
  Among transparent SNARKs, Spartan offers the fastest prover with speedups of 36–152× depending on the baseline, produces proofs that are shorter by 1.2–416×, and incurs the lowest verification times with speedups of 3.6–1326×. The only exception is proof sizes under Bulletproofs, but Bulletproofs incurs slower verification both asymptotically and concretely. When compared to the state-of-the-art zkSNARK with trusted setup, Spartan’s prover is 2× faster for arbitrary R1CS instances and 16× faster for data-parallel workloads.

### Implementation details

`libspartan` uses [`merlin`](https://docs.rs/merlin/) to automate the Fiat-Shamir transform. We also introduce a new type called `RandomTape` that extends a `Transcript` in `merlin` to allow the prover's internal methods to produce private randomness using its private transcript without having to create `OsRng` objects throughout the code. An object of type `RandomTape` is initialized with a new random seed from `OsRng` for each proof produced by the library.

## Examples

To import `libspartan` into your Rust project, add the following dependency to `Cargo.toml`:

```text
spartan = "0.8.0"
```

The following example shows how to use `libspartan` to create and verify a SNARK proof.
Some of our public APIs' style is inspired by the underlying crates we use.

```rust
extern crate libspartan;
extern crate merlin;
use libspartan::{Instance, SNARKGens, SNARK};
use merlin::Transcript;
fn main() {
    // specify the size of an R1CS instance
    let num_vars = 1024;
    let num_cons = 1024;
    let num_inputs = 10;
    let num_non_zero_entries = 1024;

    // produce public parameters
    let gens = SNARKGens::new(num_cons, num_vars, num_inputs, num_non_zero_entries);

    // ask the library to produce a synthentic R1CS instance
    let (inst, vars, inputs) = Instance::produce_synthetic_r1cs_lite(num_cons, num_vars, num_inputs);

    // create a commitment to the R1CS instance
    let (comm, decomm) = SNARK::encode(&inst, &gens);

    // produce a proof of satisfiability
    let mut prover_transcript = Transcript::new(b"snark_example");
    let proof = SNARK::prove(&inst, &comm, &decomm, vars, &inputs, &gens, &mut prover_transcript);

    // verify the proof of satisfiability
    let mut verifier_transcript = Transcript::new(b"snark_example");
    assert!(proof
      .verify(&comm, &inputs, &mut verifier_transcript, &gens)
      .is_ok());
    println!("proof verification successful!");
}
```

Here is another example to use the NIZK variant of the Spartan proof system:

```rust
extern crate libspartan;
extern crate merlin;
use libspartan::{Instance, NIZKGens, NIZK};
use merlin::Transcript;
fn main() {
    // specify the size of an R1CS instance
    let num_vars = 1024;
    let num_cons = 1024;
    let num_inputs = 10;

    // produce public parameters
    let gens = NIZKGens::new(num_cons, num_vars, num_inputs);

    // ask the library to produce a synthentic R1CS instance
    let (inst, vars, inputs) = Instance::produce_synthetic_r1cs_lite(num_cons, num_vars, num_inputs);

    // produce a proof of satisfiability
    let mut prover_transcript = Transcript::new(b"nizk_example");
    let proof = NIZK::prove(&inst, vars, &inputs, &gens, &mut prover_transcript);

    // verify the proof of satisfiability
    let mut verifier_transcript = Transcript::new(b"nizk_example");
    assert!(proof
      .verify(&inst, &inputs, &mut verifier_transcript, &gens)
      .is_ok());
    println!("proof verification successful!");
}
```

Finally, we provide an example that specifies a custom R1CS instance instead of using a synthetic instance

```rust
#![allow(non_snake_case)]
//! Demonstrates how to produces a proof for canonical cubic equation: `x^3 + x + 5 = y`.
//! The example is described in detail [here].
//!
//! The R1CS for this problem consists of the following 4 constraints:
//! x * 1 = x
//! x * x = a
//! a * a = b
//! b * b = c
//! c * c = d
//! e * e = e
//! (d + 1) * 1 = y
//!
//! [here]: https://medium.com/@VitalikButerin/quadratic-arithmetic-programs-from-zero-to-hero-f6d558cea649
#![allow(non_snake_case)]
#![allow(clippy::assertions_on_result_states)]
use curve25519_dalek::scalar::Scalar;
use libspartan::{InputsAssignment, Instance, SNARKGens, VarsAssignment, SNARK};
use merlin::Transcript;
use rand::rngs::OsRng;

fn r1cs_lite() -> (
  usize,
  usize,
  usize,
  usize,
  Instance,
  VarsAssignment,
  InputsAssignment,
) {
  // parameters of the R1CS instance
  let num_cons = 7;
  let num_vars = 5;
  let num_inputs = 1;
  let num_non_zero_entries = 8;

  // We will encode the above constraints into three matrices, where
  // the coefficients in the matrix are in the little-endian byte order
  let mut A: Vec<(usize, usize, [u8; 32])> = Vec::new();
  let mut B: Vec<(usize, usize, [u8; 32])> = Vec::new();

  let one = Scalar::ONE.to_bytes();

  // R1CSLite instance for y = x^16 + 1
  // Constraints are written in the order of A.B = C
  // For now, C will be identity - Just testing out the correctness of our R1CSLite instance for y = x^16 + 1

  // Constraint 0 is x * 1 = x
  A.push((0, 0,        one));
  B.push((0, num_vars, one));

  // Constraint 1 is x * x = a
  A.push((1, 0, one));
  B.push((1, 0, one));

  // Constraint 2 is a * a = b
  A.push((2, 1, one));
  B.push((2, 1, one));

  // Constraint 3 is b * b = c
  A.push((3, 2, one));
  B.push((3, 2, one));

  // Constraint 4 is c * c = d
  A.push((4, 3, one));
  B.push((4, 3, one));

  // Constraint 5 is 1 * 1 = 1
  A.push((5, num_vars, one));
  B.push((5, num_vars, one));

  // Constraint 6 is (d + 1) * 1 = y
  A.push((6, 4, one));
  A.push((6, num_vars, one));
  B.push((6, num_vars, one));

  let inst = Instance::new(num_cons, num_vars, num_inputs, &A, &B).unwrap();

  // compute a satisfying assignment
  let mut csprng: OsRng = OsRng;
  let z0 = Scalar::random(&mut csprng);
  let z1 = z0 * z0;          // constraint 2
  let z2 = z1 * z1;          // constraint 3
  let z3 = z2 * z2;          // constraint 4
  let z4 = z3 * z3;          // constraint 5
  let i0 = z4 + Scalar::ONE; // constraint 6

  // create a VarsAssignment
  let mut vars = vec![Scalar::ZERO.to_bytes(); num_vars];
  vars[0] = z0.to_bytes();
  vars[1] = z1.to_bytes();
  vars[2] = z2.to_bytes();
  vars[3] = z3.to_bytes();
  vars[4] = z4.to_bytes();
  let assignment_vars = VarsAssignment::new(&vars).unwrap();

  // create an InputsAssignment
  let mut inputs = vec![Scalar::ZERO.to_bytes(); num_inputs];
  inputs[0] = i0.to_bytes();
  let assignment_inputs = InputsAssignment::new(&inputs).unwrap();

  // check if the instance we created is satisfiable
  let res = inst.is_sat(&assignment_vars, &assignment_inputs);
  assert!(res.unwrap(), "should be satisfied");

  (
    num_cons,
    num_vars,
    num_inputs,
    num_non_zero_entries,
    inst,
    assignment_vars,
    assignment_inputs,
  )
}


fn main() {
  // produce an R1CS instance
  let (
    num_cons,
    num_vars,
    num_inputs,
    num_non_zero_entries,
    inst,
    assignment_vars,
    assignment_inputs,
  ) = r1cs_lite();

  // produce public parameters
  let gens = SNARKGens::new(num_cons, num_vars, num_inputs, num_non_zero_entries);

  // create a commitment to the R1CS instance
  let (comm, decomm) = SNARK::encode(&inst, &gens);

  // produce a proof of satisfiability
  let mut prover_transcript = Transcript::new(b"snark_example");
  let proof = SNARK::prove(
    &inst,
    &comm,
    &decomm,
    assignment_vars,
    &assignment_inputs,
    &gens,
    &mut prover_transcript,
  );

  // verify the proof of satisfiability
  let mut verifier_transcript = Transcript::new(b"snark_example");
  assert!(proof
    .verify(&comm, &assignment_inputs, &mut verifier_transcript, &gens)
    .is_ok());
  println!("proof verification successful!");
}
```

For more examples, see [`examples/`](examples) directory in this repo.

## Building `libspartan`

Install [`rustup`](https://rustup.rs/)

Switch to nightly Rust using `rustup`:

```text
rustup default nightly
```

Clone the repository:

```text
git clone https://github.com/Microsoft/Spartan
cd Spartan
```

To build docs for public APIs of `libspartan`:

```text
cargo doc
```

To run tests:

```text
RUSTFLAGS="-C target_cpu=native" cargo test
```

To build `libspartan`:

```text
RUSTFLAGS="-C target_cpu=native" cargo build --release
```

> NOTE: We enable SIMD instructions in `curve25519-dalek` by default, so if it fails to build remove the "simd_backend" feature argument in `Cargo.toml`.

### Supported features

- `std`: enables std features (enabled by default)
- `simd_backend`: enables `curve25519-dalek`'s simd feature (enabled by default)
- `profile`: enables fine-grained profiling information (see below for its use)

### WASM Support

`libspartan` depends upon `rand::OsRng` (internally uses `getrandom` crate), it has out of box support for `wasm32-wasi`.

For the target `wasm32-unknown-unknown` disable default features for spartan
and add direct dependency on `getrandom` with `wasm-bindgen` feature enabled.

```toml
[dependencies]
spartan = { version = "0.7", default-features = false }
# since spartan uses getrandom(rand's OsRng), we need to enable 'wasm-bindgen'
# feature to make it feed rand seed from js/nodejs env
# https://docs.rs/getrandom/0.1.16/getrandom/index.html#support-for-webassembly-and-asmjs
getrandom = { version = "0.1", features = ["wasm-bindgen"] }
```

## Performance

### End-to-end benchmarks

`libspartan` includes two benches: `benches/nizk.rs` and `benches/snark.rs`. If you report the performance of Spartan in a research paper, we recommend using these benches for higher accuracy instead of fine-grained profiling (listed below).

To run end-to-end benchmarks:

```text
RUSTFLAGS="-C target_cpu=native" cargo bench
```

### Fine-grained profiling

Build `libspartan` with `profile` feature enabled. It creates two profilers: `./target/release/snark` and `./target/release/nizk`.

These profilers report performance as depicted below (for varying R1CS instance sizes). The reported
performance is from running the profilers on a Microsoft Surface Laptop 3 on a single CPU core of Intel Core i7-1065G7 running Ubuntu 20.04 (atop WSL2 on Windows 10).
See Section 9 in our [paper](https://eprint.iacr.org/2019/550) to see how this compares with other zkSNARKs in the literature.

```text
  R1CS
  * number_of_constraints 8
  * number_of_variables 8
  * number_of_inputs 1
  * number_non-zero_entries_A 6
  * number_non-zero_entries_B 5
  * number_non-zero_entries_C 5
  * SNARK::encode
  * SNARK::encode 11.254375ms
  * SNARK::prove
    * R1CSProof::prove
      * polycommit
      * polycommit 1.68075ms
      * prove_sc_phase_one
      * prove_sc_phase_one 15.259ms
      * prove_sc_phase_two
      * prove_sc_phase_two 16.849708ms
      * polyeval
      * polyeval 5.274458ms
    * R1CSProof::prove 44.402583ms
    * len_r1cs_sat_proof 3200
    * eval_sparse_polys
    * eval_sparse_polys 53.791µs
    * R1CSEvalProof::prove
      * commit_nondet_witness
      * commit_nondet_witness 6.221959ms
      * build_layered_network
      * build_layered_network 248.208µs
      * evalproof_layered_network
        * len_product_layer_proof 5824
      * evalproof_layered_network 33.430292ms
    * R1CSEvalProof::prove 40.056708ms
    * len_r1cs_eval_proof 7952
  * SNARK::prove 85.051708ms
  * SNARK::verify
    * verify_sat_proof
    * verify_sat_proof 23.51325ms
    * verify_eval_proof
      * verify_polyeval_proof
        * verify_prod_proof
        * verify_prod_proof 2.915125ms
        * verify_hash_proof
        * verify_hash_proof 14.444042ms
      * verify_polyeval_proof 17.42725ms
    * verify_eval_proof 17.570584ms
  * SNARK::verify 41.252333ms
proof verification successful!
```

```text
  R1CSLite
  * number_of_constraints 8
  * number_of_variables 8
  * number_of_inputs 1
  * number_non-zero_entries_A 8
  * number_non-zero_entries_B 7
  * SNARK::encode
  * SNARK::encode 11.490167ms
  * SNARK::prove
    * R1CSLiteProof::prove
      * polycommit
      * polycommit 1.6835ms
      * prove_sc_phase_one
      * prove_sc_phase_one 15.4015ms
      * prove_sc_phase_two
      * prove_sc_phase_two 16.733292ms
      * polyeval
      * polyeval 5.325042ms
    * R1CSLiteProof::prove 44.5465ms
    * len_r1cs_lite_sat_proof 3200
    * eval_sparse_polys
    * eval_sparse_polys 59µs
    * R1CSLiteEvalProof::prove
      * commit_nondet_witness
      * commit_nondet_witness 3.615209ms
      * build_layered_network
      * build_layered_network 242.958µs
      * evalproof_layered_network
        * len_product_layer_proof 4672
      * evalproof_layered_network 32.323041ms
    * R1CSLiteEvalProof::prove 36.304459ms
    * len_r1cs_lite_eval_proof 6448
  * SNARK::prove 81.435791ms
  * SNARK::verify
    * verify_sat_proof
    * verify_sat_proof 23.705916ms
    * verify_eval_proof
      * verify_polyeval_proof
        * verify_prod_proof
        * verify_prod_proof 2.242209ms
        * verify_hash_proof
        * verify_hash_proof 13.755625ms
      * verify_polyeval_proof 16.07675ms
    * verify_eval_proof 16.2215ms
  * SNARK::verify 40.08625ms
proof verification successful!
```

## LICENSE

See [LICENSE](./LICENSE)

## Contributing

See [CONTRIBUTING](./CONTRIBUTING.md)
