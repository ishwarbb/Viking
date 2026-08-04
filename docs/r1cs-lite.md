# R1CS-Lite in Viking

Viking adapts Spartan from ordinary R1CS to the R1CS-Lite representation described in [Lunar](https://eprint.iacr.org/2020/1069).

## Representation

An ordinary R1CS instance stores three sparse matrices and checks

$$
(Az) \circ (Bz) = Cz.
$$

Viking accepts only $A$ and $B$. It arranges the witness as

$$
z = (\mathit{vars}_{padded}, 1, \mathit{public\ inputs})
$$

and requires each multiplication gate's output to occupy its designated position in $z$. The omitted $C$ is therefore a fixed projection: it selects unpadded variables first, then the constant and public inputs after the padding gap. Viking constructs this projection virtually when evaluating the relation.

## Why this is useful

For circuits already in this output form, R1CS-Lite has a concrete structural benefit:

- The statement contains two application-specific sparse matrices instead of three.
- SNARK encoding commits to two real matrix polynomials instead of an explicit $C$ polynomial.
- Sparse-matrix evaluation proofs store and process dereference/value data for two real matrices. The protocol still carries a logical third evaluation for compatibility with Spartan's sumcheck, but that evaluation is derived from the fixed projection.
- A frontend does not need to materialize identity-like $C$ entries for every multiplication output.

This reduces statement representation, matrix preprocessing, and commitment work associated with $C$. It does **not** remove a third of total proving or verification time: witness commitments, both sumchecks, transcript operations, and other polynomial proofs remain. The historical measurements in `Viking_Report.pdf` show mostly small, workload-dependent end-to-end differences, generally within a few percent, with some sizes improving and some regressing. The strongest reason to use this optimization is the simpler two-matrix representation and reduced explicit matrix work, not a universal large speedup.

The benefit is most relevant when the number of multiplication gates exceeds the public-input tail and the circuit compiler can emit the required output ordering without expensive rewrites.

## Constraints and compatibility

R1CS-Lite is more restrictive than arbitrary R1CS:

- `Instance::new` accepts entries for $A$ and $B$ only.
- The unpadded variable assignment must have exactly `num_vars` elements.
- Rows must follow output form. For row $i < num_vars$, the product is matched with variable $z_i$. Remaining unpadded rows match the constant/public-input tail after the variable-padding gap.
- An arbitrary $C$ matrix cannot be passed through unchanged. A compiler must reorder or introduce variables and constraints so that $C$ becomes the fixed projection.

These restrictions mean the optimization is valuable when the frontend controls circuit layout. Ordinary R1CS remains more flexible for importing unconstrained three-matrix instances.

## Verification and soundness

The virtual $C$ evaluation is part of the verified relation and must not be trusted as a prover claim. Viking binds the padded and unpadded dimensions into the computation commitment. After sumcheck produces $(r_x, r_y)$, the verifier derives

$$
\widetilde{C}(r_x, r_y)
$$

from those authenticated dimensions and the fixed projection. Serialized SNARKs contain only the claimed $A$ and $B$ evaluations; the implicit-$C$ evaluation is reconstructed during verification.

## Validation

The `bugfixes` integration was validated with Rust 1.97.1:

- 43 library tests passed.
- Every Cargo target compiled.
- NIZK and SNARK Criterion cases through 65,536 constraints completed successfully.
- Clippy completed with warnings only; the repository retains pre-existing formatting and lint warnings.

See [`examples/cubic.rs`](../examples/cubic.rs) for a concrete output-form instance and [Viking_Report.pdf](https://github.com/ishwarbb/Viking/blob/master/Viking_Report.pdf) for the project report and historical comparison data.
