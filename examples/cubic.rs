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

fn r1cs() -> (
  usize,
  usize,
  usize,
  usize,
  Instance,
  VarsAssignment,
  InputsAssignment,
) {
  // parameters of the R1CS instance
  let num_cons = 5;
  let num_vars = 5;
  let num_inputs = 1;
  let num_non_zero_entries = 6;

  // We will encode the above constraints into three matrices, where
  // the coefficients in the matrix are in the little-endian byte order
  let mut A: Vec<(usize, usize, [u8; 32])> = Vec::new();
  let mut B: Vec<(usize, usize, [u8; 32])> = Vec::new();
  let mut C: Vec<(usize, usize, [u8; 32])> = Vec::new();

  let one = Scalar::ONE.to_bytes();

  // R1CSLite instance for y = x^16 + 1
  // Constraints are written in the order of A.B = C
  // For now, C will be identity - Just testing out the correctness of our R1CSLite instance for y = x^16 + 1

  // Constraint 0 is x * x = a
  A.push((0, 0, one));
  B.push((0, 0, one));
  C.push((0, 1, one));

  // Constraint 1 is a * a = b
  A.push((1, 1, one));
  B.push((1, 1, one));
  C.push((1, 2, one));

  // Constraint 2 is b * b = c
  A.push((2, 2, one));
  B.push((2, 2, one));
  C.push((2, 3, one));

  // Constraint 3 is c * c = d
  A.push((3, 3, one));
  B.push((3, 3, one));
  C.push((3, 4, one));

  // Constraint 4 is (d + 1) * 1 = y
  A.push((4, 4, one));
  A.push((4, num_vars,     one));
  B.push((4, num_vars,     one));
  C.push((4, num_vars + 1, one));

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
