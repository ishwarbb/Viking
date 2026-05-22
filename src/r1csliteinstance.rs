use crate::transcript::AppendToTranscript;

use super::dense_mlpoly::DensePolynomial;
use super::errors::ProofVerifyError;
use super::math::Math;
use super::random::RandomTape;
use super::scalar::Scalar;
use super::sparse_mlpoly::{
  MultiSparseMatPolynomialAsDense, SparseMatEntry, SparseMatPolyCommitment,
  SparseMatPolyCommitmentGens, SparseMatPolyEvalProof, SparseMatPolynomial,
};
use super::timer::Timer;
use flate2::{write::ZlibEncoder, Compression};
use merlin::Transcript;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct R1CSLiteInstance {
  num_cons: usize,
  num_vars: usize,
  num_inputs: usize,
  A: SparseMatPolynomial,
  B: SparseMatPolynomial,
  num_unpadded_cons: usize,
  num_unpadded_vars: usize,
}

pub struct R1CSLiteCommitmentGens {
  gens: SparseMatPolyCommitmentGens,
}

impl R1CSLiteCommitmentGens {
  pub fn new(
    label: &'static [u8],
    num_cons: usize,
    num_vars: usize,
    num_inputs: usize,
    num_nz_entries: usize,
  ) -> R1CSLiteCommitmentGens {
    assert!(num_inputs < num_vars);
    let num_poly_vars_x = num_cons.log_2();
    let num_poly_vars_y = (2 * num_vars).log_2();
    let gens =
      SparseMatPolyCommitmentGens::new(label, num_poly_vars_x, num_poly_vars_y, num_nz_entries, 3);
    R1CSLiteCommitmentGens { gens }
  }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct R1CSLiteCommitment {
  num_cons: usize,
  num_vars: usize,
  num_inputs: usize,
  comm: SparseMatPolyCommitment,
}

impl AppendToTranscript for R1CSLiteCommitment {
  fn append_to_transcript(&self, _label: &'static [u8], transcript: &mut Transcript) {
    transcript.append_u64(b"num_cons", self.num_cons as u64);
    transcript.append_u64(b"num_vars", self.num_vars as u64);
    transcript.append_u64(b"num_inputs", self.num_inputs as u64);
    self.comm.append_to_transcript(b"comm", transcript);
  }
}

pub struct R1CSLiteDecommitment {
  dense: MultiSparseMatPolynomialAsDense,
}

impl R1CSLiteCommitment {
  pub fn get_num_cons(&self) -> usize {
    self.num_cons
  }

  pub fn get_num_vars(&self) -> usize {
    self.num_vars
  }

  pub fn get_num_inputs(&self) -> usize {
    self.num_inputs
  }
}

impl R1CSLiteInstance {
  pub fn new(
    num_cons: usize,
    num_vars: usize,
    num_inputs: usize,
    A: &[(usize, usize, Scalar)],
    B: &[(usize, usize, Scalar)],
    num_unpadded_cons: usize,
    num_unpadded_vars: usize,
  ) -> R1CSLiteInstance {
    Timer::print(&format!("number_of_constraints {num_cons}"));
    Timer::print(&format!("number_of_variables {num_vars}"));
    Timer::print(&format!("number_of_inputs {num_inputs}"));
    Timer::print(&format!("number_non-zero_entries_A {}", A.len()));
    Timer::print(&format!("number_non-zero_entries_B {}", B.len()));

    // check that num_cons is a power of 2
    assert_eq!(num_cons.next_power_of_two(), num_cons);

    // check that num_vars is a power of 2
    assert_eq!(num_vars.next_power_of_two(), num_vars);

    // check that number_inputs + 1 <= num_vars
    assert!(num_inputs < num_vars);

    // no errors, so create polynomials
    let num_poly_vars_x = num_cons.log_2();
    let num_poly_vars_y = (2 * num_vars).log_2();

    let mat_A = A
      .iter()
      .map(|(row, col, val)| SparseMatEntry::new(*row, *col, *val))
      .collect::<Vec<SparseMatEntry>>();
    let mat_B = B
      .iter()
      .map(|(row, col, val)| SparseMatEntry::new(*row, *col, *val))
      .collect::<Vec<SparseMatEntry>>();

    let poly_A = SparseMatPolynomial::new(num_poly_vars_x, num_poly_vars_y, mat_A);
    let poly_B = SparseMatPolynomial::new(num_poly_vars_x, num_poly_vars_y, mat_B);

    Self {
      num_cons,
      num_vars,
      num_inputs,
      A: poly_A,
      B: poly_B,
      num_unpadded_cons,
      num_unpadded_vars,
    }
  }

  pub fn get_num_vars(&self) -> usize {
    self.num_vars
  }

  pub fn get_num_cons(&self) -> usize {
    self.num_cons
  }

  pub fn get_num_inputs(&self) -> usize {
    self.num_inputs
  }

  pub fn get_num_unpadded_cons(&self) -> usize {
    self.num_unpadded_cons
  }

  pub fn get_num_unpadded_vars(&self) -> usize {
    self.num_unpadded_vars
  }

  pub fn get_digest(&self) -> Vec<u8> {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    bincode::serialize_into(&mut encoder, &self).unwrap();
    encoder.finish().unwrap()
  }

  // ! TODO: Create a synthetic R1CSLite instance
  pub fn produce_synthetic_r1cs_lite(
    num_cons: usize,
    num_vars: usize,
    num_inputs: usize,
  ) -> (R1CSLiteInstance, Vec<Scalar>, Vec<Scalar>) {
    Timer::print(&format!("number_of_constraints {num_cons}"));
    Timer::print(&format!("number_of_variables {num_vars}"));
    Timer::print(&format!("number_of_inputs {num_inputs}"));

    let mut csprng: OsRng = OsRng;

    // assert num_cons and num_vars are power of 2
    assert_eq!((num_cons.log_2()).pow2(), num_cons);
    assert_eq!((num_vars.log_2()).pow2(), num_vars);

    // num_inputs + 1 <= num_vars
    assert!(num_inputs < num_vars);

    // z is organized as [vars,1,io]
    let size_z = num_vars + num_inputs + 1;

    // produce a random satisfying assignment
    let Z = {
      let mut Z: Vec<Scalar> = (0..size_z)
        .map(|_i| Scalar::random(&mut csprng))
        .collect::<Vec<Scalar>>();
      Z[num_vars] = Scalar::one(); // set the constant term to 1
      Z
    };

    // two sparse matrices
    let mut A: Vec<SparseMatEntry> = Vec::new();
    let mut B: Vec<SparseMatEntry> = Vec::new();
    let one = Scalar::one();
    for i in 0..num_cons {
      let A_idx = i % size_z;
      A.push(SparseMatEntry::new(i, A_idx, one));
      
      let B_idx = (i + 2) % size_z;
      let z_idx = (i) % size_z;

      let A_val = Z[A_idx];
      let B_val = Z[B_idx];
      let z_val = Z[z_idx];


      if A_val * B_val == Scalar::zero() {
        B.push(SparseMatEntry::new(i, B_idx, one));
      } else {
        B.push(SparseMatEntry::new(i, B_idx, z_val * (A_val * B_val).invert().unwrap()));
      }
    }

    Timer::print(&format!("number_non-zero_entries_A {}", A.len()));
    Timer::print(&format!("number_non-zero_entries_B {}", B.len()));

    let num_poly_vars_x = num_cons.log_2();
    let num_poly_vars_y = (2 * num_vars).log_2();
    let poly_A = SparseMatPolynomial::new(num_poly_vars_x, num_poly_vars_y, A);
    let poly_B = SparseMatPolynomial::new(num_poly_vars_x, num_poly_vars_y, B);

    let inst = R1CSLiteInstance {
      num_cons,
      num_vars,
      num_inputs,
      A: poly_A,
      B: poly_B,
      num_unpadded_cons: num_cons,
      num_unpadded_vars: num_vars,
    };

    assert!(inst.is_sat(&Z[..num_vars], &Z[num_vars + 1..]));

    (inst, Z[..num_vars].to_vec(), Z[num_vars + 1..].to_vec())
  }

  fn pad(&self, z: Vec<Scalar>) -> Vec<Scalar> {
    // Pad the variables vector z to length self.num_vars (the padded variable count).
    // The caller is expected to pass z with z.len() <= self.num_vars; otherwise the
    // subtraction below would underflow.
    assert!(z.len() <= self.num_vars);

    let padded_z = {
      let mut padded_z = z.clone();
      padded_z.extend(vec![Scalar::zero(); self.num_vars - z.len()]);
      padded_z
    };
    padded_z
  }

  fn extend_one_input(&self, z: Vec<Scalar>, input: &[Scalar]) -> Vec<Scalar> {
    let final_z = {
      let mut final_z = z;
      final_z.extend(&vec![Scalar::one()]);
      final_z.extend(input);
      final_z
    };
    final_z
  }

  pub fn is_sat(&self, vars: &[Scalar], input: &[Scalar]) -> bool {
    assert_eq!(input.len(), self.num_inputs);

    let unpad_z =  self.extend_one_input(vars.to_vec(), input);
    let z = {
      let padded_z = self.pad(vars.to_vec());
      self.extend_one_input(padded_z, input)
    };

    // verify if Az * Bz - z[..num_cons] == 0
    let Az = self
      .A
      .multiply_vec(self.num_cons, self.num_vars + self.num_inputs + 1, &z);
    let Bz = self
      .B
      .multiply_vec(self.num_cons, self.num_vars + self.num_inputs + 1, &z);

    assert_eq!(Az.len(), self.num_cons);
    assert_eq!(Bz.len(), self.num_cons);
    // R1CS-Lite constraint: for every (unpadded) constraint i, A_i * B_i == z[i]
    // where z is the unpadded witness vector [vars, 1, inputs].
    // We must check ALL unpadded constraints (not just those producing variables),
    // including the ones that pin down the constant and inputs.
    (0..self.num_unpadded_cons).all(|i| Az[i] * Bz[i] == unpad_z[i])
  }

  pub fn multiply_vec(
    &self,
    num_rows: usize,
    num_cols: usize,
    z: &[Scalar],
  ) -> (DensePolynomial, DensePolynomial, DensePolynomial) {
    assert_eq!(num_rows, self.num_cons);
    assert_eq!(z.len(), num_cols);
    assert!(num_cols > self.num_vars);

    let z_vec: Vec<Scalar> = z.iter().cloned().collect();

    // Build the "projected" witness z_new used by R1CS-Lite's sumcheck.
    // The implicit C matrix picks vars[0..num_unpadded_vars] from the witness for the
    // first num_unpadded_vars constraints, then picks [1, inputs...] starting at index
    // num_vars (the padded boundary, where the constant lives) for the remaining
    // (num_unpadded_cons - num_unpadded_vars) constraints. The rest is padded with zeros.
    let mut z_new: Vec<_> = z_vec.iter().take(self.num_unpadded_vars).cloned().collect();
    z_new.extend(
      z_vec
        .iter()
        .skip(self.num_vars)
        .take(self.num_unpadded_cons - self.num_unpadded_vars),
    );
    z_new.extend(vec![Scalar::zero(); num_rows - z_new.len()]);

    (
      DensePolynomial::new(self.A.multiply_vec(num_rows, num_cols, z)),
      DensePolynomial::new(self.B.multiply_vec(num_rows, num_cols, z)),
      DensePolynomial::new(z_new)
    )
  }

  pub fn compute_eval_table_sparse(
    &self,
    num_rows: usize,
    num_cols: usize,
    evals: &[Scalar],
  ) -> (Vec<Scalar>, Vec<Scalar>) {
    assert_eq!(num_rows, self.num_cons);
    assert!(num_cols > self.num_vars);

    let evals_A = self.A.compute_eval_table_sparse(evals, num_rows, num_cols);
    let evals_B = self.B.compute_eval_table_sparse(evals, num_rows, num_cols);

    (evals_A, evals_B)
  }

  pub fn evaluate(&self, rx: &[Scalar], ry: &[Scalar]) -> (Scalar, Scalar, Scalar) {
    let mut C: Vec<SparseMatEntry> = Vec::new();
    (0..self.num_unpadded_vars).for_each(|i| {
      C.push(SparseMatEntry::new(i, i, Scalar::one()));
    });
    let gap = self.num_vars - self.num_unpadded_vars;
    (self.num_unpadded_vars..self.num_unpadded_cons).for_each(|i| {
      C.push(SparseMatEntry::new(i, i + gap, Scalar::one()));
    });

    let sparse_C = SparseMatPolynomial::new(self.num_cons.log_2(), (2 * self.num_vars).log_2(), C);

    let evals = SparseMatPolynomial::multi_evaluate(&[&self.A, &self.B, &sparse_C], rx, ry);
    (evals[0], evals[1], evals[2])
  }

  pub fn commit(&self, gens: &R1CSLiteCommitmentGens) -> (R1CSLiteCommitment, R1CSLiteDecommitment) {
    let (comm, dense) = SparseMatPolynomial::multi_commit(&[&self.A, &self.B], &gens.gens);
    let r1cs_lite_comm = R1CSLiteCommitment {
      num_cons: self.num_cons,
      num_vars: self.num_vars,
      num_inputs: self.num_inputs,
      comm,
    };

    let r1cs_lite_decomm = R1CSLiteDecommitment { dense };

    (r1cs_lite_comm, r1cs_lite_decomm)
  }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct R1CSLiteEvalProof {
  proof: SparseMatPolyEvalProof,
}

impl R1CSLiteEvalProof {
  pub fn prove(
    decomm: &R1CSLiteDecommitment,
    rx: &[Scalar], // point at which the polynomial is evaluated
    ry: &[Scalar],
    evals: &(Scalar, Scalar, Scalar),
    gens: &R1CSLiteCommitmentGens,
    transcript: &mut Transcript,
    random_tape: &mut RandomTape,
  ) -> R1CSLiteEvalProof {
    let timer = Timer::new("R1CSLiteEvalProof::prove");
    let proof = SparseMatPolyEvalProof::prove(
      &decomm.dense,
      rx,
      ry,
      &[evals.0, evals.1, evals.2],
      &gens.gens,
      transcript,
      random_tape,
    );
    timer.stop();

    R1CSLiteEvalProof { proof }
  }

  pub fn verify(
    &self,
    comm: &R1CSLiteCommitment,
    rx: &[Scalar], // point at which the R1CS matrix polynomials are evaluated
    ry: &[Scalar],
    evals: &(Scalar, Scalar, Scalar),
    gens: &R1CSLiteCommitmentGens,
    transcript: &mut Transcript,
  ) -> Result<(), ProofVerifyError> {
    self.proof.verify(
      &comm.comm,
      rx,
      ry,
      &[evals.0, evals.1, evals.2],
      &gens.gens,
      transcript,
    )
  }
}
