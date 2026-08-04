
#![allow(clippy::too_many_arguments)]
use super::commitments::{Commitments, MultiCommitGens};
use super::dense_mlpoly::{
  DensePolynomial, EqPolynomial, PolyCommitment, PolyCommitmentGens, PolyEvalProof,
};
use super::errors::ProofVerifyError;
use super::group::{CompressedGroup, GroupElement, VartimeMultiscalarMul};
use super::math::Math;
use super::nizk::{EqualityProof, KnowledgeProof, ProductProof};
use super::r1csliteinstance::R1CSLiteInstance;
use super::random::RandomTape;
use super::scalar::Scalar;
use super::sparse_mlpoly::{SparsePolyEntry, SparsePolynomial};
use super::sumcheck::ZKSumcheckInstanceProof;
use super::timer::Timer;
use super::transcript::{AppendToTranscript, ProofTranscript};
use core::iter;
use merlin::Transcript;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct R1CSLiteProof {
  comm_vars: PolyCommitment,
  sc_proof_phase1: ZKSumcheckInstanceProof,
  claims_phase2: (
    CompressedGroup,
    CompressedGroup,
    CompressedGroup,
    CompressedGroup,
  ),
  pok_claims_phase2: (KnowledgeProof, ProductProof),
  proof_eq_sc_phase1: EqualityProof,
  sc_proof_phase2: ZKSumcheckInstanceProof,
  comm_vars_at_ry: CompressedGroup,
  proof_eval_vars_at_ry: PolyEvalProof,
  proof_eq_sc_phase2: EqualityProof,
}

pub struct R1CSLiteSumcheckGens {
  gens_1: MultiCommitGens,
  gens_3: MultiCommitGens,
  gens_4: MultiCommitGens,
}

// TODO: fix passing gens_1_ref
impl R1CSLiteSumcheckGens {
  pub fn new(label: &'static [u8], gens_1_ref: &MultiCommitGens) -> Self {
    let gens_1 = gens_1_ref.clone();
    let gens_3 = MultiCommitGens::new(3, label);
    let gens_4 = MultiCommitGens::new(4, label);

    R1CSLiteSumcheckGens {
      gens_1,
      gens_3,
      gens_4,
    }
  }
}

pub struct R1CSLiteGens {
  gens_sc: R1CSLiteSumcheckGens,
  gens_pc: PolyCommitmentGens,
}

impl R1CSLiteGens {
  pub fn new(label: &'static [u8], _num_cons: usize, num_vars: usize) -> Self {
    let num_poly_vars = num_vars.log_2();
    let gens_pc = PolyCommitmentGens::new(num_poly_vars, label);
    let gens_sc = R1CSLiteSumcheckGens::new(label, &gens_pc.gens.gens_1);
    R1CSLiteGens { gens_sc, gens_pc }
  }
}

impl R1CSLiteProof {
  fn prove_phase_one(
    num_rounds: usize,
    evals_tau: &mut DensePolynomial,
    evals_Az: &mut DensePolynomial,
    evals_Bz: &mut DensePolynomial,
    evals_z: &mut DensePolynomial,
    gens: &R1CSLiteSumcheckGens,
    transcript: &mut Transcript,
    random_tape: &mut RandomTape,
  ) -> (ZKSumcheckInstanceProof, Vec<Scalar>, Vec<Scalar>, Scalar) {
    let comb_func = |poly_A_comp: &Scalar,
                     poly_B_comp: &Scalar,
                     poly_C_comp: &Scalar,
                     poly_D_comp: &Scalar|
     -> Scalar { poly_A_comp * (poly_B_comp * poly_C_comp - poly_D_comp) };

    let (sc_proof_phase_one, r, claims, blind_claim_postsc) =
      ZKSumcheckInstanceProof::prove_cubic_with_additive_term(
        &Scalar::zero(), // claim is zero
        &Scalar::zero(), // blind for claim is also zero
        num_rounds,
        evals_tau,
        evals_Az,
        evals_Bz,
        evals_z,
        comb_func,
        &gens.gens_1,
        &gens.gens_4,
        transcript,
        random_tape,
      );

    (sc_proof_phase_one, r, claims, blind_claim_postsc)
  }

  fn prove_phase_two(
    num_rounds: usize,
    claim: &Scalar,
    blind_claim: &Scalar,
    evals_z: &mut DensePolynomial,
    evals_ABz: &mut DensePolynomial,
    gens: &R1CSLiteSumcheckGens,
    transcript: &mut Transcript,
    random_tape: &mut RandomTape,
  ) -> (ZKSumcheckInstanceProof, Vec<Scalar>, Vec<Scalar>, Scalar) {
    let comb_func =
      |poly_A_comp: &Scalar, poly_B_comp: &Scalar| -> Scalar { poly_A_comp * poly_B_comp };
    let (sc_proof_phase_two, r, claims, blind_claim_postsc) = ZKSumcheckInstanceProof::prove_quad(
      claim,
      blind_claim,
      num_rounds,
      evals_z,
      evals_ABz,
      comb_func,
      &gens.gens_1,
      &gens.gens_3,
      transcript,
      random_tape,
    );

    (sc_proof_phase_two, r, claims, blind_claim_postsc)
  }

  fn protocol_name() -> &'static [u8] {
    b"R1CSLite proof"
  }

  pub fn prove(
    inst: &R1CSLiteInstance,
    vars: Vec<Scalar>,
    input: &[Scalar],
    gens: &R1CSLiteGens,
    transcript: &mut Transcript,
    random_tape: &mut RandomTape,
  ) -> (R1CSLiteProof, Vec<Scalar>, Vec<Scalar>) {
    let timer_prove = Timer::new("R1CSLiteProof::prove");
    transcript.append_protocol_name(R1CSLiteProof::protocol_name());

    // we currently require the number of |inputs| + 1 to be at most number of vars
    assert!(input.len() < vars.len());

    input.append_to_transcript(b"input", transcript);

    let timer_commit = Timer::new("polycommit");
    let (poly_vars, comm_vars, blinds_vars) = {
      // create a multilinear polynomial using the supplied assignment for variables
      let poly_vars = DensePolynomial::new(vars.clone());

      // produce a commitment to the satisfying assignment
      let (comm_vars, blinds_vars) = poly_vars.commit(&gens.gens_pc, Some(random_tape));

      // add the commitment to the prover's transcript
      comm_vars.append_to_transcript(b"poly_commitment", transcript);
      (poly_vars, comm_vars, blinds_vars)
    };
    timer_commit.stop();

    let timer_sc_proof_phase1 = Timer::new("prove_sc_phase_one");

    // append input to variables to create a single vector z
    let z = {
      let num_inputs = input.len();
      let num_vars = vars.len();
      let mut z = vars;
      z.extend(&vec![Scalar::one()]); // add constant term in z
      z.extend(input);
      z.extend(&vec![Scalar::zero(); num_vars - num_inputs - 1]); // we will pad with zeros
      z
    };

    // derive the verifier's challenge tau
    let (num_rounds_x, num_rounds_y) = (inst.get_num_cons().log_2(), z.len().log_2());
    let tau = transcript.challenge_vector(b"challenge_tau", num_rounds_x);
    // compute the initial evaluation table for R(\tau, x)
    let mut poly_tau = DensePolynomial::new(EqPolynomial::new(tau).evals());
    let (mut poly_Az, mut poly_Bz, mut poly_z) =
      inst.multiply_vec(inst.get_num_cons(), z.len(), &z);

    let (sc_proof_phase1, rx, _claims_phase1, blind_claim_postsc1) = R1CSLiteProof::prove_phase_one(
      num_rounds_x,
      &mut poly_tau,
      &mut poly_Az,
      &mut poly_Bz,
      &mut poly_z,
      &gens.gens_sc,
      transcript,
      random_tape,
    );
    assert_eq!(poly_tau.len(), 1);
    assert_eq!(poly_Az.len(), 1);
    assert_eq!(poly_Bz.len(), 1);
    assert_eq!(poly_z.len(), 1);
    timer_sc_proof_phase1.stop();

    let (tau_claim, Az_claim, Bz_claim, z_claim) =
      (&poly_tau[0], &poly_Az[0], &poly_Bz[0], &poly_z[0]);
    let (Az_blind, Bz_blind, z_blind, prod_Az_Bz_blind) = (
      random_tape.random_scalar(b"Az_blind"),
      random_tape.random_scalar(b"Bz_blind"),
      random_tape.random_scalar(b"z_blind"),
      random_tape.random_scalar(b"prod_Az_Bz_blind"),
    );

    let (pok_z_claim, comm_z_claim) = {
      KnowledgeProof::prove(
        &gens.gens_sc.gens_1,
        transcript,
        random_tape,
        z_claim,
        &z_blind,
      )
    };

    let (proof_prod, comm_Az_claim, comm_Bz_claim, comm_prod_Az_Bz_claims) = {
      let prod = Az_claim * Bz_claim;
      ProductProof::prove(
        &gens.gens_sc.gens_1,
        transcript,
        random_tape,
        Az_claim,
        &Az_blind,
        Bz_claim,
        &Bz_blind,
        &prod,
        &prod_Az_Bz_blind,
      )
    };

    comm_Az_claim.append_to_transcript(b"comm_Az_claim", transcript);
    comm_Bz_claim.append_to_transcript(b"comm_Bz_claim", transcript);
    comm_z_claim.append_to_transcript(b"comm_z_claim", transcript);
    comm_prod_Az_Bz_claims.append_to_transcript(b"comm_prod_Az_Bz_claims", transcript);

    // prove the final step of sum-check #1
    let taus_bound_rx = tau_claim;
    let blind_expected_claim_postsc1 = taus_bound_rx * (prod_Az_Bz_blind - z_blind);
    let claim_post_phase1 = (Az_claim * Bz_claim - z_claim) * taus_bound_rx;
    let (proof_eq_sc_phase1, _C1, _C2) = EqualityProof::prove(
      &gens.gens_sc.gens_1,
      transcript,
      random_tape,
      &claim_post_phase1,
      &blind_expected_claim_postsc1,
      &claim_post_phase1,
      &blind_claim_postsc1,
    );

    let timer_sc_proof_phase2 = Timer::new("prove_sc_phase_two");
    // combine the three claims into a single claim
    let r_A = transcript.challenge_scalar(b"challenege_Az");
    let r_B = transcript.challenge_scalar(b"challenege_Bz");
    let r_z = transcript.challenge_scalar(b"challenege_z");
    let claim_phase2 = r_A * Az_claim + r_B * Bz_claim + r_z * z_claim;
    let blind_claim_phase2 = r_A * Az_blind + r_B * Bz_blind + r_z * z_blind;

    let evals_ABz = {
      // compute the initial evaluation table for R(\tau, x)
      let evals_rx = EqPolynomial::new(rx.clone()).evals();
      let (evals_A, evals_B) =
        inst.compute_eval_table_sparse(inst.get_num_cons(), z.len(), &evals_rx);

      let mut evals_C = vec![Scalar::zero(); z.len()];
      (0..inst.get_num_unpadded_vars())
        .for_each(|i| evals_C[i] += evals_rx[i] * Scalar::one());
      let gap = inst.get_num_vars() - inst.get_num_unpadded_vars();
      (inst.get_num_unpadded_vars()..inst.get_num_unpadded_cons())
        .for_each(|i| evals_C[i + gap] += evals_rx[i] * Scalar::one());

      assert_eq!(evals_A.len(), evals_B.len());
      assert_eq!(evals_A.len(), evals_C.len());

      (0..evals_A.len())
      .map(|i| {
        r_A * evals_A[i] + r_B * evals_B[i] + r_z * evals_C[i]
        })
        .collect::<Vec<Scalar>>()
    };

    // another instance of the sum-check protocol
    let (sc_proof_phase2, ry, claims_phase2, blind_claim_postsc2) = R1CSLiteProof::prove_phase_two(
      num_rounds_y,
      &claim_phase2,
      &blind_claim_phase2,
      &mut DensePolynomial::new(z),
      &mut DensePolynomial::new(evals_ABz),
      &gens.gens_sc,
      transcript,
      random_tape,  
    );
    timer_sc_proof_phase2.stop();

    let timer_polyeval = Timer::new("polyeval");
    let eval_vars_at_ry = poly_vars.evaluate(&ry[1..]);
    let blind_eval = random_tape.random_scalar(b"blind_eval");
    let (proof_eval_vars_at_ry, comm_vars_at_ry) = PolyEvalProof::prove(
      &poly_vars,
      Some(&blinds_vars),
      &ry[1..],
      &eval_vars_at_ry,
      Some(&blind_eval),
      &gens.gens_pc,
      transcript,
      random_tape,
    );
    timer_polyeval.stop();

    // prove the final step of sum-check #2
    let blind_eval_Z_at_ry = (Scalar::one() - ry[0]) * blind_eval;
    let blind_expected_claim_postsc2 = claims_phase2[1] * blind_eval_Z_at_ry;
    let claim_post_phase2 = claims_phase2[0] * claims_phase2[1];
    let (proof_eq_sc_phase2, _C1, _C2) = EqualityProof::prove(
      &gens.gens_pc.gens.gens_1,
      transcript,
      random_tape,
      &claim_post_phase2,
      &blind_expected_claim_postsc2,
      &claim_post_phase2,
      &blind_claim_postsc2,
    );

    timer_prove.stop();

    (
      R1CSLiteProof {
        comm_vars,
        sc_proof_phase1,
        claims_phase2: (
          comm_Az_claim,
          comm_Bz_claim,
          comm_z_claim,
          comm_prod_Az_Bz_claims,
        ),
        pok_claims_phase2: (pok_z_claim, proof_prod),
        proof_eq_sc_phase1,
        sc_proof_phase2,
        comm_vars_at_ry,
        proof_eval_vars_at_ry,
        proof_eq_sc_phase2,
      },
      rx,
      ry,
    )
  }

  pub fn verify(
    &self,
    num_vars: usize,
    num_cons: usize,
    num_unpadded_vars: usize,
    num_unpadded_cons: usize,
    input: &[Scalar],
    evals: &(Scalar, Scalar),
    transcript: &mut Transcript,
    gens: &R1CSLiteGens,
  ) -> Result<(Vec<Scalar>, Vec<Scalar>), ProofVerifyError> {
    if !num_cons.is_power_of_two()
      || !num_vars.is_power_of_two()
      || num_vars.checked_mul(2).is_none()
      || num_unpadded_cons > num_cons
      || num_unpadded_vars > num_vars
      || num_unpadded_vars > num_unpadded_cons
      || input.len() >= num_vars
    {
      return Err(ProofVerifyError::InternalError);
    }

    transcript.append_protocol_name(R1CSLiteProof::protocol_name());

    input.append_to_transcript(b"input", transcript);

    let n = num_vars;
    // add the commitment to the verifier's transcript
    self
      .comm_vars
      .append_to_transcript(b"poly_commitment", transcript);

    let (num_rounds_x, num_rounds_y) = (num_cons.log_2(), (2 * num_vars).log_2());

    // derive the verifier's challenge tau
    let tau = transcript.challenge_vector(b"challenge_tau", num_rounds_x);

    // verify the first sum-check instance
    let claim_phase1 = Scalar::zero()
      .commit(&Scalar::zero(), &gens.gens_sc.gens_1)
      .compress();
    let (comm_claim_post_phase1, rx) = self.sc_proof_phase1.verify(
      &claim_phase1,
      num_rounds_x,
      3,
      &gens.gens_sc.gens_1,
      &gens.gens_sc.gens_4,
      transcript,
    )?;
    // perform the intermediate sum-check test with claimed Az, Bz, and z
    let (comm_Az_claim, comm_Bz_claim, comm_z_claim, comm_prod_Az_Bz_claims) = &self.claims_phase2;
    let (pok_z_claim, proof_prod) = &self.pok_claims_phase2;

    pok_z_claim.verify(&gens.gens_sc.gens_1, transcript, comm_z_claim)?;
    proof_prod.verify(
      &gens.gens_sc.gens_1,
      transcript,
      comm_Az_claim,
      comm_Bz_claim,
      comm_prod_Az_Bz_claims,
    )?;

    comm_Az_claim.append_to_transcript(b"comm_Az_claim", transcript);
    comm_Bz_claim.append_to_transcript(b"comm_Bz_claim", transcript);
    comm_z_claim.append_to_transcript(b"comm_z_claim", transcript);
    comm_prod_Az_Bz_claims.append_to_transcript(b"comm_prod_Az_Bz_claims", transcript);

    let taus_bound_rx: Scalar = (0..rx.len())
      .map(|i| rx[i] * tau[i] + (Scalar::one() - rx[i]) * (Scalar::one() - tau[i]))
      .product();
    let expected_claim_post_phase1 = (taus_bound_rx
      * (comm_prod_Az_Bz_claims.decompress().unwrap() - comm_z_claim.decompress().unwrap()))
    .compress();

    // verify proof that expected_claim_post_phase1 == claim_post_phase1
    self.proof_eq_sc_phase1.verify(
      &gens.gens_sc.gens_1,
      transcript,
      &expected_claim_post_phase1,
      &comm_claim_post_phase1,
    )?;

    // derive three public challenges and then derive a joint claim
    let r_A = transcript.challenge_scalar(b"challenege_Az");
    let r_B = transcript.challenge_scalar(b"challenege_Bz");
    let r_z = transcript.challenge_scalar(b"challenege_z");

    // r_A * comm_Az_claim + r_B * comm_Bz_claim + r_C * comm_Cz_claim;
    let comm_claim_phase2 = GroupElement::vartime_multiscalar_mul(
      iter::once(&r_A)
        .chain(iter::once(&r_B))
        .chain(iter::once(&r_z)),
      iter::once(&comm_Az_claim)
        .chain(iter::once(&comm_Bz_claim))
        .chain(iter::once(&comm_z_claim))
        .map(|pt| pt.decompress().unwrap())
        .collect::<Vec<GroupElement>>(),
    )
    .compress();

    // verify the joint claim with a sum-check protocol
    let (comm_claim_post_phase2, ry) = self.sc_proof_phase2.verify(
      &comm_claim_phase2,
      num_rounds_y,
      2,
      &gens.gens_sc.gens_1,
      &gens.gens_sc.gens_3,
      transcript,
    )?;

    // verify Z(ry) proof against the initial commitment
    self.proof_eval_vars_at_ry.verify(
      &gens.gens_pc,
      transcript,
      &ry[1..],
      &self.comm_vars_at_ry,
      &self.comm_vars,
    )?;

    let poly_input_eval = {
      // constant term
      let mut input_as_sparse_poly_entries = vec![SparsePolyEntry::new(0, Scalar::one())];
      //remaining inputs
      input_as_sparse_poly_entries.extend(
        (0..input.len())
          .map(|i| SparsePolyEntry::new(i + 1, input[i]))
          .collect::<Vec<SparsePolyEntry>>(),
      );
      SparsePolynomial::new(n.log_2(), input_as_sparse_poly_entries).evaluate(&ry[1..])
    };

    // compute commitment to eval_Z_at_ry = (Scalar::one() - ry[0]) * self.eval_vars_at_ry + ry[0] * poly_input_eval
    let comm_eval_Z_at_ry = GroupElement::vartime_multiscalar_mul(
      iter::once(Scalar::one() - ry[0]).chain(iter::once(ry[0])),
      iter::once(&self.comm_vars_at_ry.decompress().unwrap()).chain(iter::once(
        &poly_input_eval.commit(&Scalar::zero(), &gens.gens_pc.gens.gens_1),
      )),
    );

    // perform the final check in the second sum-check protocol
    let (eval_A_r, eval_B_r) = evals;
    let eval_z_r = R1CSLiteInstance::evaluate_implicit_c(
      num_cons,
      num_vars,
      num_unpadded_cons,
      num_unpadded_vars,
      &rx,
      &ry,
    );
    let expected_claim_post_phase2 =
      ((r_A * eval_A_r + r_B * eval_B_r + r_z * eval_z_r) * comm_eval_Z_at_ry).compress();
    // verify proof that expected_claim_post_phase1 == claim_post_phase1
    self.proof_eq_sc_phase2.verify(
      &gens.gens_sc.gens_1,
      transcript,
      &expected_claim_post_phase2,
      &comm_claim_post_phase2,
    )?;

    Ok((rx, ry))
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use rand::rngs::OsRng;

  fn produce_tiny_r1cs_lite() -> (R1CSLiteInstance, Vec<Scalar>, Vec<Scalar>) {
    let num_unpadded_cons: usize = 8;
    let num_unpadded_vars: usize = 5;
    let num_inputs = 2;
    let num_cons = num_unpadded_cons.next_power_of_two();
    let num_vars = num_unpadded_vars.next_power_of_two();
    let constant = num_vars;
    let input_0 = constant + 1;
    let input_1 = constant + 2;

    let mut A: Vec<(usize, usize, Scalar)> = Vec::new();
    let mut B: Vec<(usize, usize, Scalar)> = Vec::new();

    let one = Scalar::one();
    A.push((0, input_0, one));
    B.push((0, input_1, one));
    A.push((1, 0, one));
    B.push((1, 0, one));
    A.push((2, 0, one));
    A.push((2, 1, one));
    B.push((2, input_0, one));
    A.push((3, 0, one));
    A.push((3, input_1, one));
    B.push((3, 2, one));
    A.push((5, constant, one));
    B.push((5, constant, one));
    A.push((6, constant, one));
    B.push((6, input_0, one));
    A.push((7, constant, one));
    B.push((7, input_1, one));

    let inst = R1CSLiteInstance::new(num_cons, num_vars, num_inputs, &A, &B, num_unpadded_cons, num_unpadded_vars);

    // compute a satisfying assignment
    let mut csprng: OsRng = OsRng;
    let i0 = Scalar::random(&mut csprng);
    let i1 = Scalar::random(&mut csprng);
    let z1 = i0 * i1;
    let z2 = z1 * z1;
    let z3 = (z1 + z2) * i0;
    let z4 = (z1 + i1) * z3;
    let z5 = Scalar::zero();

    let mut vars = vec![Scalar::zero(); num_vars];
    vars[0] = z1;
    vars[1] = z2;
    vars[2] = z3;
    vars[3] = z4;
    vars[4] = z5;

    let mut input = vec![Scalar::zero(); num_inputs];
    input[0] = i0;
    input[1] = i1;

    (inst, vars, input)
  }

  #[test]
  fn test_tiny_r1cs_lite() {
    let (inst, vars, input) = tests::produce_tiny_r1cs_lite();
    let is_sat = inst.is_sat(&vars[..inst.get_num_unpadded_vars()], &input);
    assert!(is_sat);
  }

  #[test]
  fn test_synthetic_r1cs_lite() {
    let (inst, vars, input) = R1CSLiteInstance::produce_synthetic_r1cs_lite(1024, 1024, 10);
    let is_sat = inst.is_sat(&vars, &input);
    assert!(is_sat);
  }

  #[test]
  pub fn check_r1cs_lite_proof() {
    let num_vars = 1024;
    let num_cons = num_vars;
    let num_inputs = 10;
    let (inst, vars, input) = R1CSLiteInstance::produce_synthetic_r1cs_lite(num_cons, num_vars, num_inputs);

    let gens = R1CSLiteGens::new(b"test-m", num_cons, num_vars);

    let mut random_tape = RandomTape::new(b"proof");
    let mut prover_transcript = Transcript::new(b"example");
    let (proof, rx, ry) = R1CSLiteProof::prove(
      &inst,
      vars,
      &input,
      &gens,
      &mut prover_transcript,
      &mut random_tape,
    );

    let inst_evals = inst.evaluate(&rx, &ry);
    let inst_evals_ab = (inst_evals.0, inst_evals.1);


    let mut verifier_transcript = Transcript::new(b"example");
    assert!(proof
      .verify(
        inst.get_num_vars(),
        inst.get_num_cons(),
        inst.get_num_unpadded_vars(),
        inst.get_num_unpadded_cons(),
        &input,
        &inst_evals_ab,
        &mut verifier_transcript,
        &gens,
      )
      .is_ok());
  }
}
