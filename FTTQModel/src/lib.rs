use std::cmp::max;

use ndarray::{Array, Array1, Array2, Zip};
use rustfft::{num_complex::Complex, FftPlanner};
use serde::{Deserialize, Serialize};

use crate::ternary::TernaryQuantizer;

#[derive(Serialize, Deserialize)]
pub struct FTTQModel {
    pub weights: Vec<f32>,
    pub num_features: usize,
    pub w: usize,
    pub s: usize,
    pub k: usize,
    pub fft_plan: FFTplanner<f32>,
    pub fft_workspace: Vec<Complex<f32>>,
    pub extraction_features: Vec<ExtractionFeature>,
    pub codebook: Codebook,
}

impl FTTQModel {
    pub fn new(
        num_features: usize,
        w: usize,
        s: usize,
        k: usize,
        extraction_features: Vec<ExtractionFeature>,
        codebook: Codebook,
    ) -> Self {
        let fft_plan = FFTplanner::new(false);
        let fft_len = max(w, s);
        let fft_workspace = vec![Complex::new(0.0, 0.0); fft_len];
        let weights_len = num_features * w * s;
        let weights = vec![0.0; weights_len];

        FTTQModel {
            weights,
            num_features,
            w,
            s,
            k,
            fft_plan,
            fft_workspace,
            extraction_features,
            codebook,
        }
    }

    pub fn new_mut(
        weights: &mut [f32],
        num_features: usize,
        w: usize,
        s: usize,
        k: usize,
        extraction_features: Vec<ExtractionFeature>,
        codebook: Codebook,
    ) -> Self {
        let fft_plan = FFTplanner::new(false);
        let fft_len = max(w, s);
        let fft_workspace = vec![Complex::new(0.0, 0.0); fft_len];
        let weights_len = num_features * w * s;
        assert_eq!(weights_len, weights.len());

        FTTQModel {
            weights: weights.to_vec(),
            num_features,
            w,
            s,
            k,
            fft_plan,
            fft_workspace,
            extraction_features,
            codebook,
        }
    }

    pub fn predict(&self, sample: &Sample) -> bool {
        let mut score = 0.0;

        for i in 0..self.num_features {
            let start = i * self.w * self.s;
            let end = start + self.w * self.s;
            let weights_slice = &self.weights[start..end];
            let fttq = FTTQ::new(weights_slice, self.w, self.s, self.k, &self.fft_plan, &mut self.fft_workspace);
            let feature_score = fttq.score(sample.features[i]);
            score += feature_score;
        }

        score > 0.0
    }

    pub fn update(&mut self, sample: &Sample, alpha: f32) {
        let predicted_class = self.predict(sample);
        let true_class = sample.label;
        if predicted_class != true_class {
            for i in 0..self.num_features {
                let start = i * self.w * self.s;
                let end = start + self.w * self.s;
                let weights_slice = &mut self.weights[start..end];
                let fttq = FTTQ::new_mut(weights_slice, self.w, self.s, self.k, &self.fft_plan, &mut self.fft_workspace);
                fttq.update(sample.features[i], alpha);
            }

            match self.compression {
                Compression::Ternary => {
                    let ternary_threshold = 0.1;
                    for weight in &mut self.weights {
                        if *weight > ternary_threshold {
                            *weight = 1.0;
                        } else if *weight < -ternary_threshold {
                            *weight = -1.0;
                        } else {
                            *weight = 0.0;
                        }
                    }
                }
                _ => (),
            }
        }
    }
}