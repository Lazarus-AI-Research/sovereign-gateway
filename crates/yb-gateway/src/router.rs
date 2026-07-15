//! [`DeploymentRouter`]: the LiteLLM-style model → deployment resolver.
//!
//! The live model list is owned by the database, so the router holds a
//! hot-swappable [`Snapshot`] behind an `RwLock<Arc<…>>`. [`Router::resolve`]:
//!
//! 1. expands the requested public model into its deployments,
//! 2. filters by `excluded_models`, the optional `enabled_providers` allowlist,
//!    and the `denied_providers` denylist on the [`RouteRequest`],
//! 3. orders the survivors by the configured [`Strategy`]
//!    (weighted shuffle / round-robin / approximate least-busy), and
//! 4. appends each fallback model's deployments (same filtering), de-duplicated.
//!
//! An empty candidate list after filtering is reported as
//! [`Error::NoEligibleProvider`] — never an empty success.
//!
//! [`reload`](DeploymentRouter::reload) atomically swaps in a new snapshot built
//! from the current database deployments after an admin mutation; in-flight
//! `resolve` calls keep using the snapshot they observed.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};

use yb_core::config::Strategy;
use yb_core::{Decision, Deployment, DeploymentRecord, Error, Result, RouteRequest, Router};

/// One public model's resolved deployments plus per-model selection state used
/// by the round-robin and least-busy strategies.
struct ModelEntry {
    deployments: Vec<Deployment>,
    rr: AtomicUsize,
    load: Vec<AtomicUsize>,
}

/// An immutable view of the routing table. Swapped wholesale on reload.
struct Snapshot {
    models: HashMap<String, ModelEntry>,
    fallbacks: HashMap<String, Vec<String>>,
    /// Public alias → target model name. Applied before resolution.
    aliases: HashMap<String, String>,
    strategy: Strategy,
}

impl Snapshot {
    /// Group a flat deployment list by public model name (insertion order
    /// preserved within a model).
    fn build(
        deployments: Vec<Deployment>,
        fallbacks: HashMap<String, Vec<String>>,
        aliases: HashMap<String, String>,
        strategy: Strategy,
    ) -> Self {
        let mut models: HashMap<String, ModelEntry> = HashMap::new();
        for d in deployments {
            let entry = models.entry(d.model_name.clone()).or_insert_with(|| ModelEntry {
                deployments: Vec::new(),
                rr: AtomicUsize::new(0),
                load: Vec::new(),
            });
            entry.deployments.push(d);
            entry.load.push(AtomicUsize::new(0));
        }
        Snapshot {
            models,
            fallbacks,
            aliases,
            strategy,
        }
    }

    /// Follow the alias chain to a canonical model name. A real model name always
    /// wins over an alias of the same string; cycles and chains are bounded.
    fn canonical<'a>(&'a self, requested: &'a str) -> &'a str {
        let mut name = requested;
        for _ in 0..8 {
            // A concrete model shadows any alias of the same name.
            if self.models.contains_key(name) {
                return name;
            }
            match self.aliases.get(name) {
                Some(target) => name = target,
                None => return name,
            }
        }
        name
    }
}

/// A configuration/database-driven [`Router`] with a hot-swappable table.
pub struct DeploymentRouter {
    snapshot: RwLock<Arc<Snapshot>>,
    /// xorshift state seeded once at construction; drives the weighted shuffle.
    rng: AtomicU64,
}

impl DeploymentRouter {
    /// Build a router from a model list plus routing policy (the file/seed
    /// shape). Used in tests and for a file-only deployment; production seeds the
    /// DB and uses [`from_deployments`](Self::from_deployments).
    pub fn from_models(
        models: Vec<yb_core::config::ModelConfig>,
        fallbacks: HashMap<String, Vec<String>>,
        aliases: HashMap<String, String>,
        strategy: Strategy,
    ) -> Self {
        let deployments = models
            .into_iter()
            .flat_map(|mc| {
                mc.deployments.into_iter().map(move |dc| Deployment {
                    model_name: mc.model_name.clone(),
                    provider: dc.provider,
                    upstream_model: dc.upstream_model,
                    api_base: dc.api_base,
                    api_key: dc.api_key,
                    upstream_format: dc.upstream_format,
                    weight: dc.weight,
                    pricing: dc.pricing,
                    health_check: dc.health_check,
                    health_path: dc.health_path,
                })
            })
            .collect();
        Self::with_snapshot(Snapshot::build(deployments, fallbacks, aliases, strategy))
    }

    /// Build a router from persisted deployment records plus routing policy
    /// (strategy + fallbacks) and the alias map.
    pub fn from_deployments(
        records: &[DeploymentRecord],
        strategy: Strategy,
        fallbacks: HashMap<String, Vec<String>>,
        aliases: HashMap<String, String>,
    ) -> Self {
        let deployments = records.iter().map(|r| r.to_deployment()).collect();
        Self::with_snapshot(Snapshot::build(deployments, fallbacks, aliases, strategy))
    }

    fn with_snapshot(snap: Snapshot) -> Self {
        // Seed the PRNG from the clock; never zero (xorshift fixed point at 0).
        let seed = (yb_core::now().timestamp_nanos_opt().unwrap_or(1) as u64) | 1;
        DeploymentRouter {
            snapshot: RwLock::new(Arc::new(snap)),
            rng: AtomicU64::new(seed),
        }
    }

    /// Atomically replace the routing table with one built from `records` and the
    /// current alias map, keeping the strategy and fallback policy. Called after
    /// an admin mutation to `/admin/v1/models` or `/admin/v1/aliases`.
    pub fn reload(&self, records: &[DeploymentRecord], aliases: HashMap<String, String>) {
        let (strategy, fallbacks) = {
            let cur = self.snapshot.read().unwrap();
            (cur.strategy, cur.fallbacks.clone())
        };
        let deployments = records.iter().map(|r| r.to_deployment()).collect();
        let next = Arc::new(Snapshot::build(deployments, fallbacks, aliases, strategy));
        *self.snapshot.write().unwrap() = next;
    }

    /// The number of distinct public models currently routable.
    pub fn model_count(&self) -> usize {
        self.snapshot.read().unwrap().models.len()
    }

    /// Advance the xorshift64 PRNG and return a float in `[0, 1)`.
    fn next_unit(&self) -> f64 {
        let mut x = self.rng.load(Ordering::Relaxed);
        if x == 0 {
            x = 0x9E37_79B9_7F4A_7C15;
        }
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.rng.store(x, Ordering::Relaxed);
        (x >> 11) as f64 / ((1u64 << 53) as f64)
    }

    /// Order the surviving deployment indices of `entry` per `strategy`.
    fn order(&self, strategy: Strategy, entry: &ModelEntry, survivors: Vec<usize>) -> Vec<Deployment> {
        match strategy {
            Strategy::Simple => {
                // Weighted shuffle (Efraimidis–Spirakis): key = u^(1/weight),
                // sorted descending — heavier deployments float to the front in
                // expectation while every ordering stays possible.
                let mut keyed: Vec<(f64, usize)> = survivors
                    .into_iter()
                    .map(|i| {
                        let w = entry.deployments[i].weight.max(1) as f64;
                        let key = self.next_unit().powf(1.0 / w);
                        (key, i)
                    })
                    .collect();
                keyed.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));
                keyed
                    .into_iter()
                    .map(|(_, i)| entry.deployments[i].clone())
                    .collect()
            }
            Strategy::RoundRobin => {
                let n = survivors.len();
                let start = entry.rr.fetch_add(1, Ordering::Relaxed) % n;
                (0..n)
                    .map(|k| entry.deployments[survivors[(start + k) % n]].clone())
                    .collect()
            }
            Strategy::LeastBusy => {
                let mut idx = survivors;
                idx.sort_by_key(|&i| entry.load[i].load(Ordering::Relaxed));
                if let Some(&first) = idx.first() {
                    entry.load[first].fetch_add(1, Ordering::Relaxed);
                }
                idx.into_iter()
                    .map(|i| entry.deployments[i].clone())
                    .collect()
            }
        }
    }

    /// Append the (filtered, ordered, de-duplicated) deployments of `model`.
    fn collect(
        &self,
        snap: &Snapshot,
        model: &str,
        req: &RouteRequest,
        out: &mut Vec<Deployment>,
        seen: &mut HashSet<(String, String, String)>,
    ) {
        let Some(entry) = snap.models.get(model) else {
            return;
        };

        let mut survivors = Vec::new();
        for (i, d) in entry.deployments.iter().enumerate() {
            if req.excluded_models.contains(&d.model_name) {
                continue;
            }
            if let Some(enabled) = &req.enabled_providers {
                if !enabled.contains(&d.provider) {
                    continue;
                }
            }
            if req.denied_providers.contains(&d.provider) {
                continue;
            }
            survivors.push(i);
        }
        if survivors.is_empty() {
            return;
        }

        for d in self.order(snap.strategy, entry, survivors) {
            let key = (d.provider.clone(), d.upstream_model.clone(), d.model_name.clone());
            if seen.insert(key) {
                out.push(d);
            }
        }
    }
}

impl Router for DeploymentRouter {
    fn resolve(&self, req: &RouteRequest) -> Result<Decision> {
        let snap = self.snapshot.read().unwrap().clone();
        let mut out = Vec::new();
        let mut seen = HashSet::new();

        // Resolve any alias to its canonical model name first.
        let model = snap.canonical(&req.requested_model);
        self.collect(&snap, model, req, &mut out, &mut seen);
        if let Some(fbs) = snap.fallbacks.get(model) {
            for fb in fbs {
                self.collect(&snap, fb, req, &mut out, &mut seen);
            }
        }

        if out.is_empty() {
            return Err(Error::NoEligibleProvider(req.requested_model.clone()));
        }

        let reason = format!(
            "resolved '{}' to {} candidate(s) via {} strategy",
            req.requested_model,
            out.len(),
            strategy_name(snap.strategy),
        );
        Ok(Decision {
            candidates: out,
            reason,
        })
    }
}

/// Human-readable strategy label for [`Decision::reason`].
fn strategy_name(s: Strategy) -> &'static str {
    match s {
        Strategy::Simple => "simple",
        Strategy::RoundRobin => "round_robin",
        Strategy::LeastBusy => "least_busy",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use yb_core::config::{DeploymentConfig, ModelConfig};
    use yb_core::WireFormat;

    fn dc(provider: &str, fmt: WireFormat, weight: u32) -> DeploymentConfig {
        DeploymentConfig {
            provider: provider.to_string(),
            upstream_model: format!("{provider}-model"),
            api_base: None,
            api_key: None,
            upstream_format: fmt.into(),
            weight,
            pricing: None,
            health_check: Default::default(),
            health_path: None,
        }
    }

    fn mk_router(strategy: Strategy) -> DeploymentRouter {
        let models = vec![
            ModelConfig {
                model_name: "smart".to_string(),
                aliases: vec![],
                deployments: vec![
                    dc("openai", WireFormat::OpenaiChat, 1),
                    dc("anthropic", WireFormat::Anthropic, 1),
                ],
            },
            ModelConfig {
                model_name: "cheap".to_string(),
                aliases: vec![],
                deployments: vec![dc("openrouter", WireFormat::OpenaiChat, 1)],
            },
        ];
        let fallbacks = HashMap::from([("smart".to_string(), vec!["cheap".to_string()])]);
        // "brainy" aliases "smart"; "chain" aliases "brainy" (two hops).
        let aliases = HashMap::from([
            ("brainy".to_string(), "smart".to_string()),
            ("chain".to_string(), "brainy".to_string()),
        ]);
        DeploymentRouter::from_models(models, fallbacks, aliases, strategy)
    }

    fn req(model: &str) -> RouteRequest {
        RouteRequest {
            requested_model: model.to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn upstream_format_passes_through() {
        let r = mk_router(Strategy::Simple);
        let d = r.resolve(&req("cheap")).unwrap();
        assert_eq!(d.candidates[0].upstream_format, WireFormat::OpenaiChat.into());
    }

    #[test]
    fn primary_then_fallback() {
        let r = mk_router(Strategy::Simple);
        let d = r.resolve(&req("smart")).unwrap();
        assert_eq!(d.candidates.len(), 3);
        assert_eq!(d.candidates.last().unwrap().provider, "openrouter");
    }

    #[test]
    fn alias_resolves_to_target_and_inherits_fallbacks() {
        let r = mk_router(Strategy::Simple);
        // "brainy" -> "smart": same deployments + "smart"'s fallback to "cheap".
        let via_alias = r.resolve(&req("brainy")).unwrap();
        let direct = r.resolve(&req("smart")).unwrap();
        assert_eq!(via_alias.candidates.len(), direct.candidates.len());
        assert_eq!(via_alias.candidates.len(), 3);
        // A two-hop alias chain ("chain" -> "brainy" -> "smart") also resolves.
        let chained = r.resolve(&req("chain")).unwrap();
        assert_eq!(chained.candidates.len(), 3);
        // An unknown name still fails cleanly.
        assert!(r.resolve(&req("nope")).is_err());
    }

    #[test]
    fn denied_provider_filtered() {
        let r = mk_router(Strategy::Simple);
        let mut rq = req("smart");
        rq.denied_providers = BTreeSet::from(["openai".to_string(), "openrouter".to_string()]);
        let d = r.resolve(&rq).unwrap();
        assert_eq!(d.candidates.len(), 1);
        assert_eq!(d.candidates[0].provider, "anthropic");
    }

    #[test]
    fn enabled_providers_allowlist() {
        let r = mk_router(Strategy::Simple);
        let mut rq = req("smart");
        rq.enabled_providers = Some(BTreeSet::from(["anthropic".to_string()]));
        let d = r.resolve(&rq).unwrap();
        assert_eq!(d.candidates.len(), 1);
        assert_eq!(d.candidates[0].provider, "anthropic");
    }

    #[test]
    fn excluded_model_removes_fallback() {
        let r = mk_router(Strategy::Simple);
        let mut rq = req("smart");
        rq.excluded_models = BTreeSet::from(["cheap".to_string()]);
        let d = r.resolve(&rq).unwrap();
        assert!(d.candidates.iter().all(|c| c.model_name != "cheap"));
        assert_eq!(d.candidates.len(), 2);
    }

    #[test]
    fn everything_filtered_is_no_eligible_provider() {
        let r = mk_router(Strategy::Simple);
        let mut rq = req("smart");
        rq.denied_providers =
            BTreeSet::from(["openai".into(), "anthropic".into(), "openrouter".into()]);
        let err = r.resolve(&rq).unwrap_err();
        assert!(matches!(err, Error::NoEligibleProvider(_)));
    }

    #[test]
    fn unknown_model_is_no_eligible_provider() {
        let r = mk_router(Strategy::Simple);
        assert!(matches!(
            r.resolve(&req("nope")).unwrap_err(),
            Error::NoEligibleProvider(_)
        ));
    }

    #[test]
    fn round_robin_rotates_front() {
        let r = mk_router(Strategy::RoundRobin);
        let first = r.resolve(&req("smart")).unwrap().candidates[0]
            .provider
            .clone();
        let second = r.resolve(&req("smart")).unwrap().candidates[0]
            .provider
            .clone();
        assert_ne!(first, second, "round-robin advances the front deployment");
    }

    #[test]
    fn reload_swaps_model_table() {
        use yb_core::routing::DeploymentRecord;
        let r = mk_router(Strategy::Simple);
        assert!(r.resolve(&req("smart")).is_ok());
        assert_eq!(r.model_count(), 2);

        // Reload with a single new model; the old ones disappear.
        let rec = DeploymentRecord {
            id: yb_core::new_id(),
            model_name: "fresh".into(),
            provider: "openai".into(),
            upstream_model: "gpt-4o".into(),
            api_base: None,
            api_key: None,
            upstream_format: WireFormat::OpenaiChat.into(),
            weight: 1,
            pricing: None,
            health_check: Default::default(),
            health_path: None,
            created_at: yb_core::now(),
            updated_at: yb_core::now(),
            deleted_at: None,
        };
        r.reload(&[rec], HashMap::new());
        assert_eq!(r.model_count(), 1);
        assert!(matches!(
            r.resolve(&req("smart")).unwrap_err(),
            Error::NoEligibleProvider(_)
        ));
        assert!(r.resolve(&req("fresh")).is_ok());
    }
}
