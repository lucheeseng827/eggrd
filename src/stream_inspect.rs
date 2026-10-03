//! Bounded-window inspection of a streamed request body (0.6.0, A3).
//!
//! With `validation.stream_requests` on, a WAF body rule or inbound DLP normally forces the request
//! to buffer, because both read the whole body. A route listed under `[[validation.stream_inspect]]`
//! streams anyway and is inspected in two parts:
//!
//! * the **window** — the first N bytes, read and inspected by the ordinary WAF/DLP steps before
//!   anything is forwarded, so a hit there is a clean `403` the upstream never sees;
//! * the **tail** — every later frame, scanned as it passes by a [`TailInspector`] with the last
//!   `overlap` bytes of the previous frame carried in front of it, so a match split across two
//!   frames is still caught when it fits in the overlap. A block here cuts the upload.
//!
//! That is weaker than whole-body inspection, on purpose and documented (`StreamInspectCfg`): a
//! match longer than the overlap that straddles a frame boundary is missed, and a block in the
//! tail comes after the upstream has seen the start of the upload.

use std::sync::Arc;

use anyhow::{bail, Result};
use tracing::warn;

use crate::config::{parse_size, StreamInspectCfg};
use crate::dlp::{DlpEngine, DlpMode};
use crate::metrics::Metrics;
use crate::waf::{WafEngine, WafMode};

/// A compiled `[[validation.stream_inspect]]` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InspectWindow {
    pub prefix: String,
    pub window: usize,
    pub overlap: usize,
}

impl InspectWindow {
    /// Compile the configured routes, failing on a bad size, a path that isn't a `/` prefix, or an
    /// overlap that isn't smaller than its window.
    pub fn build(cfgs: &[StreamInspectCfg]) -> Result<Vec<InspectWindow>> {
        cfgs.iter()
            .map(|c| {
                if !c.path.starts_with('/') {
                    bail!(
                        "validation.stream_inspect: path {:?} must start with '/'",
                        c.path
                    );
                }
                let window = parse_size(&c.window)?;
                let overlap = parse_size(&c.overlap)?;
                if window == 0 {
                    bail!("validation.stream_inspect {:?}: window must be > 0", c.path);
                }
                if overlap >= window {
                    bail!(
                        "validation.stream_inspect {:?}: overlap ({}) must be smaller than window ({})",
                        c.path,
                        c.overlap,
                        c.window
                    );
                }
                Ok(InspectWindow {
                    prefix: c.path.clone(),
                    window,
                    overlap,
                })
            })
            .collect()
    }

    /// The entry for `path`: the longest matching prefix, if any. Prefixes match on a path segment
    /// boundary, as `[[upstreams]]` do: `/upload` covers `/upload` and `/upload/x`, not `/uploads`.
    pub fn for_path<'a>(routes: &'a [InspectWindow], path: &str) -> Option<&'a InspectWindow> {
        routes
            .iter()
            .filter(|r| crate::proxy::path_prefix_matches(path, &r.prefix))
            .max_by_key(|r| r.prefix.len())
    }
}

/// Whether a request that [`crate::proxy`]'s `streams_request` would buffer may stream with
/// bounded-window inspection instead: streaming is on, the route opted in, something inspects the
/// body (otherwise it streams plainly), and nothing needs the whole body — DLP `redact` rewrites
/// it and the LLM features parse it.
pub(crate) fn inspects_window(
    enabled: bool,
    route_opted_in: bool,
    waf_reads_body: bool,
    dlp_scans_request: bool,
    dlp_rewrites: bool,
    llm_reads_body: bool,
) -> bool {
    enabled
        && route_opted_in
        && (waf_reads_body || dlp_scans_request)
        && !dlp_rewrites
        && !llm_reads_body
}

/// What the tail inspector decided about a frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Pass,
    Block,
}

/// Scans the frames after the window, carrying `overlap` bytes between them.
pub struct TailInspector {
    waf: Option<Arc<WafEngine>>,
    dlp: Option<Arc<DlpEngine>>,
    metrics: Arc<Metrics>,
    overlap: usize,
    carry: Vec<u8>,
    /// A report-mode WAF hit is reported once per request, as on the buffered path.
    waf_reported: bool,
}

impl TailInspector {
    /// `waf` and `dlp` are the engines to run (`None` when that one doesn't inspect the body);
    /// `window_tail` is the end of the already-inspected window, the first carry.
    pub fn new(
        waf: Option<Arc<WafEngine>>,
        dlp: Option<Arc<DlpEngine>>,
        metrics: Arc<Metrics>,
        overlap: usize,
        window_tail: &[u8],
        waf_reported: bool,
    ) -> Self {
        let from = window_tail.len().saturating_sub(overlap);
        TailInspector {
            waf,
            dlp,
            metrics,
            overlap,
            carry: window_tail[from..].to_vec(),
            waf_reported,
        }
    }

    /// Inspect one frame (with the carry in front of it).
    pub fn check(&mut self, data: &[u8]) -> Verdict {
        if data.is_empty() {
            return Verdict::Pass;
        }
        let mut buf = std::mem::take(&mut self.carry);
        let carried = buf.len();
        buf.extend_from_slice(data);
        let verdict = self.inspect(&buf, carried);
        let from = buf.len().saturating_sub(self.overlap);
        self.carry = buf.split_off(from);
        verdict
    }

    fn inspect(&mut self, buf: &[u8], carried: usize) -> Verdict {
        if let Some(waf) = self.waf.as_ref() {
            if !self.waf_reported {
                if let Some(hit) = waf.evaluate_body(buf) {
                    self.metrics.record_waf_hit(hit.class);
                    if waf.mode() == WafMode::Block {
                        warn!(rule = %hit.rule_id, class = hit.class, "WAF blocked a streamed request body; upload cut");
                        return Verdict::Block;
                    }
                    warn!(rule = %hit.rule_id, class = hit.class, "WAF rule matched in a streamed request body (report-only)");
                    self.waf_reported = true;
                }
            }
        }
        if let Some(dlp) = self.dlp.as_ref() {
            let text = String::from_utf8_lossy(buf);
            // Count only what ends past the carry: a finding wholly inside it was counted with the
            // frame it arrived in.
            let carried_text = String::from_utf8_lossy(&buf[..char_start(buf, carried)]).len();
            let findings: Vec<_> = dlp
                .scan(&text)
                .into_iter()
                .filter(|f| f.end > carried_text)
                .collect();
            if !findings.is_empty() {
                for f in &findings {
                    self.metrics.record_dlp_finding(f.category);
                }
                match dlp.mode() {
                    DlpMode::Block => {
                        self.metrics.record_dlp_blocked();
                        warn!(
                            findings = findings.len(),
                            "streamed request body blocked by DLP; upload cut"
                        );
                        return Verdict::Block;
                    }
                    _ => warn!(
                        findings = findings.len(),
                        "DLP findings in a streamed request body (report-only)"
                    ),
                }
            }
        }
        Verdict::Pass
    }
}

/// `at`, moved back to the start of the character it falls inside. The overlap is cut in bytes, so
/// the carry can end inside a character the next frame completes; a prefix that ends on a
/// character boundary decodes exactly as the same bytes do inside the whole buffer, so offsets
/// measured on it agree with the scanned text.
fn char_start(buf: &[u8], at: usize) -> usize {
    let mut i = at.min(buf.len());
    while i > 0 && i < buf.len() && (buf[i] & 0xC0) == 0x80 {
        i -= 1;
    }
    i
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{DlpCfg, WafCfg};

    fn waf(mode: &str) -> Arc<WafEngine> {
        Arc::new(
            WafEngine::build(&WafCfg {
                mode: mode.into(),
                inspect_body: true,
                ..Default::default()
            })
            .unwrap(),
        )
    }

    fn dlp(mode: &str) -> Arc<DlpEngine> {
        Arc::new(
            DlpEngine::build(&DlpCfg {
                mode: mode.into(),
                ..Default::default()
            })
            .unwrap()
            .expect("dlp on"),
        )
    }

    fn metrics() -> Arc<Metrics> {
        Arc::new(Metrics::default())
    }

    #[test]
    fn only_a_route_that_opted_in_and_needs_inspection_streams_windowed() {
        // enabled, opted in, waf, dlp scans, dlp rewrites, llm
        assert!(inspects_window(true, true, true, false, false, false));
        assert!(inspects_window(true, true, false, true, false, false));
        assert!(!inspects_window(false, true, true, false, false, false));
        assert!(!inspects_window(true, false, true, false, false, false));
        // Nothing inspects the body: it streams plainly instead.
        assert!(!inspects_window(true, true, false, false, false, false));
        assert!(!inspects_window(true, true, true, true, true, false));
        assert!(!inspects_window(true, true, true, false, false, true));
    }

    #[test]
    fn build_checks_paths_and_sizes_and_picks_the_longest_prefix() {
        let cfg = |path: &str, window: &str, overlap: &str| StreamInspectCfg {
            path: path.into(),
            window: window.into(),
            overlap: overlap.into(),
        };
        let routes = InspectWindow::build(&[
            cfg("/up/", "64KiB", "4KiB"),
            cfg("/up/big/", "1MiB", "8KiB"),
        ])
        .unwrap();
        assert_eq!(routes[0].window, 64 * 1024);
        assert_eq!(
            InspectWindow::for_path(&routes, "/up/big/x")
                .unwrap()
                .window,
            1024 * 1024
        );
        assert_eq!(
            InspectWindow::for_path(&routes, "/up/x").unwrap().prefix,
            "/up/"
        );
        assert!(InspectWindow::for_path(&routes, "/other").is_none());

        // Segment boundaries, as [[upstreams]] match: a route does not claim a sibling path.
        let upload = InspectWindow::build(&[cfg("/upload", "64KiB", "4KiB")]).unwrap();
        assert!(InspectWindow::for_path(&upload, "/upload").is_some());
        assert!(InspectWindow::for_path(&upload, "/upload/a").is_some());
        assert!(InspectWindow::for_path(&upload, "/upload?x=1").is_some());
        assert!(InspectWindow::for_path(&upload, "/uploads-admin").is_none());

        assert!(InspectWindow::build(&[cfg("up/", "64KiB", "4KiB")]).is_err());
        assert!(InspectWindow::build(&[cfg("/up/", "0", "0")]).is_err());
        assert!(InspectWindow::build(&[cfg("/up/", "4KiB", "4KiB")]).is_err());
        assert!(InspectWindow::build(&[cfg("/up/", "lots", "1")]).is_err());
        assert!(InspectWindow::build(&[StreamInspectCfg {
            path: "/d/".into(),
            ..Default::default()
        }])
        .is_ok());
    }

    #[test]
    fn the_carry_boundary_never_splits_a_character() {
        // "aé" + "z": é is two bytes (C3 A9). A carry ending after C3 must be measured from é's start.
        let buf = "aéz".as_bytes();
        assert_eq!(char_start(buf, 2), 1, "inside é: back to its first byte");
        assert_eq!(char_start(buf, 1), 1);
        assert_eq!(char_start(buf, 3), 3);
        assert_eq!(char_start(buf, 0), 0);
        assert_eq!(char_start(buf, 99), buf.len());
        // The property the DLP offset filter needs: the prefix decodes as a prefix of the whole.
        let whole = String::from_utf8_lossy(buf);
        for at in 0..=buf.len() {
            let prefix = String::from_utf8_lossy(&buf[..char_start(buf, at)]);
            assert!(
                whole.starts_with(prefix.as_ref()),
                "at {at}: {prefix:?} vs {whole:?}"
            );
        }
    }

    #[test]
    fn a_waf_match_split_across_frames_is_caught_within_the_overlap() {
        let mut t = TailInspector::new(Some(waf("block")), None, metrics(), 64, b"", false);
        assert_eq!(t.check(b"name=x&bio=<scr"), Verdict::Pass);
        assert_eq!(t.check(b"ipt>alert(1)</script>"), Verdict::Block);
    }

    #[test]
    fn a_match_longer_than_the_overlap_across_a_boundary_is_missed() {
        // The documented weakness: with a 2-byte overlap, "<scr" + "ipt>" never meet.
        let mut t = TailInspector::new(Some(waf("block")), None, metrics(), 2, b"", false);
        assert_eq!(t.check(b"bio=<scr"), Verdict::Pass);
        assert_eq!(t.check(b"ipt>alert(1)"), Verdict::Pass);
    }

    #[test]
    fn the_window_tail_seeds_the_first_carry() {
        let mut t = TailInspector::new(
            Some(waf("block")),
            None,
            metrics(),
            64,
            b"....inspected window ending in <scr",
            false,
        );
        assert_eq!(t.check(b"ipt>"), Verdict::Block);
    }

    #[test]
    fn report_mode_passes_and_reports_a_waf_hit_once() {
        let m = metrics();
        let mut t = TailInspector::new(Some(waf("report")), None, Arc::clone(&m), 64, b"", false);
        assert_eq!(t.check(b"<script>a</script>"), Verdict::Pass);
        assert_eq!(t.check(b"<script>b</script>"), Verdict::Pass);
        assert!(t.waf_reported);
        let text = m.render();
        let hits: f64 = text
            .lines()
            .filter(|l| l.starts_with("edgeguard_waf_hits_total{"))
            .filter_map(|l| l.rsplit(' ').next()?.parse::<f64>().ok())
            .sum();
        assert_eq!(hits, 1.0);
    }

    #[test]
    fn dlp_blocks_a_split_secret_and_does_not_recount_the_carry() {
        // Split so the source never holds a key-shaped literal (the mirror scan rejects one).
        let key = concat!("AKIA", "IOSFODNN7EXAMPLE");
        let mut t = TailInspector::new(None, Some(dlp("block")), metrics(), 64, b"", false);
        assert_eq!(
            t.check(format!("x {}", &key[..8]).as_bytes()),
            Verdict::Pass
        );
        assert_eq!(
            t.check(format!("{} y", &key[8..]).as_bytes()),
            Verdict::Block
        );

        let m = metrics();
        let mut t = TailInspector::new(None, Some(dlp("report")), Arc::clone(&m), 64, b"", false);
        assert_eq!(t.check(format!("x {key} y").as_bytes()), Verdict::Pass);
        // The key is still in the carry; a later clean frame must not count it again.
        assert_eq!(t.check(b" clean"), Verdict::Pass);
        let findings: f64 = m
            .render()
            .lines()
            .filter(|l| l.starts_with("edgeguard_llm_dlp_findings_total{"))
            .filter_map(|l| l.rsplit(' ').next()?.parse::<f64>().ok())
            .sum();
        assert_eq!(findings, 1.0);
    }
}
