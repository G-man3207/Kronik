//! Packs a test image into an OCI layout, and turns an image from an OCI
//! layout into a runsc bundle (rootfs plus config.json) the way Kronik will.
//!
//! Usage:
//!   oci-tool pack --out DIR --ref NAME --layer gzip:DIR|tar:DIR...
//!                 [--entrypoint JSON] [--cmd JSON] [--env K=V]... [--workdir P]
//!                 [--user U] [--expose PORT/PROTO]...
//!   oci-tool bundle --layout DIR [--ref NAME|sha256:...] --bundle DIR [--replace]
//!                 [--cpu N] [--memory SIZE] [--pids N] [--env K=V]...
//!                 [--bind SRC:DST[:ro]]... [--cgroups-path P] [--netns PATH]
//!                 [--hostname H]
//!                 [--cmd JSON]

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::time::Instant;

use spike_c_gvisor::oci::{self, Bind, ImageSpec, LayerSource, Overrides};

fn main() {
    let mut args = std::env::args().skip(1);
    let command = args.next().unwrap_or_default();
    let mut opts: HashMap<String, Vec<String>> = HashMap::new();
    let mut flags = Vec::new();
    let rest: Vec<String> = args.collect();
    let mut i = 0;
    while i < rest.len() {
        let key = rest[i].trim_start_matches("--").to_string();
        if key == "replace" {
            flags.push(key);
            i += 1;
        } else if let Some(value) = rest.get(i + 1) {
            opts.entry(key).or_default().push(value.clone());
            i += 2;
        } else {
            fail(&format!("missing value for --{key}"));
        }
    }
    let result = match command.as_str() {
        "pack" => pack(&opts),
        "bundle" => bundle(&opts, flags.iter().any(|f| f == "replace")),
        _ => Err("command must be pack or bundle".to_string()),
    };
    if let Err(e) = result {
        fail(&e);
    }
}

fn fail(msg: &str) -> ! {
    eprintln!("oci-tool: {msg}");
    std::process::exit(1);
}

fn one<'a>(opts: &'a HashMap<String, Vec<String>>, key: &str) -> Option<&'a str> {
    opts.get(key).and_then(|v| v.last()).map(String::as_str)
}

fn many(opts: &HashMap<String, Vec<String>>, key: &str) -> Vec<String> {
    opts.get(key).cloned().unwrap_or_default()
}

fn json_list(s: Option<&str>) -> oci::Result<Vec<String>> {
    match s {
        None => Ok(Vec::new()),
        Some(s) => serde_json::from_str(s).map_err(|e| format!("bad JSON list {s}: {e}")),
    }
}

fn pack(opts: &HashMap<String, Vec<String>>) -> oci::Result<()> {
    let out = PathBuf::from(one(opts, "out").ok_or("--out is required")?);
    let layers = many(opts, "layer")
        .iter()
        .map(|l| match l.split_once(':') {
            Some(("gzip", dir)) => Ok(LayerSource {
                dir: dir.into(),
                gzip: true,
            }),
            Some(("tar", dir)) => Ok(LayerSource {
                dir: dir.into(),
                gzip: false,
            }),
            _ => Err(format!("bad --layer {l}, expected gzip:DIR or tar:DIR")),
        })
        .collect::<oci::Result<Vec<_>>>()?;
    let spec = ImageSpec {
        reference: one(opts, "ref").ok_or("--ref is required")?.to_string(),
        entrypoint: json_list(one(opts, "entrypoint"))?,
        cmd: json_list(one(opts, "cmd"))?,
        env: many(opts, "env"),
        workdir: one(opts, "workdir").unwrap_or("/").to_string(),
        user: one(opts, "user").unwrap_or_default().to_string(),
        exposed_ports: many(opts, "expose"),
    };
    let digest = oci::pack(&out, &layers, &spec)?;
    println!(
        "packed {} with {} layers: manifest {digest}",
        out.display(),
        layers.len()
    );
    Ok(())
}

fn bundle(opts: &HashMap<String, Vec<String>>, replace: bool) -> oci::Result<()> {
    let started = Instant::now();
    let layout = PathBuf::from(one(opts, "layout").ok_or("--layout is required")?);
    let bundle = PathBuf::from(one(opts, "bundle").ok_or("--bundle is required")?);
    if bundle.exists() {
        if !replace {
            return Err(format!("{} exists; pass --replace", bundle.display()));
        }
        fs::remove_dir_all(&bundle).map_err(|e| format!("remove {}: {e}", bundle.display()))?;
    }
    fs::create_dir_all(&bundle).map_err(|e| format!("create {}: {e}", bundle.display()))?;

    let image = oci::open_image(&layout, one(opts, "ref"))?;
    println!(
        "image: manifest {} config {}",
        image.manifest_digest, image.config_digest
    );
    for (layer, diff_id) in image.layers.iter().zip(&image.diff_ids) {
        println!(
            "  layer {} {} ({} bytes), diff_id {diff_id}",
            layer.media_type, layer.digest, layer.size
        );
    }
    let rootfs = bundle.join("rootfs");
    let stats = oci::unpack(&layout, &image, &rootfs)?;
    println!(
        "unpacked: {} layers verified (blob digest and diff_id), {} entries, {} whiteouts, {} opaque dirs, {} skipped",
        stats.layers, stats.entries, stats.whiteouts, stats.opaque_dirs, stats.skipped
    );

    let binds = many(opts, "bind")
        .iter()
        .map(|b| {
            let parts: Vec<&str> = b.split(':').collect();
            match parts.as_slice() {
                [src, dst] => Ok(Bind {
                    source: src.into(),
                    destination: dst.to_string(),
                    read_only: false,
                }),
                [src, dst, "ro"] => Ok(Bind {
                    source: src.into(),
                    destination: dst.to_string(),
                    read_only: true,
                }),
                _ => Err(format!("bad --bind {b}, expected SRC:DST[:ro]")),
            }
        })
        .collect::<oci::Result<Vec<_>>>()?;
    let overrides = Overrides {
        cpu: one(opts, "cpu")
            .map(|c| c.parse().map_err(|e| format!("bad --cpu {c}: {e}")))
            .transpose()?,
        memory: one(opts, "memory").map(oci::parse_size).transpose()?,
        pids: one(opts, "pids")
            .map(|p| p.parse().map_err(|e| format!("bad --pids {p}: {e}")))
            .transpose()?,
        env: many(opts, "env"),
        binds,
        cgroups_path: one(opts, "cgroups-path").map(String::from),
        netns: one(opts, "netns").map(String::from),
        hostname: one(opts, "hostname").unwrap_or("foreign").to_string(),
        cmd: one(opts, "cmd").map(|c| json_list(Some(c))).transpose()?,
    };
    let spec = oci::runtime_spec(&image.config, &rootfs, &overrides)?;
    let spec_json = serde_json::to_string_pretty(&spec).map_err(|e| e.to_string())?;
    fs::write(bundle.join("config.json"), spec_json)
        .map_err(|e| format!("write config.json: {e}"))?;
    println!(
        "bundle {} ready in {:?}: args {} user {}:{} cwd {}",
        bundle.display(),
        started.elapsed(),
        spec["process"]["args"],
        spec["process"]["user"]["uid"],
        spec["process"]["user"]["gid"],
        spec["process"]["cwd"],
    );
    Ok(())
}
