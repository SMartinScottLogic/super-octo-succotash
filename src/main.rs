#[macro_use]
extern crate log;
extern crate chrono;
extern crate env_logger;
extern crate regex;

use chrono::Local;
use env_logger::{Builder, Env};
use regex::Regex;
use std::env;
use std::ffi::OsString;
use std::io::Write;
use walkdir::WalkDir;

#[derive(Debug)]
enum DashMode {
    None,
    Manifest(String),
    //Media(walkdir::DirEntry),
    Media(String),
}

impl DashMode {
    fn is_dash(&self) -> bool {
        match *self {
            DashMode::None => false,
            _ => true,
        }
    }

    fn is_manifest(&self) -> bool {
        match *self {
            DashMode::Manifest(_) => true,
            _ => false,
        }
    }
}

fn is_manifest(filename: &str) -> bool {
    filename.contains(".mpd")
}

fn process_file(entry: walkdir::DirEntry) -> DashMode {
    let path = entry
        .path()
        .canonicalize()
        .ok()
        .map(|p| p.into_os_string().into_string().ok())
        .flatten();

    match path {
        Some(s) if { s.ends_with("headers.txt") } => DashMode::None,
        Some(s) if { s.ends_with("raw.dat") } => DashMode::None,
        Some(s) if { is_manifest(&s) } => DashMode::Manifest(s.to_string()),
        Some(s) => DashMode::Media(s.to_string()),
        None => DashMode::None,
    }
}

fn process_segment_template(
    media: &Vec<DashMode>,
    attributes: &Vec<xml::attribute::OwnedAttribute>,
) -> std::collections::HashMap<String, Vec<String>> {
    let keyword_re = Regex::new(r"\$[^$]*\$").unwrap();
    let m = attributes
        .iter()
        .filter_map(|a| match a.name.local_name.as_str() {
            "initialization" | "media" => Some((
                a.name.local_name.to_string(),
                Regex::new(&keyword_re.replace_all(&a.value, ".*")),
            )),
            _ => None,
        })
        .collect::<std::collections::HashMap<_, _>>();
    let mut me = media
        .iter()
        .filter_map(|a| match a {
            DashMode::Media(s)
                if m["initialization"]
                    .as_ref()
                    .unwrap()
                    .is_match(&s.replace(r"/", "")) =>
            {
                Some(("initialization", s))
            }
            DashMode::Media(s) if m["media"].as_ref().unwrap().is_match(&s.replace(r"/", "")) => {
                Some(("media", s))
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    me.sort_by(|a, b| match a.0.cmp(b.0) {
        std::cmp::Ordering::Equal => a.1.cmp(b.1),
        o => o,
    });
    let mut hash_map: std::collections::HashMap<String, Vec<String>> =
        std::collections::HashMap::new();
    for e in me {
        hash_map
            .entry(e.0.to_string())
            .or_default()
            .push(e.1.to_string());
    }
    hash_map
}

fn process_manifest(manifest_file: &str, media: &Vec<DashMode>) -> Vec<String> {
    let file = std::fs::File::open(manifest_file).unwrap();
    let file = std::io::BufReader::new(file);

    let parser = xml::reader::EventReader::new(file);
    let mut depth = 0;
    let mut in_title = false;
    let mut title = r"".to_string();
    let mut segments = Vec::new();
    for e in parser {
        match e {
            Ok(xml::reader::XmlEvent::StartElement {
                name, attributes, ..
            }) => {
                debug!("{}+{} {:?}", depth, name, attributes);
                if name.local_name == "Title" {
                    in_title = true;
                }
                if name.local_name == "SegmentTemplate" {
                    segments.push(process_segment_template(&media, &attributes));
                }
                depth += 1;
            }
            Ok(xml::reader::XmlEvent::EndElement { name }) => {
                if name.local_name == "Title" {
                    in_title = false;
                }
                depth -= 1;
                debug!("{}-{}", depth, name);
            }
            Ok(xml::reader::XmlEvent::CData(s)) => {
                debug!("{} {}", in_title, s);
                if in_title {
                    title += &s;
                }
            }
            Ok(xml::reader::XmlEvent::Characters(s)) => {
                debug!("{} {}", in_title, s);
                if in_title {
                    title += &s;
                }
            }
            Err(e) => {
                error!("Error: {} {}", manifest_file, e);
                break;
            }
            _ => {}
        }
    }
    let mut consumed_files: Vec<String> = Vec::new();
    consumed_files.push(manifest_file.to_string());
    info!("{}", manifest_file);
    info!("{:#?}", segments);
    let mut timestamp = manifest_file
        .rsplit(' ')
        .next()
        .unwrap()
        .parse::<u64>()
        .unwrap();
    for segment in &segments {
        for (_, files) in segment {
            for file in files {
                timestamp = std::cmp::min(
                    timestamp,
                    file.rsplit(' ').next().unwrap().parse::<u64>().unwrap(),
                );
            }
        }
    }
    // Creates a new SystemTime from the specified number of whole seconds
    let timestamp =
        std::time::UNIX_EPOCH + std::time::Duration::from_secs((timestamp as f64 / 1000.0) as u64);
    // Create DateTime from SystemTime
    let timestamp = chrono::prelude::DateTime::<chrono::Utc>::from(timestamp);
    // Formats the combined date and time with the specified format string.
    let timestamp = timestamp.format("%Y%m%dT%H%M%S%Z").to_string();
    info!("max {}", timestamp);
    segments
        .into_iter()
        .enumerate()
        .for_each(|(num, hash_map)| {
            let outname = format!("{}_{}.{}", title, timestamp, num);
            info!("outname: {}", outname);
            let mut buffer =
                std::fs::File::create(std::path::Path::new("temp").join(&outname)).unwrap();
            if let Some(init) = hash_map.get("initialization") {
                for e in init {
                    if let Ok(c) = std::fs::read(e) {
                        if let Err(err) = buffer.write_all(&c) {
                            error!("write {} into {} failed: {}", e, outname, err);
                        };
                    }
                    consumed_files.push(e.to_string());
                }
            }
            if let Some(media) = hash_map.get("media") {
                for e in media {
                    if let Ok(c) = std::fs::read(e) {
                        if let Err(err) = buffer.write_all(&c) {
                            error!("write {} into {} failed: {}", e, outname, err);
                        }
                    }
                    consumed_files.push(e.to_string());
                }
            }
        });
    consumed_files
}

pub fn rename(from: &std::path::Path, to: &std::path::Path) -> std::io::Result<()> {
    std::fs::copy(&from, &to)?;
    std::fs::remove_file(&from)
}

fn scandirs(sourceroot: &std::ffi::OsString) {
    let (manifests, media): (Vec<_>, Vec<_>) = WalkDir::new(sourceroot)
        .into_iter()
        .filter_map(|s| s.ok())
        .filter(|entry| entry.path().is_file())
        .map(process_file)
        .filter(|mode| mode.is_dash())
        .partition(DashMode::is_manifest);
    debug!("media: {:#?}", media);
    debug!("manifests: {:#?}", manifests);
    let mut consumed_files = std::collections::HashSet::<String>::new();
    for manifest in manifests {
        if let DashMode::Manifest(s) = manifest {
            for v in process_manifest(&s, &media) {
                consumed_files.insert(v);
            }
        }
    }

    for file in consumed_files {
        match std::path::Path::new(&file).strip_prefix(sourceroot) {
            Ok(suffix) => {
                let target = std::path::Path::new("used").join(suffix);
                match target.parent() {
                    Some(parent) => std::fs::create_dir_all(parent),
                    None => {
                        error!("No parent of {:?}", target);
                        Ok(())
                    }
                };
                if let Err(e) = rename(std::path::Path::new(&file), &target) {
                    error!("Failed to move {:?} to {:?}: {}", file, target, e);
                }
            }
            Err(e) => error!(
                "Failed stripping prefix {:?} from {}: {}",
                sourceroot, file, e
            ),
        };
    }
}

fn main() {
    let env = Env::default().filter_or("RUST_LOG", "info");
    Builder::from_env(env)
        .format(|buf, record| {
            writeln!(
                buf,
                "{} [{}] - {}",
                Local::now().format("%Y-%m-%dT%H:%M:%S"),
                record.level(),
                record.args()
            )
        })
        .init();

    let args: Vec<OsString> = env::args_os().collect();

    let sourceroot = &args[1];

    scandirs(sourceroot);
}
