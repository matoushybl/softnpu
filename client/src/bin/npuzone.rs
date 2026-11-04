use anyhow::anyhow;
use clap::Parser;
use curl::easy::Easy;
use libnet::{delete_link, LinkFlags, LinkHandle};
use softnpu_client::cli::get_styles;
use softnpu_client::config;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::thread::sleep;
use std::time::Duration;
use zone::{Adm, Config};
use ztest::{FsMount, SimnetLink, Zfs, Zone};

/// This tool constructs a SoftNPU zone, optionally with an acompanying host
/// zone.
///
///        host         softnpu
///  ┌─────────────┐┌─────────────┐
///  │             ││ ┌ ─ ─ ─ ─ ┐ │       ┌ ─ ─ ─ ─ ┐
///  │┌ ─ ─ ┐┌────┐││┌────┐ ┌────┐│┌────┐
///  │       │shx0├┼┼┤shi0│ │spi0├┼┤spx0├─┤         │
///  ││     │└────┘││└────┘ └────┘│└────┘
///  │  svc        ││ │  ASIC   │ │       │ network │
///  ││     │┌────┐││┌────┐ ┌────┐│┌────┐
///  │       │shx1├┼┼┤shi1│ │spi1├┼┤spx1├─┤         │
///  │└ ─ ─ ┘└────┘││└────┘ └────┘│└────┘
///  │             ││ └ ─ ─ ─ ─ ┘ │       └ ─ ─ ─ ─ ┘
///  │       ┌────┐││┌────┐       │
///  │       │mgtc├┼┼┤mgts│       │
///  │       └────┘││└────┘       │
///  └─────────────┘└─────────────┘
#[derive(Parser, Debug)]
#[command(version, about, long_about = None, styles = get_styles())]
struct Cli {
    #[clap(subcommand)]
    subcmd: SubCommand,
}

#[derive(Parser, Debug)]
enum SubCommand {
    /// Create a SoftNpu zone
    Create(ZoneInfo),

    /// Destroy a SoftNpu zone
    Destroy(ZoneInfo),
}

#[derive(Parser, Debug)]
struct ZoneInfo {
    /// Name of the SoftNpu zone
    name: String,

    /// Specify number of ports.
    #[clap(long, default_value_t = 0)]
    port_count: usize,

    /// Specify specific as sys_port,host_port pairs.
    #[clap(long)]
    ports: Vec<String>,

    /// Also create the host zone and plumb in ports.
    #[clap(long)]
    with_host: bool,

    /// Use the omicron zone type instead of sparse.
    #[clap(long)]
    omicron_zone: bool,

    /// The softnpu branch to use
    #[clap(long)]
    softnpu_commit: Option<String>,

    // hardcode for now until repo is open
    /// The sidecar-lite branch to use
    #[clap(long)]
    sidecar_lite_commit: Option<String>,
}

#[derive(Default)]
struct Resources {
    ports: Vec<SimnetLink>,
    zones: Vec<Zone>,
    user_supplied_ports: Vec<String>,
    zfs: Vec<Zfs>,
}

#[derive(Debug, Clone)]
enum PortSpec {
    Count(usize),
    List(Vec<String>),
}

const SOFTNPU_ZONE_NAME_SUFFIX: &str = "softnpu";
const HOST_ZONE_NAME_SUFFIX: &str = "host";
const SPARSE_BRAND: &str = "sparse";
const OMICRON_BRAND: &str = "omicron1";
const PFEXEC: &str = "/bin/pfexec";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.subcmd {
        SubCommand::Create(z) => {
            let brand = if z.omicron_zone {
                OMICRON_BRAND
            } else {
                SPARSE_BRAND
            };
            let mut resources = Resources::default();
            fetch_required_artifacts(
                &z.name,
                &z.softnpu_commit,
                &z.sidecar_lite_commit,
            )
            .await?;
            create_ports(&z.name, get_port_spec(&z)?, &mut resources)?;
            create_zones(&z.name, z.with_host, &mut resources, brand)?;
            // Exit without calling cleanup destructors. We want the resources
            // to stay! If we exit due to a question mark, things will be
            // cleaned up.
            std::process::exit(0);
        }
        SubCommand::Destroy(z) => {
            destroy_zones(&z.name, z.with_host);
            destroy_ports(&z.name, get_port_spec(&z)?)?;
            std::fs::remove_dir_all(format!("/{}", z.name))?;
        }
    }

    Ok(())
}

fn get_port_spec(z: &ZoneInfo) -> anyhow::Result<PortSpec> {
    if z.port_count != 0 && !z.ports.is_empty() {
        return Err(anyhow!("--port-count and --ports are exclusive"));
    }
    if z.port_count == 0 && z.ports.is_empty() {
        return Err(anyhow!("must provide --port-count or --ports"));
    }
    if z.port_count != 0 {
        Ok(PortSpec::Count(z.port_count))
    } else {
        Ok(PortSpec::List(z.ports.clone()))
    }
}

async fn fetch_required_artifacts(
    name: &str,
    softnpu_commit: &Option<String>,
    sidecar_lite_commit: &Option<String>,
) -> anyhow::Result<()> {
    fetch_softnpu(name, softnpu_commit).await?;
    fetch_sidecar_lite(name, sidecar_lite_commit).await?;
    fetch_scadm(name, sidecar_lite_commit).await?;
    Ok(())
}

async fn fetch_head_softnpu_commit(branch: &str) -> anyhow::Result<String> {
    Ok(octocrab::instance()
        .repos("oxidecomputer", "softnpu")
        .list_commits()
        .branch(branch)
        .page(1u32)
        .per_page(1)
        .send()
        .await?
        .take_items()[0]
        .sha
        .clone())
}

async fn fetch_head_sidecar_lite_commit(
    branch: &str,
) -> anyhow::Result<String> {
    Ok(octocrab::instance()
        .repos("oxidecomputer", "sidecar-lite")
        .list_commits()
        .branch(branch)
        .page(1u32)
        .per_page(1)
        .send()
        .await?
        .take_items()[0]
        .sha
        .clone())
}

async fn fetch_softnpu_url(
    shasum: bool,
    commit: &Option<String>,
) -> anyhow::Result<String> {
    let rev = match commit {
        None => fetch_head_softnpu_commit("main").await?,
        Some(commit) => commit.clone(),
    };
    let base = "https://buildomat.eng.oxide.computer";
    let path = "public/file/oxidecomputer/softnpu/image";
    let file = if shasum {
        "softnpu.sha256.txt"
    } else {
        "softnpu"
    };
    Ok(format!("{}/{}/{}/{}", base, path, rev, file))
}

async fn fetch_sidecar_lite_url(
    shasum: bool,
    commit: &Option<String>,
) -> anyhow::Result<String> {
    let rev = match commit {
        None => fetch_head_sidecar_lite_commit("main").await?,
        Some(commit) => commit.clone(),
    };
    let base = "https://buildomat.eng.oxide.computer";
    let path = "public/file/oxidecomputer/sidecar-lite/release";
    let file = if shasum {
        "libsidecar_lite.so.sha256.txt"
    } else {
        "libsidecar_lite.so"
    };
    Ok(format!("{}/{}/{}/{}", base, path, rev, file))
}

async fn fetch_scadm_url(
    shasum: bool,
    commit: &Option<String>,
) -> anyhow::Result<String> {
    let rev = match commit {
        None => fetch_head_sidecar_lite_commit("main").await?,
        Some(commit) => commit.clone(),
    };
    let base = "https://buildomat.eng.oxide.computer";
    let path = "public/file/oxidecomputer/sidecar-lite/release";
    let file = if shasum { "scadm.sha256.txt" } else { "scadm" };
    Ok(format!("{}/{}/{}/{}", base, path, rev, file))
}

fn runtime_dir(name: &str) -> String {
    // Persistent (rpool-backed) so the softnpu zone's lofs-mounted /softnpu
    // survives host reboots: the zone's binaries/toml/snapshots are the
    // scrimlet-equivalent of M.2 contents and must live on disk, not tmpfs.
    // Was /var/run/softnpu (tmpfs) which made autoboot fail verify at boot.
    format!("/var/softnpu/{}", name)
}

async fn fetch_sidecar_lite(
    name: &str,
    commit: &Option<String>,
) -> anyhow::Result<()> {
    fetch_artifact(
        &fetch_sidecar_lite_url(false, commit).await?,
        &fetch_sidecar_lite_url(true, commit).await?,
        "asic_program.so",
        name,
    )
    .await
}

async fn fetch_scadm(
    name: &str,
    commit: &Option<String>,
) -> anyhow::Result<()> {
    fetch_artifact(
        &fetch_scadm_url(false, commit).await?,
        &fetch_scadm_url(true, commit).await?,
        "scadm",
        name,
    )
    .await
}

async fn fetch_softnpu(
    name: &str,
    commit: &Option<String>,
) -> anyhow::Result<()> {
    fetch_artifact(
        &fetch_softnpu_url(false, commit).await?,
        &fetch_softnpu_url(true, commit).await?,
        "softnpu",
        name,
    )
    .await
}

async fn fetch_artifact(
    artifact_url: &str,
    shasum_url: &str,
    filename: &str,
    name: &str,
) -> anyhow::Result<()> {
    let mut easy = Easy::new();
    let name = name.to_owned();

    // Local override: if a fork-built artifact is present in the
    // fork-image dir, install it unconditionally and skip buildomat
    // entirely. This lets a (non-buildomat) fork softnpu/
    // sidecar-lite ride the standard `npu create sidecar` provisioning so
    // the zone is born with the fork binaries (no post-boot swaps, no
    // switch reprogramming dance). The dir is persistent (matches
    // runtime_dir's /var/softnpu root) so staged fork artifacts also
    // survive host reboots.
    let fork_image = format!("/var/softnpu/fork-image/{}", filename);
    if std::path::Path::new(&fork_image).exists() {
        let dir = runtime_dir(&name);
        std::fs::create_dir_all(&dir)?;
        let mut src = std::fs::File::open(&fork_image)?;
        let mut dst = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o755)
            .open(format!("{}/{}", dir, filename))?;
        std::io::copy(&mut src, &mut dst)?;
        println!(
            "local override: installed {} from {}",
            filename, fork_image
        );
        return Ok(());
    }

    println!("remote url: {shasum_url}");

    let mut remote_shasum = Vec::new();
    easy.url(shasum_url).unwrap();
    let mut transfer = easy.transfer();
    transfer.write_function(|data| {
        remote_shasum.extend_from_slice(data);
        Ok(data.len())
    })?;
    transfer.perform()?;
    drop(transfer);

    let remote_shasum =
        String::from_utf8_lossy(remote_shasum.as_slice()).to_string();
    let remote_shasum = remote_shasum.trim().to_owned();

    let dir = runtime_dir(&name);
    std::fs::create_dir_all(&dir)?;
    let filepath = format!("{}/{}", dir, filename);
    let path = std::path::Path::new(&filepath);

    if let Ok(digest) = sha256::try_digest(path) {
        if digest == remote_shasum {
            println!("already have latest {filename}");
            return Ok(());
        } else {
            println!(
                "{filename} shasum mismatch \n{:?} != {:?}",
                digest, remote_shasum,
            );
            println!("will update {filename}")
        }
    }

    print!("downloading {filename} ...");
    std::io::stdout().flush()?;

    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o755)
        .open(path)
        .unwrap();

    easy.url(artifact_url).unwrap();
    let mut transfer = easy.transfer();
    transfer.write_function(|data| {
        f.write_all(data).unwrap();
        Ok(data.len())
    })?;
    transfer.perform()?;
    drop(transfer);

    println!("done");

    Ok(())
}

fn create_ports(
    name: &str,
    spec: PortSpec,
    resources: &mut Resources,
) -> anyhow::Result<()> {
    let mut cfg = config::Config {
        p4_program: "/softnpu/asic_program.so".to_owned(),
        ..Default::default()
    };
    match spec {
        PortSpec::Count(count) => {
            for i in 0..count {
                println!("creating port {}", i);
                let external_ifx = format!("{}_shx{}", name, i);
                let internal_ifx = format!("{}_shi{}", name, i);
                let scrimlet = internal_ifx.clone();
                resources
                    .ports
                    .push(SimnetLink::new(&external_ifx, &internal_ifx)?);

                let external_ifx = format!("{}_spx{}", name, i);
                let internal_ifx = format!("{}_spi{}", name, i);
                let sidecar = internal_ifx.clone();
                resources
                    .ports
                    .push(SimnetLink::new(&external_ifx, &internal_ifx)?);
                cfg.ports.push(config::Port {
                    sidecar,
                    scrimlet,
                    mtu: 9000,
                });
            }
        }
        PortSpec::List(ports) => {
            for (i, p) in ports.iter().enumerate() {
                let (sys, host) = p
                    .split_once(',')
                    .ok_or(anyhow!("--port expected sys,host found {p}"))?;
                println!("creating port {host} for {sys}");
                let external_ifx = host.to_string();
                let internal_ifx = format!("{name}_shi{i}");
                let scrimlet = internal_ifx.clone();
                // Mirror the sidecar datalink's MAC onto the scrimlet-side simnet for
                // the uplink (qsfp) port: the softnpu treats the MAC of its external
                // datalink as its "local MAC" and drops external unicast frames sent
                // to any other MAC. Sharing the MAC makes the link L2-transparent so
                // the switch zone can announce/learn it normally.
                let mac = if host.contains("qsfp") {
                    Some(libnet::get_link(&LinkHandle::Name(sys.to_owned()))?.mac)
                } else {
                    None
                };
                resources
                    .ports
                    .push(SimnetLink::with_mac(&external_ifx, &internal_ifx, mac, None)?);
                resources.user_supplied_ports.push(sys.to_owned());
                let sidecar = sys.to_owned();
                cfg.ports.push(config::Port {
                    sidecar,
                    scrimlet,
                    mtu: 9000,
                });
            }
        }
    }

    let filepath = format!("{}/softnpu.toml", runtime_dir(name));
    let mut f = std::fs::File::create(filepath)?;
    f.write_all(toml::to_string(&cfg)?.as_bytes())?;
    Ok(())
}

fn destroy_ports(name: &str, port_spec: PortSpec) -> anyhow::Result<()> {
    match port_spec {
        PortSpec::Count(count) => {
            for i in 0..count {
                destroy_port(format!("{}_shx{}", name, i));
                destroy_port(format!("{}_shi{}", name, i));
                destroy_port(format!("{}_spx{}", name, i));
                destroy_port(format!("{}_spi{}", name, i));
            }
        }
        PortSpec::List(ports) => {
            for (i, p) in ports.iter().enumerate() {
                let (_sys, host) = p
                    .split_once(',')
                    .ok_or(anyhow!("--port expected sys,host found {}", p))?;
                destroy_port(format!("{}_shi{}", name, i));
                destroy_port(host.to_owned());
            }
        }
    };
    Ok(())
}

fn destroy_port(name: String) {
    println!("destroying port {}", name);
    let h = LinkHandle::Name(name.clone());
    if let Err(e) = delete_link(&h, LinkFlags::Active) {
        eprintln!("failed to delete link {}: {}", name, e);
    }
}

fn create_zones(
    name: &str,
    with_host: bool,
    resources: &mut Resources,
    brand: &str,
) -> anyhow::Result<()> {
    let zfs = Zfs::new(name)?;
    println!("softnpu zone setup");
    create_softnpu_zone(name, resources, &zfs, brand)?;
    if with_host {
        println!("host zone setup");
        create_host_zone(name, resources, &zfs, brand)?;
    }
    resources.zfs.push(zfs);
    Ok(())
}

fn destroy_zones(name: &str, with_host: bool) {
    if let Err(e) = std::process::Command::new(PFEXEC)
        .env_clear()
        .arg("zfs")
        .arg("destroy")
        .arg("-rf")
        .arg(format!("rpool/{}", name))
        .output()
    {
        eprintln!("failed to delete zfs dataset rpool/{name}: {e}")
    }

    destroy_zone(format!("{}_{}", name, SOFTNPU_ZONE_NAME_SUFFIX));
    if with_host {
        destroy_zone(format!("{}_{}", name, HOST_ZONE_NAME_SUFFIX));
    }
}

fn destroy_zone(name: String) {
    println!("halting zone {name}");
    if let Err(e) = Adm::new(&name).halt_blocking() {
        eprintln!("failed to halt zone config for {name}: {e}");
    }

    println!("uninstalling zone {name}");
    if let Err(e) = Adm::new(&name).uninstall_blocking(true) {
        eprintln!("failed to uninstall zone config for {name}: {e}");
    }

    println!("deleting zone {name}");
    let mut c = Config::new(&name);
    if let Err(e) = c.delete(true).run_blocking() {
        eprintln!("failed to delete zone config for {name}: {e}");
    }
}

fn create_softnpu_zone(
    name: &str,
    resources: &mut Resources,
    zfs: &Zfs,
    brand: &str,
) -> anyhow::Result<()> {
    let mut phys: Vec<&str> =
        resources.ports.iter().map(|p| p.end_b.as_str()).collect();

    for p in &resources.user_supplied_ports {
        phys.push(p.as_str());
    }

    let dir = runtime_dir(name);
    let fs = FsMount::new(&dir, "/softnpu");

    let z = Zone::new(
        &format!("{}_{}", name, SOFTNPU_ZONE_NAME_SUFFIX),
        brand,
        zfs,
        &phys,
        &[fs],
    )?;
    sleep(Duration::from_secs(3));
    copy_in_mgmt_script(name)?;
    z.zexec("/usr/sbin/svccfg import /softnpu/manifest/softnpu.xml")?;
    z.wait_for_network()?;
    z.zexec("/softnpu/npu start")?;
    resources.zones.push(z);
    Ok(())
}

fn create_host_zone(
    name: &str,
    resources: &mut Resources,
    zfs: &Zfs,
    brand: &str,
) -> anyhow::Result<()> {
    // host ports are only the first half
    let n = resources.ports.len() / 2;
    let phys: Vec<&str> = resources.ports[..n]
        .iter()
        .map(|p| p.end_a.as_str())
        .collect();

    let dir = runtime_dir(name);
    let fs = FsMount::new(&dir, "/softnpu");

    resources.zones.push(Zone::new(
        &format!("{}_{}", name, HOST_ZONE_NAME_SUFFIX),
        brand,
        zfs,
        &phys,
        &[fs],
    )?);
    Ok(())
}

fn copy_in_mgmt_script(name: &str) -> anyhow::Result<()> {
    let dir = runtime_dir(name);
    let path = format!("{}/npu", dir);
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o755)
        .open(path)?;
    f.write_all(SOFTNPU_SCRIPT.as_bytes())?;

    // In-zone SMF manifest so zone boot (autoboot) starts softnpu as a real
    // service instead of relying on the one-shot zexec at create time.
    // Without this, a booted zone has nobody to run the runtime.
    let manifest_dir = format!("{}/manifest", dir);
    std::fs::create_dir_all(&manifest_dir)?;
    let manifest_path = format!("{}/softnpu.xml", manifest_dir);
    let mut m = std::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(manifest_path)?;
    m.write_all(SMF_MANIFEST.as_bytes())?;
    Ok(())
}

const SMF_MANIFEST: &str = r#"<?xml version="1.0"?>
<!DOCTYPE service_bundle SYSTEM "/usr/share/lib/xml/dtd/service_bundle.dtd.1">
<service_bundle type="manifest" name="softnpu">
  <service name="oxide/softnpu" type="service" version="1">
    <create_default_instance enabled="true"/>
    <single_instance/>
    <dependency name="filesystem" grouping="require_all" restart_on="error"
      type="service">
      <service_fmri value="svc:/system/filesystem/minimal"/>
    </dependency>
    <dependency name="network" grouping="require_any" restart_on="error"
      type="service">
      <service_fmri value="svc:/network/service"/>
    </dependency>
    <exec_method type="method" name="start"
      exec="/softnpu/npu start" timeout_seconds="60"/>
    <exec_method type="method" name="stop"
      exec="/softnpu/npu stop" timeout_seconds="60"/>
    <property_group name="startd" type="framework">
      <propval name="duration" type="astring" value="contract"/>
      <propval name="ignore_error" type="astring" value="core,signal"/>
    </property_group>
    <stability value="Evolving"/>
    <template>
      <common_name>
        <loctext xml:lang="C">Softnpu packet processor</loctext>
      </common_name>
    </template>
  </service>
</service_bundle>
"#;


const SOFTNPU_SCRIPT: &str = "#!/bin/bash

case $1 in
    start) 
        if pgrep -f softnpu.bin > /dev/null 2>&1; then
            exit 0
        fi
        /softnpu/softnpu \\
            --uds-path /softnpu \\
            /softnpu/softnpu.toml \\
            &> /var/log/softnpu.log \\
            &
        ;;
    stop)
        pkill -9 softnpu
        ;;
    *)
        echo 'usage: npu [start|stop]'
        exit 1
        ;;
esac
";
