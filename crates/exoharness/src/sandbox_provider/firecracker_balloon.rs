use super::*;

pub(super) const KVM_CAP_NR_MEMSLOTS: libc::c_int = 10;
pub(super) const KVM_CAP_MAX_VCPUS: libc::c_int = 66;

const BALLOON_POLL_INTERVAL: Duration = Duration::from_millis(100);

#[derive(Serialize)]
pub(super) struct Configuration {
    amount_mib: u32,
    deflate_on_oom: bool,
    stats_polling_interval_s: u32,
}

#[derive(Serialize)]
pub(super) struct HotplugConfiguration {
    total_size_mib: u32,
    slot_size_mib: u32,
}

#[derive(Serialize, Deserialize)]
struct HotplugTarget {
    requested_size_mib: u32,
}

#[derive(Debug, Deserialize)]
struct HotplugStatistics {
    requested_size_mib: u32,
    plugged_size_mib: u32,
}

#[derive(Serialize, Deserialize)]
struct BalloonTarget {
    amount_mib: u32,
}

#[derive(Debug, Deserialize)]
pub(super) struct Statistics {
    pub(super) target_pages: u64,
    pub(super) actual_pages: u64,
}

pub(super) fn ceiling(runtime: &FirecrackerRuntimeFingerprint) -> Option<SandboxResourceShape> {
    SandboxResourceShape::new(
        runtime.cpu_ceiling.unwrap_or(runtime.vcpu_count),
        runtime.memory_ceiling_mib.unwrap_or(runtime.memory_mib),
    )
}

pub(super) fn validate_grant(
    runtime: &FirecrackerRuntimeFingerprint,
    grant: SandboxResourceShape,
) -> Result<()> {
    let ceiling = ceiling(runtime).context("invalid Firecracker resource capacity")?;
    runtime.validate_memory_grant(grant.memory_mib.get())?;
    ensure!(
        grant.vcpu_count.get() >= runtime.vcpu_count && grant.vcpu_count <= ceiling.vcpu_count,
        "Firecracker resource grant must grow within the running VM's capacity"
    );
    Ok(())
}

pub(super) fn resources(record: &MachineRecord) -> Result<SandboxResourceShape> {
    if record.resource_grant.is_none()
        && (record.runtime.cpu_ceiling.is_some() || record.runtime.memory_ceiling_mib.is_some())
    {
        bail!("Firecracker live allocation has no resource grant; recreate it before resizing");
    }
    let grant = record
        .resource_grant
        .or_else(|| SandboxResourceShape::new(record.runtime.vcpu_count, record.runtime.memory_mib))
        .context("invalid Firecracker resource grant")?;
    validate_grant(&record.runtime, grant)?;
    Ok(grant)
}

pub(super) fn grant(record: &MachineRecord) -> Result<u32> {
    Ok(resources(record)?.memory_mib.get())
}

pub(super) fn cpu_quota(vcpus: u16) -> String {
    format!("{} 100000", u64::from(vcpus) * 100_000)
}

pub(super) fn kvm_capability(capability: libc::c_int) -> Result<u32> {
    use std::os::fd::AsRawFd;
    let kvm = File::open("/dev/kvm")?;
    // SAFETY: KVM_CHECK_EXTENSION reads an integer capability, not a pointer.
    const KVM_CHECK_EXTENSION: libc::c_ulong = 0xAE03;
    let value = unsafe { libc::ioctl(kvm.as_raw_fd(), KVM_CHECK_EXTENSION, capability) };
    ensure!(value > 0, "KVM capability {capability} is unavailable");
    Ok(u32::try_from(value)?)
}

pub(super) fn host_memory_capacity() -> Result<std::num::NonZeroU32> {
    let info = fs::read_to_string("/proc/meminfo")?;
    let kib: u64 = info
        .lines()
        .find_map(|line| line.strip_prefix("MemTotal:"))
        .and_then(|value| value.split_whitespace().next())
        .context("host memory capacity is unavailable")?
        .parse()?;
    let mut bytes = kib
        .checked_mul(1024)
        .context("host memory capacity overflow")?;
    let membership = fs::read_to_string("/proc/self/cgroup")?;
    let relative = membership
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .context("live growth requires cgroup v2")?;
    let root = Path::new("/sys/fs/cgroup");
    let mut group = root.to_owned();
    for component in Path::new(relative).components() {
        match component {
            std::path::Component::Normal(name) => group.push(name),
            std::path::Component::RootDir | std::path::Component::CurDir => {}
            _ => bail!("invalid host cgroup path"),
        }
    }
    loop {
        let limit = group.join("memory.max");
        if limit.try_exists()? {
            let value = fs::read_to_string(limit)?;
            if value.trim() != "max" {
                bytes = bytes.min(value.trim().parse()?);
            }
        }
        if group == root {
            break;
        }
        ensure!(group.pop(), "invalid host cgroup hierarchy");
    }
    let mib = u32::try_from(bytes / (1024 * 1024))?
        .checked_sub(FIRECRACKER_MEMORY_HEADROOM_MIB as u32)
        .context("host memory capacity cannot cover Firecracker overhead")?;
    std::num::NonZeroU32::new(mib).context("host memory capacity is empty")
}

pub(super) fn hotplug_configuration(
    runtime: &FirecrackerRuntimeFingerprint,
) -> Option<HotplugConfiguration> {
    let total_size_mib = runtime.hotplug_memory_mib();
    (total_size_mib > 0).then_some(HotplugConfiguration {
        total_size_mib,
        slot_size_mib: runtime.memory_slot_size_mib.unwrap_or(128),
    })
}

pub(super) fn configuration(record: &MachineRecord) -> Result<Option<Configuration>> {
    record
        .runtime
        .memory_ceiling_mib
        .map(|_| {
            let grant = grant(record)?;
            Ok(Configuration {
                amount_mib: record.runtime.physical_memory_mib(grant) - grant,
                deflate_on_oom: false,
                stats_polling_interval_s: 3600,
            })
        })
        .transpose()
}

pub(super) fn deadline(memory_mib: u32) -> Instant {
    Instant::now() + Duration::from_secs(30 + u64::from(memory_mib).div_ceil(128))
}

fn api_timeout(deadline: Instant) -> Result<Duration> {
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .filter(|duration| !duration.is_zero())
        .context("Firecracker resource update deadline expired")?;
    Ok(remaining.min(FIRECRACKER_API_TIMEOUT))
}

fn wait_for_target(socket: &Path, amount_mib: u32, deadline: Instant) -> Result<()> {
    let pages = u64::from(amount_mib) * 256;
    let mut observed: Option<Statistics> = None;
    loop {
        let timeout = api_timeout(deadline).with_context(|| {
            format!("Firecracker balloon timed out: target {pages} pages, observed {observed:?}")
        })?;
        let response =
            firecracker_api_response(socket, "GET", "/balloon/statistics", &[], timeout)?;
        let stats: Statistics = serde_json::from_slice(&response)?;
        if stats.target_pages == pages && stats.actual_pages == pages {
            return Ok(());
        }
        observed = Some(stats);
        std::thread::sleep(
            BALLOON_POLL_INTERVAL.min(deadline.saturating_duration_since(Instant::now())),
        );
    }
}

pub(super) fn initialize_until(
    config: &FirecrackerConfig,
    record: &MachineRecord,
    deadline: Instant,
) -> Result<()> {
    let grant = grant(record)?;
    let runtime = &record.runtime;
    ensure!(
        runtime.memory_ceiling_mib.is_some(),
        "Firecracker has no live memory capacity"
    );
    let socket = jail_root(config, &record.machine_id).join("run/firecracker.socket");
    if runtime.hotplug_memory_mib() > 0 {
        let requested_size_mib = runtime.physical_memory_mib(grant) - runtime.boot_memory_mib();
        firecracker_api_request(
            &socket,
            "PATCH",
            "/hotplug/memory",
            &HotplugTarget { requested_size_mib },
            api_timeout(deadline)?,
        )?;
        let mut observed: Option<HotplugStatistics> = None;
        loop {
            let timeout = api_timeout(deadline).with_context(|| format!(
                "Firecracker memory hotplug timed out: target {requested_size_mib} MiB, observed {observed:?}; verify CONFIG_VIRTIO_MEM and automatic memory onlining"
            ))?;
            let response =
                firecracker_api_response(&socket, "GET", "/hotplug/memory", &[], timeout)?;
            let stats: HotplugStatistics = serde_json::from_slice(&response)?;
            if stats.requested_size_mib == requested_size_mib
                && stats.plugged_size_mib == requested_size_mib
            {
                break;
            }
            observed = Some(stats);
            std::thread::sleep(
                BALLOON_POLL_INTERVAL.min(deadline.saturating_duration_since(Instant::now())),
            );
        }
    }
    let target = runtime.physical_memory_mib(grant) - grant;
    firecracker_api_request(
        &socket,
        "PATCH",
        "/balloon",
        &BalloonTarget { amount_mib: target },
        api_timeout(deadline)?,
    )?;
    wait_for_target(&socket, target, deadline)
}

pub(super) fn expand(
    config: &FirecrackerConfig,
    record: &MachineRecord,
    target: SandboxResourceShape,
) -> crate::SandboxResult<crate::SandboxResourceUpdate> {
    let current = resources(record)?;
    let ceiling = ceiling(&record.runtime).context("invalid Firecracker resource capacity")?;
    if (record.runtime.cpu_ceiling.is_none() && record.runtime.memory_ceiling_mib.is_none())
        || target.vcpu_count < current.vcpu_count
        || target.memory_mib < current.memory_mib
        || target.vcpu_count > ceiling.vcpu_count
        || target.memory_mib > ceiling.memory_mib
    {
        return Err(crate::SandboxFailure::InvalidRequest {
            message: "Firecracker live expansion must grow within the running VM's capacity".into(),
        }
        .into());
    }
    if !process_running(&jail_root(config, &record.machine_id).join("firecracker.pid")) {
        return Err(anyhow!("Firecracker expansion source is not running").into());
    }
    apply_grant(
        config,
        record,
        &firecracker_cgroup_dir(config, &record.machine_id),
        target,
    )
}

fn apply_grant(
    config: &FirecrackerConfig,
    record: &MachineRecord,
    cgroup: &Path,
    target: SandboxResourceShape,
) -> crate::SandboxResult<crate::SandboxResourceUpdate> {
    let memory_mib = target.memory_mib.get();
    let deadline = deadline(memory_mib);
    let mut record = record.clone();
    record.resource_grant = Some(target);
    // Journal the reservation before changing any host or guest limit.
    replace_manifest(&config.state_root, &record)?;
    use crate::SandboxResourceUpdateStatus::{Confirmed, Unconfirmed};
    let mut cpu = if record.runtime.cpu_ceiling.is_some() {
        Unconfirmed
    } else {
        Confirmed
    };
    let mut memory = if record.runtime.memory_ceiling_mib.is_some() {
        Unconfirmed
    } else {
        Confirmed
    };
    let applied = (|| -> Result<()> {
        fs::write(
            cgroup.join("memory.max"),
            (u64::from(firecracker_host_reservation(target)?.memory_mib.get()) * 1024 * 1024)
                .to_string(),
        )?;
        fs::write(
            cgroup.join("memory.high"),
            ((u64::from(memory_mib) + 256) * 1024 * 1024).to_string(),
        )?;
        if record.runtime.cpu_ceiling.is_some() {
            fs::write(cgroup.join("cpu.max"), cpu_quota(target.vcpu_count.get()))?;
            cpu = Confirmed;
        }
        if record.runtime.memory_ceiling_mib.is_some() {
            initialize_until(config, &record, deadline)?;
            memory = Confirmed;
        }
        Ok(())
    })();
    Ok(match applied {
        Ok(()) => crate::SandboxResourceUpdate::Applied { grant: target },
        Err(error) => crate::SandboxResourceUpdate::Incomplete {
            reservation: target,
            cpu,
            memory,
            error: error.into(),
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record() -> MachineRecord {
        let mut runtime = super::super::tests::test_runtime();
        runtime.vcpu_count = 2;
        runtime.memory_mib = 4096;
        runtime.memory_ceiling_mib = Some(16384);
        MachineRecord {
            machine_id: "fc-0123456789abcdef-01234567".to_owned(),
            spec_hash: "spec".to_owned(),
            runtime,
            resource_grant: SandboxResourceShape::new(2, 4096),
            resolved_image: "image".to_owned(),
            slot: 1,
            network_enabled: false,
            workspace_id: None,
            resource_paths: Vec::new(),
            idle_ttl_seconds: None,
            snapshot_template: None,
            snapshot_network_slot: None,
        }
    }

    #[test]
    fn timeout_reports_observed_balloon_pages() -> Result<()> {
        let root = tempfile::tempdir_in("/tmp")?;
        let socket = root.path().join("api");
        let listener = StdUnixListener::bind(&socket)?;
        let peer = std::thread::spawn(move || -> Result<()> {
            let (mut stream, _) = listener.accept()?;
            let (request, body) = super::super::tests::read_api_request(&mut stream)?;
            assert!(request.starts_with("GET /balloon/statistics "));
            assert!(body.is_empty());
            let body = r#"{"target_pages":256,"actual_pages":7}"#;
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            )?;
            Ok(())
        });
        let error =
            wait_for_target(&socket, 1, Instant::now() + Duration::from_millis(20)).unwrap_err();
        assert!(error.to_string().contains("actual_pages: 7"));
        peer.join().unwrap()?;
        Ok(())
    }

    #[test]
    fn api_waits_share_the_remaining_resize_deadline() -> Result<()> {
        let root = tempfile::tempdir_in("/tmp")?;
        let config = FirecrackerConfig {
            state_root: root.path().into(),
            ..Default::default()
        };
        let record = record();
        let socket = jail_root(&config, &record.machine_id).join("run/firecracker.socket");
        fs::create_dir_all(socket.parent().context("socket parent")?)?;
        let listener = StdUnixListener::bind(socket)?;
        let (release, blocked) = std::sync::mpsc::channel();
        let peer = std::thread::spawn(move || -> Result<()> {
            let (mut stream, _) = listener.accept()?;
            let (request, _) = super::super::tests::read_api_request(&mut stream)?;
            assert!(request.starts_with("PATCH /hotplug/memory "));
            stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")?;
            let (mut stream, _) = listener.accept()?;
            let (request, _) = super::super::tests::read_api_request(&mut stream)?;
            assert!(request.starts_with("GET /hotplug/memory "));
            blocked.recv()?;
            Ok(())
        });
        let started = Instant::now();
        let error =
            initialize_until(&config, &record, started + Duration::from_secs(2)).unwrap_err();
        let elapsed = started.elapsed();
        release.send(())?;
        peer.join().unwrap()?;
        assert!(
            error.chain().any(|cause| cause
                .downcast_ref::<std::io::Error>()
                .is_some_and(|error| error.kind() == std::io::ErrorKind::TimedOut)),
            "{error:#}"
        );
        assert!(
            elapsed < Duration::from_secs(4),
            "API wait ignored the remaining deadline: {elapsed:?}"
        );
        Ok(())
    }

    #[test]
    fn failed_host_limit_retains_the_reservation_for_retry() -> Result<()> {
        let root = tempfile::tempdir()?;
        let config = FirecrackerConfig {
            state_root: root.path().into(),
            ..Default::default()
        };
        let record = record();
        fs::create_dir_all(config.state_root.join("manifests"))?;
        write_manifest(&config.state_root, &record)?;
        let before = fs::read(manifest_path(&config.state_root, &record.machine_id))?;
        let update = apply_grant(
            &config,
            &record,
            &root.path().join("missing-cgroup"),
            SandboxResourceShape::new(2, 8192).unwrap(),
        )
        .unwrap();
        assert!(matches!(
            update,
            crate::SandboxResourceUpdate::Incomplete {
                memory: crate::SandboxResourceUpdateStatus::Unconfirmed,
                ..
            }
        ));
        let after = fs::read(manifest_path(&config.state_root, &record.machine_id))?;
        assert_ne!(after, before);
        let persisted: MachineRecord = serde_json::from_slice(&after)?;
        assert_eq!(grant(&persisted)?, 8192);
        Ok(())
    }

    #[test]
    fn host_limit_precedes_deflation_and_completion_waits_for_actual_pages() {
        let root = tempfile::tempdir_in("/tmp").unwrap();
        let config = FirecrackerConfig {
            state_root: root.path().to_owned(),
            ..Default::default()
        };
        let mut record = record();
        record.runtime.cpu_ceiling = Some(8);
        fs::create_dir_all(config.state_root.join("manifests")).unwrap();
        write_manifest(&config.state_root, &record).unwrap();
        let initial = configuration(&record).unwrap().unwrap();
        assert_eq!(initial.amount_mib, 0);
        assert!(!initial.deflate_on_oom);
        let socket = jail_root(&config, &record.machine_id).join("run/firecracker.socket");
        fs::create_dir_all(socket.parent().unwrap()).unwrap();
        let listener = StdUnixListener::bind(&socket).unwrap();
        let cgroup = root.path().join("cgroup");
        fs::create_dir(&cgroup).unwrap();
        let cgroup_for_peer = cgroup.clone();
        let peer = std::thread::spawn(move || {
            let replies = [
                ("PATCH /hotplug/memory ", 500, ""),
                ("PATCH /hotplug/memory ", 200, ""),
                (
                    "GET /hotplug/memory ",
                    200,
                    r#"{"requested_size_mib":4096,"plugged_size_mib":2048}"#,
                ),
                (
                    "GET /hotplug/memory ",
                    200,
                    r#"{"requested_size_mib":4096,"plugged_size_mib":4096}"#,
                ),
                ("PATCH /balloon ", 200, ""),
                (
                    "GET /balloon/statistics ",
                    200,
                    r#"{"target_pages":0,"actual_pages":1}"#,
                ),
                (
                    "GET /balloon/statistics ",
                    200,
                    r#"{"target_pages":0,"actual_pages":0}"#,
                ),
            ];
            for (path, status, response) in replies {
                let (mut stream, _) = listener.accept().unwrap();
                let (request, body) = super::super::tests::read_api_request(&mut stream).unwrap();
                assert!(request.starts_with(path), "{request}");
                assert_eq!(
                    fs::read_to_string(cgroup_for_peer.join("cpu.max")).unwrap(),
                    cpu_quota(4)
                );
                assert_eq!(
                    fs::read_to_string(cgroup_for_peer.join("memory.max")).unwrap(),
                    ((8192_u64 + 1024) * 1024 * 1024).to_string()
                );
                assert_eq!(
                    fs::read_to_string(cgroup_for_peer.join("memory.high")).unwrap(),
                    ((8192_u64 + 256) * 1024 * 1024).to_string()
                );
                if path == "PATCH /hotplug/memory " {
                    assert_eq!(
                        serde_json::from_slice::<HotplugTarget>(&body)
                            .unwrap()
                            .requested_size_mib,
                        4096
                    );
                } else if path == "PATCH /balloon " {
                    assert_eq!(
                        serde_json::from_slice::<BalloonTarget>(&body)
                            .unwrap()
                            .amount_mib,
                        0
                    );
                } else {
                    assert!(body.is_empty());
                }
                write!(stream, "HTTP/1.1 {status} OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response}", response.len()).unwrap();
            }
        });
        let resources = SandboxResourceShape::new(4, 8192).unwrap();
        assert!(
            matches!(apply_grant(&config, &record, &cgroup, resources).unwrap(), crate::SandboxResourceUpdate::Incomplete { reservation, cpu: crate::SandboxResourceUpdateStatus::Confirmed, memory: crate::SandboxResourceUpdateStatus::Unconfirmed, .. } if reservation == resources)
        );
        let record: MachineRecord = serde_json::from_slice(
            &fs::read(manifest_path(&config.state_root, &record.machine_id)).unwrap(),
        )
        .unwrap();
        assert_eq!(
            fs::metadata(manifest_path(&config.state_root, &record.machine_id))
                .unwrap()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(record.runtime.memory_mib, 4096);
        assert_eq!(grant(&record).unwrap(), 8192);
        assert!(
            matches!(apply_grant(&config, &record, &cgroup, resources).unwrap(), crate::SandboxResourceUpdate::Applied { grant } if grant == resources)
        );
        peer.join().unwrap();
        assert_eq!(grant(&record).unwrap(), 8192);
        assert_eq!(configuration(&record).unwrap().unwrap().amount_mib, 0);
        assert!(
            expand(
                &config,
                &record,
                SandboxResourceShape::new(3, 8192).unwrap()
            )
            .is_err()
        );
        assert!(
            expand(
                &config,
                &record,
                SandboxResourceShape::new(2, 4096).unwrap()
            )
            .is_err()
        );
        assert!(
            expand(
                &config,
                &record,
                SandboxResourceShape::new(2, 32768).unwrap()
            )
            .is_err()
        );
    }
    #[test]
    fn cpu_write_failure_retains_the_grant_and_retry_applies_it_without_a_balloon() -> Result<()> {
        let root = tempfile::tempdir()?;
        let config = FirecrackerConfig {
            state_root: root.path().into(),
            ..Default::default()
        };
        let mut record = record();
        record.runtime.cpu_ceiling = Some(8);
        record.runtime.memory_ceiling_mib = None;
        fs::create_dir(config.state_root.join("manifests"))?;
        write_manifest(&config.state_root, &record)?;
        let cgroup = root.path().join("cgroup");
        fs::create_dir(&cgroup)?;
        fs::create_dir(cgroup.join("cpu.max"))?;
        let target = SandboxResourceShape::new(4, 4096).unwrap();
        let update = apply_grant(&config, &record, &cgroup, target)?;
        assert!(matches!(update, crate::SandboxResourceUpdate::Incomplete {
                reservation,
                cpu: crate::SandboxResourceUpdateStatus::Unconfirmed,
                memory: crate::SandboxResourceUpdateStatus::Confirmed,
                ..
            } if reservation == target));
        let persisted: MachineRecord = serde_json::from_slice(&fs::read(manifest_path(
            &config.state_root,
            &record.machine_id,
        ))?)?;
        assert_eq!(resources(&persisted)?, target);
        assert_eq!(persisted.runtime.vcpu_count, 2);
        fs::remove_dir(cgroup.join("cpu.max"))?;
        assert!(matches!(apply_grant(&config, &persisted, &cgroup, target)?,
            crate::SandboxResourceUpdate::Applied { grant } if grant == target));
        assert_eq!(fs::read_to_string(cgroup.join("cpu.max"))?, "400000 100000");
        let before = fs::read(manifest_path(&config.state_root, &record.machine_id))?;
        let rejected = expand(
            &config,
            &persisted,
            SandboxResourceShape::new(2, 4096).unwrap(),
        )
        .unwrap_err();
        assert!(matches!(
            rejected.failure(),
            Some(crate::SandboxFailure::InvalidRequest { .. })
        ));
        assert_eq!(
            fs::read(manifest_path(&config.state_root, &record.machine_id))?,
            before
        );
        assert_eq!(fs::read_to_string(cgroup.join("cpu.max"))?, "400000 100000");
        Ok(())
    }
}
