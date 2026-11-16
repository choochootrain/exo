use super::tests::{native_request, shell};
use super::*;
use futures::io::AsyncReadExt as _;

fn cpu_usage(cgroup: &Path) -> Result<u64> {
    fs::read_to_string(cgroup.join("cpu.stat"))?
        .lines()
        .find_map(|line| line.strip_prefix("usage_usec "))
        .context("missing cgroup CPU usage")?
        .parse()
        .map_err(Into::into)
}

async fn cpu_rate(cgroup: &Path) -> Result<f64> {
    let before = cpu_usage(cgroup)?;
    let started = Instant::now();
    tokio::time::sleep(Duration::from_secs(2)).await;
    Ok((cpu_usage(cgroup)? - before) as f64 / 1_000_000.0 / started.elapsed().as_secs_f64())
}

#[tokio::test]
#[ignore = "requires root, KVM, Python guest image, at least four host CPUs, and TMPDIR on XFS"]
async fn live_cpu_growth_increases_execution_capacity_and_survives_filesystem_restore() -> Result<()>
{
    let temp = tempfile::Builder::new().prefix("cpu-").tempdir()?;
    let image = std::env::var("FIRECRACKER_IMAGE")?;
    let config = FirecrackerConfig {
        state_root: temp.path().join("s"),
        allowed_local_images: vec![image.clone().into()],
        image_size_gib: 1,
        workspace_size_gib: 1,
        live_cpu_growth: true,
        max_machines: NonZeroUsize::new(1),
        ..Default::default()
    };
    let backend = FirecrackerSandboxBackend::new(config.clone()).await?;
    let mut request = native_request(&config, "cpu-growth", &image)?;
    request.spec.resources = SandboxResourceShape::new(1, 512);
    let result: Result<()> = async {
        let handle = backend.acquire(request.clone()).await?;
        request.provider_state = handle.provider_state();
        let capacity = handle.live_resource_ceiling().context("missing CPU capacity")?;
        ensure!(capacity.vcpu_count.get() >= 4, "test needs four available host CPUs");
        assert_eq!(capacity.memory_mib.get(), 512);
        let id = backend.shared.warm_machines.lock().await[&request.sandbox_id].machine_id.clone();
        let cgroup = firecracker_cgroup_dir(&config, &id);
        let pid = fs::read(backend.shared.pid_path(&id))?;
        assert_eq!(fs::read_to_string(cgroup.join("cpu.max"))?.trim(), "100000 100000");
        assert_eq!(handle.live_resource_grant().await?, SandboxResourceShape::new(1, 512));
        let invalid = SandboxResourceShape::new(capacity.vcpu_count.get() + 1, 512).unwrap();
        let error = handle.expand_resources(invalid).await.unwrap_err();
        assert!(matches!(error.failure(), Some(crate::SandboxFailure::InvalidRequest { .. })));
        assert_eq!(fs::read_to_string(cgroup.join("cpu.max"))?.trim(), "100000 100000");

        let mut workers = handle.start_process(&SandboxCommand {
            argv: vec!["python3".into(), "-u".into(), "-c".into(), r#"
import os, time
for _ in range(4):
    if os.fork() == 0:
        while True:
            pass
print('ready', flush=True)
while True:
    time.sleep(1)
"#.into()],
            env: HashMap::new(),
            display_argv: None,
            cwd: Some("/".into()),
            timeout: Some(Duration::from_secs(120)),
        }).await?;
        let mut ready = [0; 6];
        workers.stdout.read_exact(&mut ready).await?;
        assert_eq!(&ready, b"ready\n");
        let before = cpu_rate(&cgroup).await?;
        assert!(before <= 1.3, "initial quota exceeded: {before}");
        let target = SandboxResourceShape::new(4, 512).unwrap();
        let mut growth = Box::pin(handle.expand_resources(target));
        assert!(futures::poll!(&mut growth).is_pending());
        drop(growth);
        assert_eq!(handle.live_resource_grant().await?, Some(target));
        assert!(matches!(handle.expand_resources(target).await?,
            crate::SandboxResourceUpdate::Applied { grant } if grant == target));
        assert_eq!(fs::read_to_string(cgroup.join("cpu.max"))?.trim(), "400000 100000");
        let after = cpu_rate(&cgroup).await?;
        assert!(after >= 2.0 && after > before * 1.7, "growth did not add execution capacity: {before} -> {after}");
        assert_eq!(fs::read(backend.shared.pid_path(&id))?, pid);
        let error = handle.expand_resources(SandboxResourceShape::new(2, 512).unwrap()).await.unwrap_err();
        assert!(matches!(error.failure(), Some(crate::SandboxFailure::InvalidRequest { .. })));
        assert_eq!(handle.live_resource_grant().await?, Some(target));
        assert_eq!(shell(&handle, "printf usable-after-growth").await?, "usable-after-growth");
        workers.terminate().await?;
        shell(&handle, "printf cpu > /tmp/cpu-state; printf workspace > /workspace/state; printf repository > /repo/state").await?;
        let capture = backend.suspend(request.clone(), crate::SnapshotKind::Filesystem).await?;
        let restored = backend.acquire_from_snapshot(request.clone(), capture.clone()).await?;
        assert_eq!(restored.live_resource_grant().await?, Some(target));
        assert_eq!(shell(&restored, "cat /tmp/cpu-state /workspace/state /repo/state").await?, "cpuworkspacerepository");
        restored.stop().await?;
        backend.delete_snapshot(capture).await?;
        Ok(())
    }.await;
    backend.terminate_all().await?;
    result
}
