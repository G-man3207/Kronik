use super::*;
use kronik_proto::log::v1 as pb;
use std::os::unix::fs::FileExt as _;

fn record(target: &str) -> Record {
    Record::AuditEvent(pb::AuditEvent { action: "test.native.readset".into(), target: target.into(),
        audit: Some(pb::Audit { token_id: "readset-test".into(), reason: "held ordinary source".into(), wall_time_ms: 1 }),
        ..Default::default() })
}

async fn open(env: &Env, config: &LogConfig)
    -> (Log, mpsc::UnboundedReceiver<Committed>, oneshot::Receiver<String>)
{
    let (committed, received) = mpsc::unbounded_channel();
    let (fatal, failed) = oneshot::channel();
    let (log, _) = Log::open(env, config.clone(), committed, fatal).await.unwrap();
    (log, received, failed)
}

#[tokio::test]
async fn held_file_namespace_and_finite_cut_survive_path_replacement_and_reject_actual_crc_damage() {
    let root = tempfile::tempdir().unwrap();
    let env = Env::real(tokio::runtime::Handle::current());
    let mut config = LogConfig::new(root.path().join("log"), "native-original");
    config.group_commit_window = Duration::ZERO;
    let (log, _received, _failed) = open(&env, &config).await;
    let first = log.append(record("first")).await.unwrap();
    let reader = LogReader::new(env, config.dir.clone(), config.branch.clone());
    let captured = reader.capture_readset(1, first).await.unwrap();
    let second = log.append(record("later")).await.unwrap();
    assert!(second > captured.through());
    assert!(captured.read_while_with_namespace(1, second, |_, _| Ok(true)).await.is_err());
    let path = config.dir.join(segment_name(1));
    let original = root.path().join("held-original.seg");
    std::fs::rename(&path, &original).unwrap();
    std::fs::write(&path, b"replacement is not the actual native source").unwrap();
    let mut frames = Vec::new();
    captured.read_while_with_namespace(1, first, |namespace, committed| {
        frames.push((namespace.to_owned(), committed));
        Ok(true)
    }).await.unwrap();
    assert_eq!(frames.len(), 1);
    assert_eq!(frames[0].0, config.branch);
    assert_eq!(frames[0].1.lsn, first);
    assert_eq!(frames[0].1.record, record("first"));
    assert!(reader.read_while_with_namespace(1, first, |_, _| Ok(true)).await.is_err());
    let offset = frames[0].1.pos.offset + ENVELOPE_LEN as u64;
    let file = std::fs::OpenOptions::new().read(true).write(true).open(original).unwrap();
    let mut byte = [0u8];
    file.read_exact_at(&mut byte, offset).unwrap();
    byte[0] ^= 0x80;
    file.write_all_at(&byte, offset).unwrap();
    assert!(captured.read_while_with_namespace(1, first, |_, _| Ok(true)).await.is_err());
}

#[tokio::test]
async fn held_closed_files_remain_dense_after_unlink_and_missing_live_middle_is_not_empty_success() {
    let root = tempfile::tempdir().unwrap();
    let env = Env::real(tokio::runtime::Handle::current());
    let mut config = LogConfig::new(root.path().join("log"), "native-dense");
    config.group_commit_window = Duration::ZERO;
    config.segment_max_bytes = 1;
    let (log, _received, _failed) = open(&env, &config).await;
    for index in 0..3 { log.append(record(&format!("frame-{index}"))).await.unwrap(); }
    let reader = LogReader::new(env.clone(), config.dir.clone(), config.branch.clone());
    let captured = reader.capture_readset(1, 3).await.unwrap();
    let starts = reader.starts().await.unwrap();
    assert!(starts.len() >= 3, "the real writer must have closed the source segments");
    std::fs::remove_file(config.dir.join(segment_name(starts[1]))).unwrap();
    let mut held = Vec::new();
    captured.read_while_with_namespace(1, 3, |namespace, frame| {
        assert_eq!(namespace, config.branch);
        held.push(frame.lsn);
        Ok(true)
    }).await.unwrap();
    assert_eq!(held, vec![1, 2, 3]);
    assert!(reader.read_while_with_namespace(1, 3, |_, _| Ok(true)).await.is_err());
    let foreign = LogReader::new(env, config.dir.clone(), "claimed-other-namespace");
    assert!(foreign.capture_readset(1, 3).await.is_err());
    assert!(reader.capture_readset(1, Lsn::MAX).await.is_err());
}

#[tokio::test]
async fn zero_cut_is_only_an_empty_data_view_and_never_opens_a_missing_root() {
    let root = tempfile::tempdir().unwrap();
    let env = Env::real(tokio::runtime::Handle::current());
    let reader = LogReader::new(env, root.path().join("absent-log"), "native-empty");
    let captured = reader.capture_readset(1, 0).await.unwrap();
    assert_eq!(captured.from(), 1);
    assert_eq!(captured.through(), 0);
    assert_eq!(captured.retained_from(), None);
    captured.read_while_with_namespace(1, 0, |_, _| panic!("no positive source frame exists")).await.unwrap();
}
