use super::persistence::{IndexedEvent, StoredRecord};
use super::{
    acknowledgement, persistence, record, segments, UsageAcknowledgement, UsageAppendReceipt,
    UsageCursor, UsageSpoolError, UsageSpoolOptions, UsageSpoolRecord, UsageSpoolStatus,
    MAX_RECORD_LINE_BYTES, MAX_REPLAY_BATCH_RECORDS, MAX_USAGE_EVENT_BYTES,
};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{Arc, PoisonError, RwLock, Weak};
use tokio::io::AsyncWriteExt;
use tokio::sync::{mpsc, oneshot, Mutex};
use uuid::Uuid;

#[derive(Debug)]
pub(crate) struct UsageSpool {
    core: Arc<UsageSpoolCore>,
    writer: std::sync::Mutex<Option<mpsc::UnboundedSender<WriterCommand>>>,
    writer_task: std::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
}

#[derive(Debug)]
struct UsageSpoolCore {
    gateway_id: Uuid,
    capacity_bytes: u64,
    // Keeps epoch deletion from racing byte-exact replay after offsets are selected.
    replay_guard: tokio::sync::RwLock<()>,
    inner: Mutex<UsageSpoolInner>,
    status: RwLock<UsageSpoolStatus>,
}

#[derive(Debug)]
struct UsageSpoolInner {
    _lock_file: std::fs::File,
    current_file: tokio::fs::File,
    current_path: std::path::PathBuf,
    current_offset: u64,
    boot_epoch: Uuid,
    next_sequence: u64,
    total_bytes: u64,
    directory: std::path::PathBuf,
    manifest: super::SpoolManifest,
    manifest_bytes: u64,
    epoch_bytes: HashMap<Uuid, u64>,
    reserved_bytes: u64,
    // Only unacknowledged records remain replayable.
    records: Vec<StoredRecord>,
    // All physically retained events remain indexed for append idempotence.
    events: HashMap<Uuid, IndexedEvent>,
    failure: Option<String>,
}

#[derive(Debug)]
enum WriterCommand {
    Append {
        event_id: Uuid,
        payload: Vec<u8>,
        reserved_bytes: u64,
        completion: oneshot::Sender<std::result::Result<UsageCursor, String>>,
    },
    Release {
        reserved_bytes: u64,
    },
    Shutdown {
        completion: oneshot::Sender<()>,
    },
}

#[derive(Debug)]
pub(crate) struct UsageReservation {
    writer: mpsc::UnboundedSender<WriterCommand>,
    core: Weak<UsageSpoolCore>,
    reserved_bytes: u64,
}

impl UsageReservation {
    pub(crate) fn commit(
        mut self,
        event_id: Uuid,
        payload: Vec<u8>,
    ) -> Result<UsageAppendReceipt, UsageSpoolError> {
        if event_id.is_nil() {
            return Err(UsageSpoolError::InvalidOptions {
                reason: "event_id must not be the nil UUID".to_string(),
            });
        }
        if payload.len() > MAX_USAGE_EVENT_BYTES {
            return Err(UsageSpoolError::EventTooLarge {
                actual_bytes: payload.len(),
                maximum_bytes: MAX_USAGE_EVENT_BYTES,
            });
        }
        let (completion, receiver) = oneshot::channel();
        if self
            .writer
            .send(WriterCommand::Append {
                event_id,
                payload,
                reserved_bytes: self.reserved_bytes,
                completion,
            })
            .is_err()
        {
            let reason = "usage spool writer is not running".to_string();
            let reserved_bytes = std::mem::take(&mut self.reserved_bytes);
            schedule_writer_failure(self.core.clone(), reserved_bytes, reason.clone());
            return Err(UsageSpoolError::Unavailable { reason });
        }
        self.reserved_bytes = 0;
        Ok(UsageAppendReceipt {
            completion: receiver,
        })
    }
}

impl Drop for UsageReservation {
    fn drop(&mut self) {
        if self.reserved_bytes > 0 {
            let reserved_bytes = std::mem::take(&mut self.reserved_bytes);
            if self
                .writer
                .send(WriterCommand::Release { reserved_bytes })
                .is_err()
            {
                schedule_writer_failure(
                    self.core.clone(),
                    reserved_bytes,
                    "usage spool writer stopped before releasing terminal capacity".to_string(),
                );
            }
        }
    }
}

impl UsageSpool {
    pub(crate) async fn open(options: UsageSpoolOptions) -> Result<Self, UsageSpoolError> {
        let opened = persistence::open(&options).await?;
        let status = UsageSpoolStatus {
            gateway_id: options.gateway_id,
            boot_epoch: opened.boot_epoch,
            next_sequence: opened.next_sequence,
            acknowledged_through: opened.manifest.acknowledged_through(),
            oldest_retained_cursor: opened.records.first().map(|record| record.cursor),
            retained_records: opened.records.len() as u64,
            retained_bytes: opened.total_bytes,
            reserved_bytes: 0,
            capacity_bytes: options.max_bytes,
            writable: opened.total_bytes < options.max_bytes,
            reason: None,
        };
        let core = Arc::new(UsageSpoolCore {
            gateway_id: options.gateway_id,
            capacity_bytes: options.max_bytes,
            replay_guard: tokio::sync::RwLock::new(()),
            inner: Mutex::new(UsageSpoolInner {
                _lock_file: opened.lock_file,
                current_file: opened.current_file,
                current_path: opened.current_path,
                current_offset: opened.current_offset,
                boot_epoch: opened.boot_epoch,
                next_sequence: opened.next_sequence,
                total_bytes: opened.total_bytes,
                directory: options.directory,
                manifest: opened.manifest,
                manifest_bytes: opened.manifest_bytes,
                epoch_bytes: opened.epoch_bytes,
                reserved_bytes: 0,
                records: opened.records,
                events: opened.events,
                failure: None,
            }),
            status: RwLock::new(status),
        });
        let (writer, receiver) = mpsc::unbounded_channel();
        let writer_task = tokio::spawn(run_writer(Arc::downgrade(&core), receiver));
        Ok(Self {
            core,
            writer: std::sync::Mutex::new(Some(writer)),
            writer_task: std::sync::Mutex::new(Some(writer_task)),
        })
    }

    pub(crate) fn status(&self) -> UsageSpoolStatus {
        self.core.status()
    }

    #[cfg(test)]
    pub(crate) async fn append(
        &self,
        event_id: Uuid,
        payload: &[u8],
    ) -> Result<UsageCursor, UsageSpoolError> {
        self.core.append(event_id, payload, 0).await
    }

    pub(crate) async fn append_reserving_terminal(
        &self,
        event_id: Uuid,
        payload: &[u8],
    ) -> Result<(UsageCursor, UsageReservation), UsageSpoolError> {
        let writer = self
            .writer
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .cloned()
            .ok_or_else(|| UsageSpoolError::Unavailable {
                reason: "usage spool writer is shutting down".to_string(),
            })?;
        if writer.is_closed() {
            let reason = "usage spool writer is not running".to_string();
            self.core.mark_unavailable(reason.clone()).await;
            return Err(UsageSpoolError::Unavailable { reason });
        }
        let reserved_bytes = MAX_RECORD_LINE_BYTES as u64;
        let cursor = self.core.append(event_id, payload, reserved_bytes).await?;
        Ok((
            cursor,
            UsageReservation {
                writer,
                core: Arc::downgrade(&self.core),
                reserved_bytes,
            },
        ))
    }

    #[allow(dead_code)] // Used by the pending Cloud transport adapter and production-shaped tests.
    pub(crate) async fn read_batch(
        &self,
        after: Option<UsageCursor>,
        limit: usize,
    ) -> Result<Vec<UsageSpoolRecord>, UsageSpoolError> {
        let _replay_guard = self.core.replay_guard.read().await;
        let selected = {
            let inner = self.core.inner.lock().await;
            if let Some(reason) = &inner.failure {
                return Err(UsageSpoolError::Unavailable {
                    reason: reason.clone(),
                });
            }
            let start = match after {
                None => 0,
                Some(cursor) if Some(cursor) == inner.manifest.acknowledged_through() => 0,
                Some(cursor) => inner
                    .records
                    .iter()
                    .position(|record| record.cursor == cursor)
                    .map(|index| index + 1)
                    .ok_or(UsageSpoolError::CursorGap {
                        boot_epoch: cursor.boot_epoch,
                        sequence: cursor.sequence,
                    })?,
            };
            inner
                .records
                .iter()
                .skip(start)
                .take(limit.min(MAX_REPLAY_BATCH_RECORDS))
                .cloned()
                .collect::<Vec<_>>()
        };

        record::read_batch(&selected, self.core.gateway_id).await
    }

    #[allow(dead_code)] // Used by the pending Cloud transport adapter and production-shaped tests.
    pub(crate) async fn acknowledge(
        &self,
        cursor: UsageCursor,
    ) -> Result<UsageAcknowledgement, UsageSpoolError> {
        self.core.acknowledge(cursor).await
    }

    pub(crate) async fn shutdown(&self) {
        let sender = self
            .writer
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        if let Some(sender) = sender {
            let (completion, receiver) = oneshot::channel();
            let _ = sender.send(WriterCommand::Shutdown { completion });
            let _ = receiver.await;
        }
        let task = self
            .writer_task
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        if let Some(task) = task {
            let _ = task.await;
        }
    }
}

impl Drop for UsageSpool {
    fn drop(&mut self) {
        self.writer
            .get_mut()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        if let Some(task) = self
            .writer_task
            .get_mut()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
        {
            task.abort();
        }
    }
}

impl UsageSpoolCore {
    fn status(&self) -> UsageSpoolStatus {
        self.status
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    async fn acknowledge(
        &self,
        cursor: UsageCursor,
    ) -> Result<UsageAcknowledgement, UsageSpoolError> {
        if cursor.boot_epoch.is_nil() || cursor.sequence == 0 || cursor.sequence == u64::MAX {
            return Err(UsageSpoolError::CursorGap {
                boot_epoch: cursor.boot_epoch,
                sequence: cursor.sequence,
            });
        }

        let _replay_guard = self.replay_guard.write().await;
        let mut inner = self.inner.lock().await;
        self.ensure_available(&inner)?;
        if inner.manifest.acknowledged_through() == Some(cursor) {
            return Ok(UsageAcknowledgement {
                acknowledged_through: cursor,
                newly_acknowledged_records: 0,
                reclaimed_bytes: 0,
                cleanup_pending: false,
            });
        }

        let position = inner
            .records
            .iter()
            .position(|record| record.cursor == cursor)
            .ok_or(UsageSpoolError::CursorGap {
                boot_epoch: cursor.boot_epoch,
                sequence: cursor.sequence,
            })?;
        let epoch_position = inner
            .manifest
            .epochs
            .iter()
            .position(|epoch| epoch.boot_epoch == cursor.boot_epoch)
            .ok_or_else(|| {
                UsageSpoolError::corrupt(format!(
                    "retained cursor {}/{} has no manifest epoch",
                    cursor.boot_epoch, cursor.sequence
                ))
            })?;
        let mut retiring_epochs = inner.manifest.epochs[..epoch_position]
            .iter()
            .filter_map(|epoch| (epoch.boot_epoch != inner.boot_epoch).then_some(epoch.boot_epoch))
            .collect::<std::collections::HashSet<_>>();
        let cursor_finishes_epoch = !inner.records[position + 1..]
            .iter()
            .any(|record| record.cursor.boot_epoch == cursor.boot_epoch);
        if cursor_finishes_epoch && cursor.boot_epoch != inner.boot_epoch {
            retiring_epochs.insert(cursor.boot_epoch);
        }
        let first_retained = if !cursor_finishes_epoch && cursor.boot_epoch != inner.boot_epoch {
            let record = inner.records.get(position + 1).cloned().ok_or_else(|| {
                UsageSpoolError::corrupt(format!(
                    "partial acknowledgement of epoch {} has no retained successor",
                    cursor.boot_epoch
                ))
            })?;
            if record.cursor.boot_epoch != cursor.boot_epoch {
                return Err(UsageSpoolError::corrupt(format!(
                    "partial acknowledgement of epoch {} crosses an epoch boundary",
                    cursor.boot_epoch
                )));
            }
            Some(record)
        } else {
            None
        };

        let persisted = match acknowledgement::persist(
            &inner.directory,
            self.gateway_id,
            &inner.manifest,
            cursor,
            &retiring_epochs,
            first_retained.as_ref(),
        )
        .await
        {
            Ok(persisted) => persisted,
            Err(error) => {
                self.mark_failed(
                    &mut inner,
                    format!(
                        "usage acknowledgement did not reach a confirmed runtime state; restart is required: {error}"
                    ),
                );
                return Err(error);
            }
        };

        let previous_total_bytes = inner.total_bytes;
        let newly_acknowledged_records = (position + 1) as u64;
        inner.records.drain(..=position);
        let mut cleanup_error = persisted.cleanup_error;
        let mut reclaimed_bytes = 0;
        if cleanup_error.is_none() && !persisted.compacted_epochs.is_empty() {
            match segments::scan(&inner.directory, &persisted.manifest, self.gateway_id).await {
                Ok((records, events, segment_bytes, epoch_bytes, _)) => {
                    inner.records = records;
                    inner.events = events;
                    inner.epoch_bytes = epoch_bytes;
                    match segment_bytes.checked_add(persisted.manifest_bytes) {
                        Some(total_bytes) => {
                            reclaimed_bytes = previous_total_bytes.saturating_sub(total_bytes);
                            inner.total_bytes = total_bytes;
                        }
                        None => {
                            cleanup_error = Some(
                                "usage acknowledgement committed but byte accounting became inconsistent; restart is required"
                                    .to_string(),
                            );
                        }
                    }
                }
                Err(error) => {
                    cleanup_error = Some(format!(
                        "usage acknowledgement is durable but compacted epoch reindexing requires restart: {error}"
                    ));
                }
            }
        } else {
            let removed_segment_bytes = persisted
                .removed_epochs
                .iter()
                .filter_map(|boot_epoch| inner.epoch_bytes.remove(boot_epoch))
                .fold(0_u64, u64::saturating_add);
            inner
                .events
                .retain(|_, event| !persisted.removed_epochs.contains(&event.cursor.boot_epoch));

            let total_bytes = inner
                .total_bytes
                .checked_sub(inner.manifest_bytes)
                .and_then(|bytes| bytes.checked_sub(removed_segment_bytes))
                .and_then(|bytes| bytes.checked_add(persisted.manifest_bytes));
            reclaimed_bytes = total_bytes
                .map(|total_bytes| previous_total_bytes.saturating_sub(total_bytes))
                .unwrap_or(removed_segment_bytes);
            match total_bytes {
                Some(total_bytes) => inner.total_bytes = total_bytes,
                None if cleanup_error.is_none() => {
                    cleanup_error = Some(
                        "usage acknowledgement committed but byte accounting became inconsistent; restart is required"
                            .to_string(),
                    );
                }
                None => {}
            }
        }
        inner.manifest = persisted.manifest;
        inner.manifest_bytes = persisted.manifest_bytes;

        let cleanup_pending = cleanup_error.is_some();
        match cleanup_error {
            Some(reason) => self.mark_failed(&mut inner, reason),
            None => self.update_status(&inner, None),
        }

        Ok(UsageAcknowledgement {
            acknowledged_through: cursor,
            newly_acknowledged_records,
            reclaimed_bytes,
            cleanup_pending,
        })
    }

    async fn append(
        &self,
        event_id: Uuid,
        payload: &[u8],
        reserve_bytes: u64,
    ) -> Result<UsageCursor, UsageSpoolError> {
        if event_id.is_nil() {
            return Err(UsageSpoolError::InvalidOptions {
                reason: "event_id must not be the nil UUID".to_string(),
            });
        }
        if payload.len() > MAX_USAGE_EVENT_BYTES {
            return Err(UsageSpoolError::EventTooLarge {
                actual_bytes: payload.len(),
                maximum_bytes: MAX_USAGE_EVENT_BYTES,
            });
        }
        let digest: [u8; 32] = Sha256::digest(payload).into();
        let mut inner = self.inner.lock().await;
        self.ensure_available(&inner)?;
        if let Some(existing) = inner.events.get(&event_id).cloned() {
            if existing.payload_sha256 != digest {
                return Err(UsageSpoolError::EventConflict { event_id });
            }
            if reserve_bytes > 0 {
                self.reserve(&mut inner, reserve_bytes)?;
            }
            return Ok(existing.cursor);
        }

        let cursor = UsageCursor {
            boot_epoch: inner.boot_epoch,
            sequence: inner.next_sequence,
        };
        if cursor.sequence == u64::MAX {
            let reason = "usage sequence exhausted".to_string();
            self.mark_failed(&mut inner, reason.clone());
            return Err(UsageSpoolError::Unavailable { reason });
        }
        let (bytes, payload_sha256) = record::encode(self.gateway_id, cursor, event_id, payload)?;
        let requested_bytes = (bytes.len() as u64).saturating_add(reserve_bytes);
        self.ensure_capacity(&mut inner, requested_bytes)?;

        let offset = inner.current_offset;
        if let Err(error) = inner.current_file.write_all(&bytes).await {
            let error = UsageSpoolError::io("append epoch record", &inner.current_path, error);
            self.mark_failed(&mut inner, error.to_string());
            return Err(error);
        }
        if let Err(error) = inner.current_file.sync_data().await {
            let error = UsageSpoolError::io("sync epoch record", &inner.current_path, error);
            self.mark_failed(&mut inner, error.to_string());
            return Err(error);
        }

        inner.current_offset += bytes.len() as u64;
        inner.total_bytes += bytes.len() as u64;
        let boot_epoch = inner.boot_epoch;
        *inner.epoch_bytes.entry(boot_epoch).or_default() += bytes.len() as u64;
        inner.reserved_bytes += reserve_bytes;
        inner.next_sequence += 1;
        let stored = StoredRecord::new(
            cursor,
            event_id,
            payload_sha256,
            &inner.current_path,
            offset,
            bytes.len(),
        );
        inner.records.push(stored);
        inner.events.insert(
            event_id,
            IndexedEvent {
                cursor,
                payload_sha256,
            },
        );
        self.update_status(&inner, None);
        Ok(cursor)
    }

    async fn append_reserved(
        &self,
        event_id: Uuid,
        payload: &[u8],
        reserved_bytes: u64,
    ) -> Result<UsageCursor, UsageSpoolError> {
        let digest: [u8; 32] = Sha256::digest(payload).into();
        let mut inner = self.inner.lock().await;
        self.ensure_available(&inner)?;
        if reserved_bytes > inner.reserved_bytes {
            let reason = "usage terminal reservation accounting underflow".to_string();
            self.mark_failed(&mut inner, reason.clone());
            return Err(UsageSpoolError::Unavailable { reason });
        }
        if let Some(existing) = inner.events.get(&event_id).cloned() {
            inner.reserved_bytes -= reserved_bytes;
            self.update_status(&inner, None);
            return if existing.payload_sha256 == digest {
                Ok(existing.cursor)
            } else {
                Err(UsageSpoolError::EventConflict { event_id })
            };
        }
        let cursor = UsageCursor {
            boot_epoch: inner.boot_epoch,
            sequence: inner.next_sequence,
        };
        if cursor.sequence == u64::MAX {
            let reason = "usage sequence exhausted".to_string();
            self.mark_failed(&mut inner, reason.clone());
            return Err(UsageSpoolError::Unavailable { reason });
        }
        let (bytes, payload_sha256) = record::encode(self.gateway_id, cursor, event_id, payload)?;
        if bytes.len() as u64 > reserved_bytes {
            let reason = format!(
                "usage terminal record requires {} bytes but reserved {} bytes",
                bytes.len(),
                reserved_bytes
            );
            self.mark_failed(&mut inner, reason.clone());
            return Err(UsageSpoolError::Unavailable { reason });
        }

        let offset = inner.current_offset;
        if let Err(error) = inner.current_file.write_all(&bytes).await {
            let error = UsageSpoolError::io("append reserved record", &inner.current_path, error);
            self.mark_failed(&mut inner, error.to_string());
            return Err(error);
        }
        if let Err(error) = inner.current_file.sync_data().await {
            let error = UsageSpoolError::io("sync reserved record", &inner.current_path, error);
            self.mark_failed(&mut inner, error.to_string());
            return Err(error);
        }

        inner.reserved_bytes -= reserved_bytes;
        inner.current_offset += bytes.len() as u64;
        inner.total_bytes += bytes.len() as u64;
        let boot_epoch = inner.boot_epoch;
        *inner.epoch_bytes.entry(boot_epoch).or_default() += bytes.len() as u64;
        inner.next_sequence += 1;
        let stored = StoredRecord::new(
            cursor,
            event_id,
            payload_sha256,
            &inner.current_path,
            offset,
            bytes.len(),
        );
        inner.records.push(stored);
        inner.events.insert(
            event_id,
            IndexedEvent {
                cursor,
                payload_sha256,
            },
        );
        self.update_status(&inner, None);
        Ok(cursor)
    }

    async fn release(&self, reserved_bytes: u64) {
        let mut inner = self.inner.lock().await;
        if reserved_bytes > inner.reserved_bytes {
            let reason = "usage terminal reservation accounting underflow".to_string();
            self.mark_failed(&mut inner, reason);
            return;
        }
        inner.reserved_bytes -= reserved_bytes;
        self.update_status(&inner, inner.failure.clone());
    }

    async fn mark_unavailable(&self, reason: String) {
        let mut inner = self.inner.lock().await;
        self.mark_failed(&mut inner, reason);
    }

    async fn fail_reservation(&self, reserved_bytes: u64, reason: String) {
        let mut inner = self.inner.lock().await;
        if reserved_bytes > inner.reserved_bytes {
            self.mark_failed(
                &mut inner,
                "usage terminal reservation accounting underflow".to_string(),
            );
            return;
        }
        inner.reserved_bytes -= reserved_bytes;
        self.mark_failed(&mut inner, reason);
    }

    fn reserve(
        &self,
        inner: &mut UsageSpoolInner,
        reserve_bytes: u64,
    ) -> Result<(), UsageSpoolError> {
        self.ensure_capacity(inner, reserve_bytes)?;
        inner.reserved_bytes += reserve_bytes;
        self.update_status(inner, None);
        Ok(())
    }

    fn ensure_available(&self, inner: &UsageSpoolInner) -> Result<(), UsageSpoolError> {
        match &inner.failure {
            Some(reason) => Err(UsageSpoolError::Unavailable {
                reason: reason.clone(),
            }),
            None => Ok(()),
        }
    }

    fn ensure_capacity(
        &self,
        inner: &mut UsageSpoolInner,
        requested_bytes: u64,
    ) -> Result<(), UsageSpoolError> {
        let retained_and_reserved = inner.total_bytes.saturating_add(inner.reserved_bytes);
        if retained_and_reserved.saturating_add(requested_bytes) <= self.capacity_bytes {
            return Ok(());
        }
        let reason = format!(
            "{} retained/reserved bytes plus {} requested bytes exceed {} bytes",
            retained_and_reserved, requested_bytes, self.capacity_bytes
        );
        self.update_status(inner, Some(reason));
        Err(UsageSpoolError::Full {
            retained_bytes: retained_and_reserved,
            requested_bytes,
            capacity_bytes: self.capacity_bytes,
        })
    }

    fn mark_failed(&self, inner: &mut UsageSpoolInner, reason: String) {
        inner.failure = Some(reason.clone());
        self.update_status(inner, Some(reason));
    }

    fn update_status(&self, inner: &UsageSpoolInner, reason: Option<String>) {
        let occupied = inner.total_bytes.saturating_add(inner.reserved_bytes);
        *self.status.write().unwrap_or_else(PoisonError::into_inner) = UsageSpoolStatus {
            gateway_id: self.gateway_id,
            boot_epoch: inner.boot_epoch,
            next_sequence: inner.next_sequence,
            acknowledged_through: inner.manifest.acknowledged_through(),
            oldest_retained_cursor: inner.records.first().map(|record| record.cursor),
            retained_records: inner.records.len() as u64,
            retained_bytes: inner.total_bytes,
            reserved_bytes: inner.reserved_bytes,
            capacity_bytes: self.capacity_bytes,
            writable: inner.failure.is_none() && occupied < self.capacity_bytes,
            reason,
        };
    }
}

async fn run_writer(
    core: Weak<UsageSpoolCore>,
    mut receiver: mpsc::UnboundedReceiver<WriterCommand>,
) {
    while let Some(command) = receiver.recv().await {
        match command {
            WriterCommand::Append {
                event_id,
                payload,
                reserved_bytes,
                completion,
            } => {
                let result = match core.upgrade() {
                    Some(core) => core
                        .append_reserved(event_id, &payload, reserved_bytes)
                        .await
                        .map_err(|error| error.to_string()),
                    None => Err("usage spool was dropped".to_string()),
                };
                let _ = completion.send(result);
            }
            WriterCommand::Release { reserved_bytes } => {
                if let Some(core) = core.upgrade() {
                    core.release(reserved_bytes).await;
                }
            }
            WriterCommand::Shutdown { completion } => {
                let _ = completion.send(());
                return;
            }
        }
    }
}

fn schedule_writer_failure(core: Weak<UsageSpoolCore>, reserved_bytes: u64, reason: String) {
    let Some(core) = core.upgrade() else {
        return;
    };
    if let Ok(runtime) = tokio::runtime::Handle::try_current() {
        runtime.spawn(async move {
            core.fail_reservation(reserved_bytes, reason).await;
        });
    }
}
