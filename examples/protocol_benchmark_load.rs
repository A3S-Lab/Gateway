//! Same-host WebSocket, TCP, and UDP round-trip load generator.

use clap::{Parser, ValueEnum};
use futures_util::{SinkExt, StreamExt};
use serde::Serialize;
use std::error::Error;
use std::path::PathBuf;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::{mpsc, watch};
use tokio::time::Instant;
use tokio_tungstenite::tungstenite::Message;

type BoxError = Box<dyn Error + Send + Sync>;

#[derive(Debug, Clone, Copy, ValueEnum)]
enum Protocol {
    Websocket,
    Tcp,
    Udp,
}

#[derive(Debug, Parser)]
struct Args {
    #[arg(long, value_enum)]
    protocol: Protocol,
    #[arg(long)]
    target: String,
    #[arg(long, default_value_t = 64)]
    connections: usize,
    #[arg(long, default_value_t = 10)]
    duration_seconds: u64,
    #[arg(long, default_value_t = 32)]
    payload_bytes: usize,
    #[arg(long)]
    output: PathBuf,
}

#[derive(Debug, Serialize)]
struct Metrics {
    schema_version: u8,
    success_rate: f64,
    operations: usize,
    operations_per_second: f64,
    average_latency_us: f64,
    p50_latency_us: f64,
    p90_latency_us: f64,
    p99_latency_us: f64,
}

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    let args = Args::parse();
    if args.connections == 0 || args.duration_seconds == 0 || args.payload_bytes == 0 {
        return Err("connections, duration, and payload size must be positive".into());
    }

    let payload = vec![b'a'; args.payload_bytes];
    let (ready_tx, mut ready_rx) = mpsc::channel(args.connections);
    let (start_tx, start_rx) = watch::channel(None::<Instant>);
    let mut workers = Vec::with_capacity(args.connections);
    let protocol = args.protocol;

    for _ in 0..args.connections {
        let ready = ready_tx.clone();
        let start = start_rx.clone();
        let target = args.target.clone();
        let worker_payload = payload.clone();
        workers.push(tokio::spawn(async move {
            match protocol {
                Protocol::Websocket => websocket_worker(target, worker_payload, ready, start).await,
                Protocol::Tcp => tcp_worker(target, worker_payload, ready, start).await,
                Protocol::Udp => udp_worker(target, worker_payload, ready, start).await,
            }
        }));
    }
    drop(ready_tx);

    for _ in 0..args.connections {
        ready_rx
            .recv()
            .await
            .ok_or("a load worker failed before it became ready")?;
    }
    let deadline = Instant::now() + Duration::from_secs(args.duration_seconds);
    start_tx.send(Some(deadline))?;

    let mut latencies = Vec::new();
    for worker in workers {
        latencies.extend(worker.await??);
    }
    if latencies.is_empty() {
        return Err("the load run completed without an operation".into());
    }

    let metrics = summarize(latencies, args.duration_seconds);
    if let Some(parent) = args.output.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&args.output, serde_json::to_vec_pretty(&metrics)?)?;
    println!("{}", serde_json::to_string(&metrics)?);
    Ok(())
}

async fn wait_for_start(start: &mut watch::Receiver<Option<Instant>>) -> Result<Instant, BoxError> {
    start.changed().await?;
    start
        .borrow()
        .ok_or_else(|| "load start was not published".into())
}

async fn websocket_worker(
    target: String,
    payload: Vec<u8>,
    ready: mpsc::Sender<()>,
    mut start: watch::Receiver<Option<Instant>>,
) -> Result<Vec<u64>, BoxError> {
    let (mut socket, _) = tokio_tungstenite::connect_async(target).await?;
    ready.send(()).await?;
    let deadline = wait_for_start(&mut start).await?;
    let mut latencies = Vec::new();
    while Instant::now() < deadline {
        let operation_start = std::time::Instant::now();
        socket.send(Message::Binary(payload.clone())).await?;
        let response = socket
            .next()
            .await
            .ok_or("WebSocket closed during load")??;
        if response.into_data() != payload {
            return Err("WebSocket echo payload did not match".into());
        }
        latencies.push(elapsed_microseconds(operation_start));
    }
    Ok(latencies)
}

async fn tcp_worker(
    target: String,
    payload: Vec<u8>,
    ready: mpsc::Sender<()>,
    mut start: watch::Receiver<Option<Instant>>,
) -> Result<Vec<u64>, BoxError> {
    let mut stream = TcpStream::connect(target).await?;
    let mut response = vec![0_u8; payload.len()];
    ready.send(()).await?;
    let deadline = wait_for_start(&mut start).await?;
    let mut latencies = Vec::new();
    while Instant::now() < deadline {
        let operation_start = std::time::Instant::now();
        stream.write_all(&payload).await?;
        stream.read_exact(&mut response).await?;
        if response != payload {
            return Err("TCP echo payload did not match".into());
        }
        latencies.push(elapsed_microseconds(operation_start));
    }
    Ok(latencies)
}

async fn udp_worker(
    target: String,
    payload: Vec<u8>,
    ready: mpsc::Sender<()>,
    mut start: watch::Receiver<Option<Instant>>,
) -> Result<Vec<u64>, BoxError> {
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    socket.connect(target).await?;
    let mut response = vec![0_u8; payload.len()];
    ready.send(()).await?;
    let deadline = wait_for_start(&mut start).await?;
    let mut latencies = Vec::new();
    while Instant::now() < deadline {
        let operation_start = std::time::Instant::now();
        socket.send(&payload).await?;
        let length = socket.recv(&mut response).await?;
        if length != payload.len() || response != payload {
            return Err("UDP echo payload did not match".into());
        }
        latencies.push(elapsed_microseconds(operation_start));
    }
    Ok(latencies)
}

fn elapsed_microseconds(start: std::time::Instant) -> u64 {
    u64::try_from(start.elapsed().as_micros())
        .unwrap_or(u64::MAX)
        .max(1)
}

fn summarize(mut latencies: Vec<u64>, duration_seconds: u64) -> Metrics {
    latencies.sort_unstable();
    let operations = latencies.len();
    let average = latencies.iter().map(|value| *value as f64).sum::<f64>() / operations as f64;
    Metrics {
        schema_version: 1,
        success_rate: 1.0,
        operations,
        operations_per_second: operations as f64 / duration_seconds as f64,
        average_latency_us: average,
        p50_latency_us: percentile(&latencies, 0.50),
        p90_latency_us: percentile(&latencies, 0.90),
        p99_latency_us: percentile(&latencies, 0.99),
    }
}

fn percentile(values: &[u64], quantile: f64) -> f64 {
    let rank = (values.len() as f64 * quantile).ceil() as usize;
    let index = rank.saturating_sub(1).min(values.len() - 1);
    values[index] as f64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summary_uses_sorted_latency_percentiles() {
        let metrics = summarize((1..=100).rev().collect(), 2);
        assert_eq!(metrics.operations, 100);
        assert_eq!(metrics.operations_per_second, 50.0);
        assert_eq!(metrics.p50_latency_us, 50.0);
        assert_eq!(metrics.p90_latency_us, 90.0);
        assert_eq!(metrics.p99_latency_us, 99.0);
    }
}
