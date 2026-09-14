use crate::firewall::FirewallCtx;
use crate::parsers::parse_log;
use chrono::Utc;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use uip_core::types::LogType;
use uip_core::ParsedLog;

pub async fn run_udp(sock: UdpSocket, tx: mpsc::Sender<ParsedLog>, ctx: FirewallCtx) {
    let mut buf = vec![0u8; 65536];
    let mut dropped: u64 = 0;
    loop {
        let Ok((n, _peer)) = sock.recv_from(&mut buf).await else {
            continue;
        };
        let line = String::from_utf8_lossy(&buf[..n]);
        let line = line.trim_end_matches(['\r', '\n', '\0']);
        if line.is_empty() {
            continue;
        }
        let parsed = parse_log(line, Utc::now(), &ctx).unwrap_or_else(|| ParsedLog {
            log_type: Some(LogType::System),
            timestamp: Some(Utc::now()),
            raw_log: line.to_string(),
            ..Default::default()
        });
        if tx.try_send(parsed).is_err() {
            dropped += 1;
            if dropped.is_power_of_two() {
                tracing::warn!(dropped, "writer channel full, dropping log lines");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::firewall::FirewallCtx;
    use uip_core::types::LogType;

    #[tokio::test]
    async fn receives_and_parses_datagrams() {
        let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        let (tx, mut rx) = tokio::sync::mpsc::channel(16);
        tokio::spawn(run_udp(sock, tx, FirewallCtx::default()));

        let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.send_to(b"Feb  8 16:43:49 UDR dnsmasq[1]: query[A] example.com from 192.168.1.5", addr).await.unwrap();
        client.send_to(b"complete garbage", addr).await.unwrap();

        let p1 = rx.recv().await.unwrap();
        assert_eq!(p1.log_type, Some(LogType::Dns));
        let p2 = rx.recv().await.unwrap();
        assert_eq!(p2.log_type, Some(LogType::System));
        assert_eq!(p2.raw_log, "complete garbage");
    }
}
