use crate::platform::procmon::proc_net_packet::{ProcNetPacketRow, ProcNetXdpRow};
use crate::utils::hex_parse::parse_hex_token;
use crate::utils::name_parsing::normalized_name;

pub(crate) fn read_proc_net_packet_rows() -> Vec<ProcNetPacketRow> {
    use std::io::{BufRead, BufReader};
    let Ok(file) = std::fs::File::open("/proc/net/packet") else {
        return Vec::new();
    };
    let mut contents = String::new();
    for line in BufReader::new(file).lines() {
        let Ok(line) = line else { break };
        contents.push_str(&line);
        contents.push('\n');
    }
    parse_proc_net_packet_rows(&contents)
}

pub(crate) fn read_proc_net_xdp_rows() -> Vec<ProcNetXdpRow> {
    use std::io::{BufRead, BufReader};
    let Ok(file) = std::fs::File::open("/proc/net/xdp") else {
        return Vec::new();
    };
    let mut contents = String::new();
    for line in BufReader::new(file).lines() {
        let Ok(line) = line else { break };
        contents.push_str(&line);
        contents.push('\n');
    }

    let mut lines = contents.lines();
    let Some(header_line) = lines.next() else {
        return Vec::new();
    };
    let headers: Vec<String> = header_line
        .split_whitespace()
        .map(normalized_name)
        .collect();

    let idx_of = |names: &[&str]| -> Option<usize> {
        headers.iter().position(|h| names.iter().any(|n| h == n))
    };

    let inode_idx = idx_of(&["inode", "ino"]);
    let uid_idx = idx_of(&["uid"]);
    let iface_idx = idx_of(&["ifindex", "if_idx", "if"]);
    let cookie_idx = idx_of(&["cookie"]);

    let mut out = Vec::new();
    for line in lines {
        let Some(inode_pos) = inode_idx else {
            continue;
        };
        let Some(uid_pos) = uid_idx else {
            continue;
        };
        let Some(if_pos) = iface_idx else {
            continue;
        };

        let numeric = parse_u32_columns(line, &[inode_pos, uid_pos, if_pos]);
        let inode = numeric.first().and_then(|v| *v);
        let uid = numeric.get(1).and_then(|v| *v);
        let iface = numeric.get(2).and_then(|v| *v);
        let cookie = cookie_idx.and_then(|cookie_pos| line.split_whitespace().nth(cookie_pos));

        let (Some(inode), Some(uid), Some(iface)) = (inode, uid, iface) else {
            continue;
        };

        let (cookie0, cookie1) = if cookie_idx.is_some() {
            if let Some(v) = parse_hex_token::<u64>(cookie.unwrap_or("0")) {
                ((v & 0xffff_ffff) as u32, ((v >> 32) & 0xffff_ffff) as u32)
            } else {
                (0, 0)
            }
        } else {
            (0, 0)
        };

        out.push(ProcNetXdpRow {
            iface,
            uid,
            inode,
            cookie0,
            cookie1,
        });
    }

    out
}

pub(crate) fn parse_u32_columns(line: &str, indexes: &[usize]) -> Vec<Option<u32>> {
    if indexes.is_empty() {
        return Vec::new();
    }

    let mut out = vec![None; indexes.len()];
    let mut remaining = indexes.len();
    let max_idx = indexes.iter().copied().max().unwrap_or(0);

    for (idx, col) in line.split_whitespace().enumerate() {
        if idx > max_idx || remaining == 0 {
            break;
        }

        for (slot, wanted) in indexes.iter().enumerate() {
            if *wanted == idx && out[slot].is_none() {
                out[slot] = col.parse::<u32>().ok();
                remaining = remaining.saturating_sub(1);
            }
        }
    }

    out
}

pub(crate) fn parse_proc_net_packet_rows(contents: &str) -> Vec<ProcNetPacketRow> {
    let mut out = Vec::new();

    for line in contents.lines().skip(1) {
        let parsed = parse_u32_columns(line, &[4, 7, 8]);
        let iface = parsed.first().and_then(|v| *v);
        let uid = parsed.get(1).and_then(|v| *v);
        let inode = parsed.get(2).and_then(|v| *v);

        let (Some(iface), Some(uid), Some(inode)) = (iface, uid, inode) else {
            continue;
        };
        out.push(ProcNetPacketRow { iface, uid, inode });
    }

    out
}
