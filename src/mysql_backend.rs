use byteorder::{LittleEndian, ByteOrder};
use eyre::{eyre, Result};
use tokio::io::{self, AsyncReadExt, AsyncWriteExt, split};
use tokio::net::TcpStream;
use tracing::{debug, info};

use crate::backend_config::{get_rds_password, BackendConfig, DbSpec};

// MySQL capability flags
const CLIENT_LONG_PASSWORD: u32 = 1;
const CLIENT_FOUND_ROWS: u32 = 1 << 1;
const CLIENT_LONG_FLAG: u32 = 1 << 2;
const CLIENT_CONNECT_WITH_DB: u32 = 1 << 3;
const CLIENT_PROTOCOL_41: u32 = 1 << 9;
const CLIENT_SSL: u32 = 1 << 11;
const CLIENT_SECURE_CONNECTION: u32 = 1 << 15;
const CLIENT_PLUGIN_AUTH: u32 = 1 << 19;
const CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA: u32 = 1 << 21;

// Packet markers
const OK_MARKER: u8 = 0x00;
const ERR_MARKER: u8 = 0xFF;
const AUTH_SWITCH_MARKER: u8 = 0xFE;

// Server status
const SERVER_STATUS_AUTOCOMMIT: u16 = 0x0002;

// --- Low-level MySQL packet I/O ---

async fn read_packet<S: AsyncReadExt + Unpin>(stream: &mut S) -> Result<(u8, Vec<u8>)> {
    let mut header = [0u8; 4];
    stream.read_exact(&mut header).await?;
    let len = header[0] as usize | (header[1] as usize) << 8 | (header[2] as usize) << 16;
    let seq = header[3];
    let mut payload = vec![0u8; len];
    stream.read_exact(&mut payload).await?;
    Ok((seq, payload))
}

async fn write_packet<S: AsyncWriteExt + Unpin>(
    stream: &mut S,
    seq: u8,
    payload: &[u8],
) -> Result<()> {
    let len = payload.len();
    let header = [
        (len & 0xFF) as u8,
        ((len >> 8) & 0xFF) as u8,
        ((len >> 16) & 0xFF) as u8,
        seq,
    ];
    stream.write_all(&header).await?;
    stream.write_all(payload).await?;
    stream.flush().await?;
    Ok(())
}

// --- Length-encoded integer helpers ---

fn read_lenenc_int(data: &[u8]) -> Result<(usize, usize)> {
    if data.is_empty() {
        return Err(eyre!("Empty data for lenenc int"));
    }
    match data[0] {
        0..=250 => Ok((data[0] as usize, 1)),
        0xFC => {
            if data.len() < 3 {
                return Err(eyre!("Truncated lenenc int"));
            }
            Ok((LittleEndian::read_u16(&data[1..3]) as usize, 3))
        }
        0xFD => {
            if data.len() < 4 {
                return Err(eyre!("Truncated lenenc int"));
            }
            let v = data[1] as usize | (data[2] as usize) << 8 | (data[3] as usize) << 16;
            Ok((v, 4))
        }
        0xFE => {
            if data.len() < 9 {
                return Err(eyre!("Truncated lenenc int"));
            }
            Ok((LittleEndian::read_u64(&data[1..9]) as usize, 9))
        }
        _ => Err(eyre!("Invalid lenenc int prefix: 0x{:02x}", data[0])),
    }
}

fn write_lenenc_int(buf: &mut Vec<u8>, val: usize) {
    if val < 251 {
        buf.push(val as u8);
    } else if val < 65536 {
        buf.push(0xFC);
        buf.extend_from_slice(&(val as u16).to_le_bytes());
    } else if val < 16777216 {
        buf.push(0xFD);
        buf.push((val & 0xFF) as u8);
        buf.push(((val >> 8) & 0xFF) as u8);
        buf.push(((val >> 16) & 0xFF) as u8);
    } else {
        buf.push(0xFE);
        buf.extend_from_slice(&(val as u64).to_le_bytes());
    }
}

// --- Packet builders ---

/// Build a fake HandshakeV10 to send to the connecting client.
/// The proxy does not validate client credentials — it only extracts user/database.
fn build_handshake_v10() -> Vec<u8> {
    let caps: u32 = CLIENT_LONG_PASSWORD
        | CLIENT_FOUND_ROWS
        | CLIENT_LONG_FLAG
        | CLIENT_CONNECT_WITH_DB
        | CLIENT_PROTOCOL_41
        | CLIENT_SECURE_CONNECTION
        | CLIENT_PLUGIN_AUTH;

    let mut buf = Vec::with_capacity(128);

    // protocol version
    buf.push(10);
    // server version (NUL-terminated)
    buf.extend_from_slice(b"8.0.35-rds-iam-proxy\0");
    // connection id
    buf.extend_from_slice(&1u32.to_le_bytes());
    // auth-plugin-data part 1 (8 bytes, fixed — proxy ignores client auth)
    buf.extend_from_slice(&[0x3a, 0x5c, 0x7e, 0x12, 0x45, 0x67, 0x89, 0xab]);
    // filler
    buf.push(0x00);
    // capability flags lower 2 bytes
    buf.extend_from_slice(&(caps as u16).to_le_bytes());
    // character set: utf8mb4_general_ci = 45
    buf.push(45);
    // status flags
    buf.extend_from_slice(&SERVER_STATUS_AUTOCOMMIT.to_le_bytes());
    // capability flags upper 2 bytes
    buf.extend_from_slice(&((caps >> 16) as u16).to_le_bytes());
    // auth-plugin-data length (21 = 8 + 13)
    buf.push(21);
    // reserved (10 bytes)
    buf.extend_from_slice(&[0u8; 10]);
    // auth-plugin-data part 2 (12 random-ish bytes + trailing NUL = 13)
    buf.extend_from_slice(&[
        0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x00,
    ]);
    // auth plugin name (NUL-terminated)
    buf.extend_from_slice(b"mysql_native_password\0");

    buf
}

fn build_ok_packet() -> Vec<u8> {
    vec![
        OK_MARKER,                                        // header
        0x00,                                              // affected_rows (lenenc 0)
        0x00,                                              // last_insert_id (lenenc 0)
        (SERVER_STATUS_AUTOCOMMIT & 0xFF) as u8,           // status lo
        (SERVER_STATUS_AUTOCOMMIT >> 8) as u8,             // status hi
        0x00, 0x00,                                        // warnings
    ]
}

fn build_err_packet(code: u16, state: &str, msg: &str) -> Vec<u8> {
    let mut buf = Vec::with_capacity(16 + msg.len());
    buf.push(ERR_MARKER);
    buf.extend_from_slice(&code.to_le_bytes());
    buf.push(b'#');
    buf.extend_from_slice(&state.as_bytes()[..5]); // exactly 5 chars
    buf.extend_from_slice(msg.as_bytes());
    buf
}

/// Compute the client capability flags to use for both SSLRequest and HandshakeResponse.
/// They must be consistent — SSLRequest is the first 32 bytes of the HandshakeResponse.
/// We only advertise capabilities we actually implement; blindly echoing all server caps
/// would require sending data (e.g. connect_attrs) that we don't produce.
fn compute_client_caps(server_caps: u32, has_db: bool) -> u32 {
    let mut caps = CLIENT_LONG_PASSWORD
        | CLIENT_FOUND_ROWS
        | CLIENT_LONG_FLAG
        | CLIENT_PROTOCOL_41
        | CLIENT_SSL
        | CLIENT_SECURE_CONNECTION
        | CLIENT_PLUGIN_AUTH;

    if has_db {
        caps |= CLIENT_CONNECT_WITH_DB;
    }

    // Only advertise lenenc if the server supports it
    if server_caps & CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA != 0 {
        caps |= CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA;
    }

    // Only keep capabilities the server actually supports
    caps & server_caps
}

/// Build the SSLRequest packet payload (exactly 32 bytes).
fn build_ssl_request(client_caps: u32) -> Vec<u8> {
    let mut buf = Vec::with_capacity(32);
    buf.extend_from_slice(&client_caps.to_le_bytes());
    buf.extend_from_slice(&(16u32 << 20).to_le_bytes()); // max packet 16 MB
    buf.push(45); // utf8mb4
    buf.extend_from_slice(&[0u8; 23]);
    buf
}

/// Build HandshakeResponse41 with mysql_clear_password plugin and IAM token.
fn build_handshake_response(
    client_caps: u32,
    user: &str,
    password: &str,
    database: &str,
) -> Vec<u8> {
    let use_lenenc = client_caps & CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA != 0;
    let has_db = !database.is_empty();

    let mut buf = Vec::with_capacity(256 + password.len());

    buf.extend_from_slice(&client_caps.to_le_bytes());
    buf.extend_from_slice(&(16u32 << 20).to_le_bytes()); // max packet 16 MB
    buf.push(45); // utf8mb4
    buf.extend_from_slice(&[0u8; 23]);

    // username (NUL-terminated)
    buf.extend_from_slice(user.as_bytes());
    buf.push(0x00);

    // auth response
    if use_lenenc {
        // mysql_clear_password: password bytes + NUL terminator
        let auth_data: Vec<u8> = [password.as_bytes(), &[0x00]].concat();
        write_lenenc_int(&mut buf, auth_data.len());
        buf.extend_from_slice(&auth_data);
    } else {
        // Can't fit IAM token in 1-byte length; send empty and rely on AuthSwitchRequest
        buf.push(0);
    }

    // database (NUL-terminated)
    if has_db {
        buf.extend_from_slice(database.as_bytes());
        buf.push(0x00);
    }

    // auth plugin name (NUL-terminated)
    if use_lenenc {
        buf.extend_from_slice(b"mysql_clear_password\0");
    } else {
        buf.extend_from_slice(b"mysql_native_password\0");
    }

    buf
}

// --- Protocol parsing ---

/// Extract server capabilities from a HandshakeV10 payload.
fn parse_server_handshake(payload: &[u8]) -> Result<u32> {
    if payload.is_empty() || payload[0] != 10 {
        return Err(eyre!(
            "Invalid MySQL handshake: protocol version {}",
            payload.first().unwrap_or(&0)
        ));
    }
    let mut pos = 1;

    // skip server version (NUL-terminated)
    let nul = payload[pos..]
        .iter()
        .position(|&b| b == 0)
        .ok_or_else(|| eyre!("Missing NUL in server version"))?;
    pos += nul + 1;

    // skip connection id (4), auth-plugin-data part 1 (8), filler (1) = 13
    pos += 13;

    if pos + 2 > payload.len() {
        return Err(eyre!("Handshake too short for capabilities"));
    }
    let caps_low = LittleEndian::read_u16(&payload[pos..pos + 2]) as u32;
    pos += 2;

    // skip character_set (1), status_flags (2) = 3
    pos += 3;

    if pos + 2 > payload.len() {
        return Err(eyre!("Handshake too short for upper capabilities"));
    }
    let caps_high = LittleEndian::read_u16(&payload[pos..pos + 2]) as u32;

    Ok(caps_low | (caps_high << 16))
}

/// Extract user and database from the client's HandshakeResponse41 payload.
fn parse_client_handshake(payload: &[u8]) -> Result<DbSpec> {
    if payload.len() < 32 {
        return Err(eyre!("HandshakeResponse too short"));
    }
    let caps = LittleEndian::read_u32(&payload[0..4]);

    // capabilities(4) + max_packet(4) + charset(1) + reserved(23) = 32
    let mut pos = 32;

    // username (NUL-terminated)
    let user_end = payload[pos..]
        .iter()
        .position(|&b| b == 0)
        .ok_or_else(|| eyre!("Missing NUL for username"))?;
    let user = std::str::from_utf8(&payload[pos..pos + user_end])?.to_owned();
    pos += user_end + 1;

    // skip auth response
    if caps & CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA != 0 {
        let (auth_len, hdr_bytes) = read_lenenc_int(&payload[pos..])?;
        pos += hdr_bytes + auth_len;
    } else if caps & CLIENT_SECURE_CONNECTION != 0 {
        if pos >= payload.len() {
            return Err(eyre!("Truncated auth response"));
        }
        let auth_len = payload[pos] as usize;
        pos += 1 + auth_len;
    } else {
        let end = payload[pos..]
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(0);
        pos += end + 1;
    }

    // database (NUL-terminated) if CLIENT_CONNECT_WITH_DB
    let database = if caps & CLIENT_CONNECT_WITH_DB != 0 && pos < payload.len() {
        let db_end = payload[pos..]
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(payload.len() - pos);
        std::str::from_utf8(&payload[pos..pos + db_end])?.to_owned()
    } else {
        String::new()
    };

    debug!("MySQL client: user={}, database={}", user, database);
    Ok(DbSpec::new(user, database))
}

fn parse_err_message(payload: &[u8]) -> String {
    if payload.len() < 4 {
        return "Unknown error".into();
    }
    let code = LittleEndian::read_u16(&payload[1..3]);
    let msg_start = if payload.len() > 9 && payload[3] == b'#' {
        9
    } else {
        3
    };
    let msg = std::str::from_utf8(&payload[msg_start..]).unwrap_or("(invalid utf8)");
    format!("Error {}: {}", code, msg)
}

// --- Backend connection (proxy → RDS MySQL) ---

async fn connect_backend(
    config: &BackendConfig,
    db_spec: &DbSpec,
) -> Result<tokio_native_tls::TlsStream<TcpStream>> {
    let password = get_rds_password(
        config.endpoint_hostname(),
        config.endpoint_port(),
        config.region(),
        db_spec.user(),
    )
    .await?;

    let mut stream = TcpStream::connect(config.connect_str()).await?;

    // Read server handshake (seq 0)
    let (seq, handshake_payload) = read_packet(&mut stream).await?;
    debug!("MySQL server handshake received (seq={})", seq);
    let server_caps = parse_server_handshake(&handshake_payload)?;

    if server_caps & CLIENT_SSL == 0 {
        return Err(eyre!(
            "MySQL server does not support SSL (required for IAM auth)"
        ));
    }

    // Compute client caps once for consistency between SSLRequest and HandshakeResponse
    let has_db = !db_spec.database().is_empty();
    let client_caps = compute_client_caps(server_caps, has_db);
    debug!("Server caps: 0x{:08x}, Client caps: 0x{:08x}", server_caps, client_caps);

    // Send SSLRequest (seq 1)
    let ssl_req = build_ssl_request(client_caps);
    write_packet(&mut stream, seq + 1, &ssl_req).await?;

    // MySQL: TLS handshake starts immediately after SSLRequest (no server response byte)
    let native_connector = native_tls::TlsConnector::builder()
        .danger_accept_invalid_certs(true)
        .build()?;
    let tls_connector = tokio_native_tls::TlsConnector::from(native_connector);
    let mut tls_stream = tls_connector
        .connect(config.endpoint_hostname(), stream)
        .await?;

    // Send HandshakeResponse over TLS (seq 2)
    let response = build_handshake_response(client_caps, db_spec.user(), &password, db_spec.database());
    write_packet(&mut tls_stream, seq + 2, &response).await?;

    // Handle authentication result
    let (resp_seq, result) = read_packet(&mut tls_stream).await?;

    match result[0] {
        OK_MARKER => {
            debug!("MySQL backend auth succeeded");
            Ok(tls_stream)
        }
        AUTH_SWITCH_MARKER => {
            debug!("MySQL backend requested auth switch");
            let plugin_end = result[1..]
                .iter()
                .position(|&b| b == 0)
                .ok_or_else(|| eyre!("Invalid AuthSwitchRequest"))?;
            let plugin_name = std::str::from_utf8(&result[1..1 + plugin_end])?;
            debug!("Auth switch to plugin: {}", plugin_name);

            if plugin_name == "mysql_clear_password" {
                // Respond with cleartext password + NUL (no length prefix for AuthSwitchResponse)
                let mut auth_data = password.as_bytes().to_vec();
                auth_data.push(0x00);
                write_packet(&mut tls_stream, resp_seq + 1, &auth_data).await?;

                let (_seq2, final_result) = read_packet(&mut tls_stream).await?;
                match final_result[0] {
                    OK_MARKER => {
                        debug!("MySQL auth succeeded after auth switch");
                        Ok(tls_stream)
                    }
                    ERR_MARKER => Err(eyre!(
                        "MySQL auth failed after switch: {}",
                        parse_err_message(&final_result)
                    )),
                    other => Err(eyre!("Unexpected post-switch response: 0x{:02x}", other)),
                }
            } else {
                Err(eyre!(
                    "Unsupported auth plugin requested by server: {}",
                    plugin_name
                ))
            }
        }
        ERR_MARKER => Err(eyre!(
            "MySQL backend auth failed: {}",
            parse_err_message(&result)
        )),
        0x01 => {
            // AuthMoreData — wait for the final OK/ERR
            debug!("Received AuthMoreData, waiting for final result");
            let (_seq2, final_result) = read_packet(&mut tls_stream).await?;
            match final_result[0] {
                OK_MARKER => Ok(tls_stream),
                ERR_MARKER => Err(eyre!(
                    "MySQL auth failed: {}",
                    parse_err_message(&final_result)
                )),
                other => Err(eyre!("Unexpected auth response: 0x{:02x}", other)),
            }
        }
        other => Err(eyre!("Unexpected auth response: 0x{:02x}", other)),
    }
}

// --- Public entry point ---

/// Handle a complete MySQL client connection: fake handshake, parse credentials,
/// connect to RDS backend with IAM auth, then relay traffic bidirectionally.
pub async fn handle_mysql_client(config: &BackendConfig, mut client: TcpStream) -> Result<()> {
    // 1. Send fake HandshakeV10 to client (seq 0)
    let handshake = build_handshake_v10();
    write_packet(&mut client, 0, &handshake).await?;

    // 2. Read client HandshakeResponse (seq 1)
    let (seq, client_payload) = read_packet(&mut client).await?;

    // If the payload is exactly 32 bytes the client sent an SSLRequest
    if client_payload.len() == 32 {
        let err = build_err_packet(
            1045,
            "28000",
            "SSL not supported by proxy. Connect without SSL.",
        );
        write_packet(&mut client, seq + 1, &err).await?;
        return Err(eyre!("Client requested SSL to proxy (not supported)"));
    }

    let db_spec = parse_client_handshake(&client_payload)?;
    info!(
        "MySQL connection: user={}, database={}",
        db_spec.user(),
        db_spec.database()
    );

    // 3. Connect to RDS backend with IAM auth
    let server = match connect_backend(config, &db_spec).await {
        Ok(s) => s,
        Err(e) => {
            let err = build_err_packet(1045, "28000", &format!("Backend auth failed: {}", e));
            write_packet(&mut client, seq + 1, &err).await?;
            return Err(e);
        }
    };

    // 4. Tell the client authentication succeeded
    let ok = build_ok_packet();
    write_packet(&mut client, seq + 1, &ok).await?;

    // 5. Bidirectional relay
    let (mut client_read, mut client_write) = io::split(client);
    let (mut server_read, mut server_write) = split(server);

    let c2s = async {
        io::copy(&mut client_read, &mut server_write).await?;
        server_write.shutdown().await
    };
    let s2c = async {
        io::copy(&mut server_read, &mut client_write).await?;
        client_write.shutdown().await
    };

    tokio::try_join!(c2s, s2c)?;
    Ok(())
}
