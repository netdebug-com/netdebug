use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr},
    sync::Arc,
};

use axum::{
    body::Body,
    extract::{Path, State},
    http::{Response, StatusCode},
    response::IntoResponse,
    Router,
};
use axum::{response, routing};
use common_wasm::timeseries_stats::{CounterProvider, CounterProviderWithTimeUpdate};
use gui_types::CongestedLinksReply;
use libconntrack::{
    connection_tracker::{ConnectionTrackerMsg, TimeMode},
    dns_tracker::DnsTrackerMessage,
    send_or_log_sync,
    topology_client::TopologyRpcMessage,
    utils::{channel_rpc, channel_rpc_perf},
};
use libconntrack_wasm::{
    bidir_bandwidth_to_chartjs, AggregateStatEntry, ChartJsBandwidth, ConnectionIdString,
    ConnectionKey, ConnectionMeasurements, DnsTrackerEntry, ExportedNeighborState,
    NetworkInterfaceState,
};
use tokio::sync::mpsc::channel;
use tower_http::{
    cors::{self, AllowOrigin, CorsLayer},
    trace::{DefaultMakeSpan, TraceLayer},
};

use crate::Trackers;

// When running electron forge in dev mode, it (or rather the webpack
// it uses) starts the HTTP dev-server on this URL/origin. We need to
// set-up tower/axum to allow cross-origin requests from this origin
const ELECTRON_DEV_SERVER_ORIGIN: &str = "http://localhost:3000";

pub fn setup_axum_router() -> Router<Arc<Trackers>> {
    // Setup CORS to make sure that the electron in dev-mode can request
    // resources.
    let allowed_origins = vec![ELECTRON_DEV_SERVER_ORIGIN.parse().unwrap()];
    let cors = CorsLayer::new()
        .allow_methods(cors::Any)
        .allow_origin(AllowOrigin::list(allowed_origins));
    // Basic Request logging
    let trace_layer = TraceLayer::new_for_http()
        .make_span_with(DefaultMakeSpan::new().level(tracing::Level::DEBUG));
    Router::new()
        .route("/api/get_counters", routing::get(handle_get_counters))
        .route("/api/get_flows", routing::get(handle_get_flows))
        .route(
            "/api/get_one_flow/:conn_id",
            routing::get(handle_get_one_flow),
        )
        .route("/api/probe_flow/:conn_id", routing::get(handle_probe_flow))
        .route(
            "/api/pingtree_probe_flow/:conn_id",
            routing::get(handle_pingtree_probe_flow),
        )
        .route("/api/get_dns_cache", routing::get(handle_get_dns_cache))
        .route(
            "/api/get_aggregate_bandwidth",
            routing::get(handle_get_aggregate_bandwidth),
        )
        .route("/api/get_dns_flows", routing::get(handle_get_dns_flows))
        .route("/api/get_app_flows", routing::get(handle_get_app_flows))
        .route("/api/get_host_flows", routing::get(handle_get_host_flows))
        .route("/api/get_my_ip", routing::get(handle_get_my_ip))
        .route(
            "/api/get_congested_links",
            routing::get(handle_get_congested_links),
        )
        .route(
            "/api/get_system_network_history",
            routing::get(handle_get_system_network_history),
        )
        .route("/api/get_devices", routing::get(handle_get_devices))
        .layer(cors)
        .layer(trace_layer)
}

pub async fn handle_get_counters(State(trackers): State<Arc<Trackers>>) -> String {
    // IndexMap iterates over entries in insertion order
    let mut map = indexmap::IndexMap::<String, u64>::new();
    {
        let locked_registries = trackers
            .counter_registries
            .as_ref()
            .unwrap()
            .lock()
            .unwrap();
        locked_registries.update_time();
        locked_registries.append_counters(&mut map);
    }
    serde_json::to_string_pretty(&map).unwrap()
}

// TODO: for all teh handle_FOO handlers. Instead of returning empty on an error, we should
// actually propagate an proper error back to the UI.
// TODO: our usagae of SLA logging is inconsistent. Some have SLAs, some don't for now, I'm
// simply copying what we used for websocket

pub(crate) async fn handle_get_flows(
    State(trackers): State<Arc<Trackers>>,
) -> response::Json<Vec<ConnectionMeasurements>> {
    let (tx, mut rx) = channel(1);
    let req = ConnectionTrackerMsg::GetConnectionMeasurements {
        tx,
        time_mode: TimeMode::Wallclock,
    };
    response::Json(
        channel_rpc_perf(
            trackers.connection_tracker.clone().unwrap(),
            req,
            &mut rx,
            "connection_tracker/GetConnectionMeasurements",
            Some(tokio::time::Duration::from_millis(200)),
        )
        .await
        .unwrap_or_default(),
    )
}

pub(crate) async fn handle_probe_flow(
    State(trackers): State<Arc<Trackers>>,
    Path(conn_id_str): Path<ConnectionIdString>,
) -> impl IntoResponse {
    let conn_key = match ConnectionKey::try_from(&conn_id_str) {
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                format!("Invalid ConnectionId `{}`: {}", conn_id_str, e),
            )
        }
        Ok(key) => key,
    };

    // We currently don't care about the actual probe report that's been returned.
    // The user will get that on the next refresh of all flows. But maybe we should make
    // this rest enpoint more versatile and just return the ProbeReport instead?
    let (tx, _) = channel(1);
    let req = ConnectionTrackerMsg::ProbeReport {
        key: conn_key,
        should_probe_again: true,
        application_rtt: None,
        tx,
    };
    send_or_log_sync!(
        trackers.connection_tracker.clone().unwrap(),
        "connection_tracker/ProbeReport",
        req
    );
    (StatusCode::OK, String::new())
}

pub(crate) async fn handle_get_one_flow(
    State(trackers): State<Arc<Trackers>>,
    Path(conn_id_str): Path<ConnectionIdString>,
) -> Response<Body> {
    let conn_key = match ConnectionKey::try_from(&conn_id_str) {
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                format!("Invalid ConnectionId `{}`: {}", conn_id_str, e),
            )
                .into_response()
        }
        Ok(key) => key,
    };

    let (tx, mut rx) = channel(1);
    let req = ConnectionTrackerMsg::GetConnection {
        key: conn_key,
        time_mode: TimeMode::Wallclock,
        tx,
    };
    match channel_rpc_perf(
        trackers.connection_tracker.clone().unwrap(),
        req,
        &mut rx,
        "connection_tracker/GetConnection",
        None,
    )
    .await
    {
        // maybe_conn is an Option, so None gets serialized as `null`
        Ok(maybe_conn) => response::Json(maybe_conn).into_response(),
        Err(()) => (StatusCode::INTERNAL_SERVER_ERROR, String::new()).into_response(),
    }
}

pub(crate) async fn handle_pingtree_probe_flow(
    State(trackers): State<Arc<Trackers>>,
    Path(conn_id_str): Path<ConnectionIdString>,
) -> Response<Body> {
    let conn_key = match ConnectionKey::try_from(&conn_id_str) {
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                format!("Invalid ConnectionId `{}`: {}", conn_id_str, e),
            )
                .into_response()
        }
        Ok(key) => key,
    };

    let (tx, mut rx) = channel(1);
    let req = ConnectionTrackerMsg::GetConnection {
        key: conn_key,
        time_mode: TimeMode::Wallclock,
        tx,
    };
    match channel_rpc_perf(
        trackers.connection_tracker.clone().unwrap(),
        req,
        &mut rx,
        "connection_tracker/GetConnection",
        None,
    )
    .await
    {
        Ok(Some(conn)) => {
            let result = trackers
                .pingtree_manager
                .as_ref()
                .unwrap()
                .run_pingtree_for_probe_nodes(&conn.probe_report_summary, Some(conn.key))
                .await;
            response::Json(result).into_response()
        }
        Ok(None) => (StatusCode::OK, "null".to_owned()).into_response(),
        Err(()) => (StatusCode::INTERNAL_SERVER_ERROR, String::new()).into_response(),
    }
}

pub(crate) async fn handle_get_dns_cache(
    State(trackers): State<Arc<Trackers>>,
) -> response::Json<HashMap<IpAddr, DnsTrackerEntry>> {
    let (tx, mut rx) = channel(1);
    let req = DnsTrackerMessage::DumpReverseMap { tx };
    response::Json(
        channel_rpc(
            trackers.dns_tracker.clone().unwrap(),
            req,
            &mut rx,
            "dns_tracker/DumpReverseMap",
            None,
        )
        .await
        .unwrap_or_default(),
    )
}

pub(crate) async fn handle_get_aggregate_bandwidth(
    State(trackers): State<Arc<Trackers>>,
) -> response::Json<Vec<ChartJsBandwidth>> {
    let (tx, mut rx) = channel(1);
    let req = ConnectionTrackerMsg::GetTrafficCounters {
        tx,
        time_mode: TimeMode::Wallclock,
    };
    response::Json(
        channel_rpc_perf(
            trackers.connection_tracker.clone().unwrap(),
            req,
            &mut rx,
            "connection_tracker/GetTrafficCounter",
            Some(tokio::time::Duration::from_millis(50)),
        )
        .await
        .map(bidir_bandwidth_to_chartjs)
        .unwrap_or_default(),
    )
}

pub(crate) async fn handle_get_dns_flows(
    State(trackers): State<Arc<Trackers>>,
) -> response::Json<Vec<AggregateStatEntry>> {
    let (tx, mut rx) = channel(1);
    let req = ConnectionTrackerMsg::GetDnsTrafficCounters {
        tx,
        time_mode: TimeMode::Wallclock,
    };
    response::Json(
        channel_rpc_perf(
            trackers.connection_tracker.clone().unwrap(),
            req,
            &mut rx,
            "connection_tracker/GetDnsTrafficCounters",
            Some(tokio::time::Duration::from_millis(100)),
        )
        .await
        .unwrap_or_default(),
    )
}

pub(crate) async fn handle_get_app_flows(
    State(trackers): State<Arc<Trackers>>,
) -> response::Json<Vec<AggregateStatEntry>> {
    let (tx, mut rx) = channel(1);
    let req = ConnectionTrackerMsg::GetAppTrafficCounters {
        tx,
        time_mode: TimeMode::Wallclock,
    };
    response::Json(
        channel_rpc_perf(
            trackers.connection_tracker.clone().unwrap(),
            req,
            &mut rx,
            "connection_tracker/GetAppTrafficCounters",
            Some(tokio::time::Duration::from_millis(100)),
        )
        .await
        .unwrap_or_default(),
    )
}

pub(crate) async fn handle_get_host_flows(
    State(trackers): State<Arc<Trackers>>,
) -> response::Json<Vec<AggregateStatEntry>> {
    let (tx, mut rx) = channel(1);
    let req = ConnectionTrackerMsg::GetHostTrafficCounters {
        tx,
        time_mode: TimeMode::Wallclock,
    };
    response::Json(
        channel_rpc_perf(
            trackers.connection_tracker.clone().unwrap(),
            req,
            &mut rx,
            "connection_tracker/GetHostTrafficCounters",
            Some(tokio::time::Duration::from_millis(100)),
        )
        .await
        .unwrap_or_default(),
    )
}

pub(crate) async fn handle_get_my_ip(
    State(trackers): State<Arc<Trackers>>,
) -> response::Json<IpAddr> {
    // TODO: should return a list of IPs or a pair of v4/v6.
    let (tx, mut rx) = channel(1);
    let req = TopologyRpcMessage::GetMyIpAndUserAgent { reply_tx: tx };
    response::Json(
        channel_rpc_perf(
            trackers.topology_rpc_client.clone().unwrap(),
            req,
            &mut rx,
            "topology_server/GetMyIp",
            None,
        )
        .await
        .map(|perf_msg| {
            let (ip, _) = perf_msg.perf_check_get("handle_get_my_ip");
            ip
        })
        .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
    )
}

pub(crate) async fn handle_get_devices(
    State(trackers): State<Arc<Trackers>>,
) -> response::Json<Vec<ExportedNeighborState>> {
    let (tx, mut rx) = channel(1);
    let req = ConnectionTrackerMsg::GetCachedNeighbors { tx };
    response::Json(
        channel_rpc_perf(
            trackers.connection_tracker.clone().unwrap(),
            req,
            &mut rx,
            "ConnectionTracker/GetNeighborState",
            None,
        )
        .await
        .unwrap_or_default(),
    )
}

pub(crate) async fn handle_get_congested_links(
    State(trackers): State<Arc<Trackers>>,
) -> response::Json<CongestedLinksReply> {
    // 1. request connection measurements from conntracker
    let (tx, mut rx) = channel(1);
    let req = ConnectionTrackerMsg::GetConnectionMeasurements {
        tx,
        time_mode: TimeMode::Wallclock,
    };
    let conn_measurements = match channel_rpc_perf(
        trackers.connection_tracker.clone().unwrap(),
        req,
        &mut rx,
        "congested links -- connection_tracker/GetConnectionMeasurements",
        None,
    )
    .await
    {
        Ok(m) => m,
        Err(_) => return response::Json(CongestedLinksReply::default()),
    };

    // 2. send the measurements to the topology server for analysis
    let (tx, mut rx) = channel(1);
    let req = TopologyRpcMessage::InferCongestion {
        connection_measurements: conn_measurements.clone(),
        reply_tx: tx,
    };
    let congestion_summary = channel_rpc_perf(
        trackers.topology_rpc_client.clone().unwrap(),
        req,
        &mut rx,
        "congested links -- topology_server/InferCongestion",
        None,
    )
    .await
    .map(|perf_msg| perf_msg.perf_check_get("handle_congested_links"))
    .unwrap_or_default();
    response::Json(CongestedLinksReply {
        congestion_summary,
        connection_measurements: conn_measurements,
    })
}

pub(crate) async fn handle_get_system_network_history(
    State(trackers): State<Arc<Trackers>>,
) -> response::Json<Vec<NetworkInterfaceState>> {
    response::Json(
        trackers
            .system_tracker
            .clone()
            .unwrap()
            .read()
            .await
            .get_network_interface_histories(),
    )
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use axum::{body::Body, http::Request, http::Response, routing::RouterIntoService};
    use http_body_util::BodyExt;

    // for `collect`
    use libconntrack::connection_tracker::ConnectionTrackerReceiver;
    use libconntrack_wasm::IpProtocol;
    use tower::{Service, ServiceExt};

    use super::*;

    struct MockRouteHandler {
        service: RouterIntoService<Body>,
        // needs to be an Option<> so we `take()` it and move it into an async block
        conn_track_rx: Option<ConnectionTrackerReceiver>,
    }

    async fn extract_status_and_body(response: Response<Body>) -> (StatusCode, String) {
        (
            response.status(),
            String::from_utf8(
                response
                    .into_body()
                    .collect()
                    .await
                    .unwrap()
                    .to_bytes()
                    .to_vec(),
            )
            .unwrap(),
        )
    }

    impl MockRouteHandler {
        fn new() -> Self {
            let (conn_track_tx, conn_track_rx) = channel(10);
            let mut trackers = Trackers::empty();
            trackers.connection_tracker = Some(conn_track_tx);

            let trackers = Arc::new(trackers);

            MockRouteHandler {
                conn_track_rx: Some(conn_track_rx),
                service: setup_axum_router().with_state(trackers).into_service(),
            }
        }

        fn conn_track_rx(&mut self) -> &mut ConnectionTrackerReceiver {
            self.conn_track_rx.as_mut().unwrap()
        }

        /// Call the service with the given request
        async fn call_req(&mut self, req: Request<Body>) -> Response<Body> {
            // black magic taken from https://github.com/tokio-rs/axum/blob/main/examples/testing/src/main.rs#L162
            ServiceExt::<Request<Body>>::ready(&mut self.service)
                .await
                .unwrap()
                .call(req)
                .await
                .unwrap()
        }

        /// Call the given URI with an empty body and no headers
        async fn simple_call_uri(&mut self, uri: &str) -> Response<Body> {
            self.call_req(Request::builder().uri(uri).body(Body::empty()).unwrap())
                .await
        }
    }

    #[tokio::test]
    async fn test_handle_probe_flows() {
        let mut service = MockRouteHandler::new();

        // without a connection_id parameter we get a 404 not found
        assert_eq!(
            service.simple_call_uri("/api/probe_flow").await.status(),
            StatusCode::NOT_FOUND
        );
        assert!(service.conn_track_rx().is_empty());

        // invalid connection key.
        let resp = service.simple_call_uri("/api/probe_flow/XXX").await;
        let (status, body) = extract_status_and_body(resp).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        // should have an error message in the body
        assert!(!body.is_empty());
        assert!(service.conn_track_rx().is_empty());

        // a valid request
        let orig_key = ConnectionKey {
            local_ip: IpAddr::from_str("127.0.0.1").unwrap(),
            remote_ip: IpAddr::from_str("1.2.3.4").unwrap(),
            local_l4_port: 23,
            remote_l4_port: 4242,
            ip_proto: IpProtocol::TCP,
        };
        let uri = format!("/api/probe_flow/{}", ConnectionIdString::from(&orig_key));
        let (status, body) = extract_status_and_body(service.simple_call_uri(&uri).await).await;
        assert_eq!(status, StatusCode::OK);
        // no body
        assert!(body.is_empty());
        match service
            .conn_track_rx()
            .try_recv()
            .unwrap()
            .skip_perf_check()
        {
            ConnectionTrackerMsg::ProbeReport {
                key,
                should_probe_again,
                application_rtt,
                tx: _tx,
            } => {
                assert_eq!(key, orig_key);
                assert!(should_probe_again);
                assert_eq!(application_rtt, None);
            }
            _ => panic!("Got unexpected connection tracker message"),
        };
    }

    #[tokio::test]
    async fn test_handle_get_one_flow() {
        let mut service = MockRouteHandler::new();

        // without a connection_id parameter we get a 404 not found
        assert_eq!(
            service.simple_call_uri("/api/get_one_flow").await.status(),
            StatusCode::NOT_FOUND
        );
        assert!(service.conn_track_rx().is_empty());

        // invalid connection key.
        let resp = service.simple_call_uri("/api/get_one_flow/XXX").await;
        let (status, body) = extract_status_and_body(resp).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        // should have an error message in the body
        assert!(!body.is_empty());
        assert!(service.conn_track_rx().is_empty());

        // a valid request
        let orig_key = ConnectionKey {
            local_ip: IpAddr::from_str("127.0.0.1").unwrap(),
            remote_ip: IpAddr::from_str("1.2.3.4").unwrap(),
            local_l4_port: 23,
            remote_l4_port: 4242,
            ip_proto: IpProtocol::TCP,
        };
        let expected_conn_measurement = ConnectionMeasurements::make_mock();
        // spawn a connection tracker
        let expected_conn_measurement_clone = expected_conn_measurement.clone();
        let key_clone = orig_key.clone();
        let mut conn_track_rx = service.conn_track_rx.take().unwrap();
        tokio::spawn(async move {
            // Handle two requests. On the first one, return None, on the second request
            // return a mock connection
            let msg = conn_track_rx.recv().await.unwrap().skip_perf_check();
            match msg {
                ConnectionTrackerMsg::GetConnection { key, tx, .. } if key == key_clone => {
                    tx.try_send(None).unwrap();
                }
                _ => panic!("Unexpected connection tracker message"),
            };
            // Handle two requests. On the first one, return None, on the second request
            // return a mock connection
            let msg = conn_track_rx.recv().await.unwrap().skip_perf_check();
            match msg {
                ConnectionTrackerMsg::GetConnection { key, tx, .. } if key == key_clone => {
                    tx.try_send(Some(expected_conn_measurement_clone)).unwrap();
                }
                _ => panic!("Unexpected connection tracker message"),
            };
        });

        let uri = format!("/api/get_one_flow/{}", ConnectionIdString::from(&orig_key));
        let (status, body) = extract_status_and_body(service.simple_call_uri(&uri).await).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "null");

        let uri = format!("/api/get_one_flow/{}", ConnectionIdString::from(&orig_key));
        let (status, body) = extract_status_and_body(service.simple_call_uri(&uri).await).await;
        assert_eq!(status, StatusCode::OK);
        let received_conn_measurement =
            serde_json::from_str::<ConnectionMeasurements>(&body).unwrap();
        assert_eq!(received_conn_measurement, expected_conn_measurement);
    }

    // TODO: add test for `handle_pingtree_probe_flow`, but that requires mocking a bunch of
    // stuff (a mock ConnectionMeasurement with probe_report_summary, and a mock PingTreeManager.
}
