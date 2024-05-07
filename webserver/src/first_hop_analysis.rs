/*
// all users across all orgs who had loss

SELECT desktop_aggregated_ping_data.time, device_uuid, num_responses_recv, num_probes_sent,
    (100.0*(1-num_responses_recv/num_probes_sent::float)) AS percent_loss, organization,name, description
FROM desktop_aggregated_ping_data
INNER JOIN desktop_network_interface_state ON desktop_network_interface_state.state_uuid = desktop_aggregated_ping_data.network_interface_state_uuid
INNER JOIN devices ON desktop_network_interface_state.device_uuid = devices.uuid
WHERE num_responses_recv < num_probes_sent ORDER BY 5 DESC;

// top five users with first-hop loss problems in the last hour


//

SELECT device_uuid, SUM(num_responses_recv), SUM(num_probes_sent),
    (100.0*(1-SUM(num_responses_recv)/SUM(num_probes_sent::float))) AS percent_loss, organization,name, description
FROM desktop_aggregated_ping_data
INNER JOIN desktop_network_interface_state ON desktop_network_interface_state.state_uuid = desktop_aggregated_ping_data.network_interface_state_uuid
INNER JOIN devices ON desktop_network_interface_state.device_uuid = devices.uuid
GROUP BY device_uuid, organization, name, description  ORDER BY 5 DESC;
             device_uuid              |    sum    |    sum    |     percent_loss     | organization |        name         | description
--------------------------------------+-----------+-----------+----------------------+--------------+---------------------+--------------
 00000000-0000-0000-0000-000000000000 |    476405 |    476510 |  0.02203521437115219 |            1 |                     |
 11aea277-c8cb-4d25-b9b4-ec730de6af22 |    102356 |    102440 |  0.08199921905505114 |            1 | RSY's Laptop        | 24.218.5.159
 2c27391d-a634-4fff-84bc-bd836589ffed |   4407834 |   4409722 |  0.04281449034655438 |            1 | Gregor's Laptop     |
 da5dd3c6-58dc-4f56-b10b-d38fba795744 | 128063058 | 128070827 | 0.006066174617580522 |            1 | Rob's Laptop (prod) | 75.11.9.108



 // top 10 users by percent_loss across all time (assumes all devices are registered in devices TABLE) for org =1

SELECT devices.uuid, T.percent_loss, devices.name, devices.description FROM (
    SELECT device_uuid,  SUM(num_responses_recv), SUM(num_probes_sent),
        (100.0*(1-SUM(num_responses_recv)/SUM(num_probes_sent::float))) AS percent_loss
    FROM desktop_network_interface_state
    INNER JOIN desktop_aggregated_ping_data ON desktop_aggregated_ping_data.network_interface_state_uuid = desktop_network_interface_state.state_uuid
    WHERE device_uuid IN ( SELECT uuid FROM devices WHERE organization = 1)
    GROUP BY device_uuid
    ORDER BY 4 DESC
    LIMIT 10
    ) AS T
INNER JOIN devices ON devices.uuid = T.device_uuid;

*/

use gui_types::{FirstHopPacketLossReportEntry, OrganizationId};

use gui_types::FirstHopTimeSeriesData;
use tokio_postgres::Client;
use uuid::Uuid;

use crate::{remotedb_client::extract_aggregated_ping_data, rest_routes::TimeRangeQueryParams};

/// Get the top n worst first hop devices in the time range, by packet loss
pub async fn first_hop_worst_n_by_packet_loss(
    db_client: &Client,
    n: u32,
    organization: OrganizationId,
    _time_range: &TimeRangeQueryParams, // TODO: support time ranges; ignore for now
) -> Result<Vec<FirstHopPacketLossReportEntry>, tokio_postgres::Error> {
    // NOTE: assumes that the compiler prevents malicious parameters from being passed
    // Should be fairly simple to maintain this assumption

    // NOTE on the query: despite being a little complicate, it's not that bad.
    // Step #1/inner query: make a list of device_uuid's for this org
    // Step #2: extract the interface uuid's that match devices in that org
    // Step #3: INNER JOIN that list with the ping data and compute percent_loss
    // Step #4: ORDER and LIMIT that to the top n; save all of #1-4 as table "T"
    //      NOTE we cast a bunch of variables from postgres's arbitrary precision 'numeric' type
    //          which our postgres client doesn't understand to 'bigint' which ours can convert to i64
    //          there is a 3rd party crate 'rust_decimal' to support 'numeric' types natively, but is over
    //          kill for our needs.  Check out https://github.com/sfackler/rust-postgres/issues/307 for more
    //          details.
    // STEP #5/outer query: INNER JOIN table T with the device table to get name, description, etc.
    let query = format!("
SELECT devices.uuid, T.percent_loss, devices.name, devices.description, T.probes_recv::bigint, T.probes_sent::bigint FROM (
    SELECT device_uuid,  SUM(num_responses_recv) AS probes_recv, SUM(num_probes_sent) AS probes_sent,
        (100.0*(1-SUM(num_responses_recv)/SUM(num_probes_sent::float))) AS percent_loss  
    FROM desktop_network_interface_state  
    INNER JOIN desktop_aggregated_ping_data ON desktop_aggregated_ping_data.network_interface_state_uuid = desktop_network_interface_state.state_uuid 
    WHERE device_uuid IN ( SELECT uuid FROM devices WHERE organization = {}) 
    GROUP BY device_uuid 
    ORDER BY 4 DESC 
    LIMIT {}
    ) AS T
INNER JOIN devices ON devices.uuid = T.device_uuid;
    ", organization, n);
    let rows = db_client.query(&query, &[]).await?;
    Ok(rows
        .iter()
        .map(|row| FirstHopPacketLossReportEntry {
            device_uuid: row.get::<_, Uuid>("uuid"),
            device_name: row.get::<_, Option<String>>("name"),
            device_description: row.get::<_, Option<String>>("description"),
            probes_sent: row.get::<_, i64>("probes_sent") as u64,
            probes_recv: row.get::<_, i64>("probes_recv") as u64,
            percent_loss: row.get::<_, f64>("percent_loss"),
        })
        .collect::<Vec<FirstHopPacketLossReportEntry>>())
}

/// Collect the data on a single device to build a time series graph of
/// first-hop data
///
pub async fn first_hop_single_device_timeline(
    db_client: &Client,
    device_uuid: Uuid,
) -> Result<Vec<Vec<FirstHopTimeSeriesData>>, tokio_postgres::Error> {
    let mut results: Vec<Vec<FirstHopTimeSeriesData>> = Vec::new();
    let rows = db_client.query( "
        SELECT q.* FROM ( 
            SELECT interface_name, has_link, is_wireless, start_time, desktop_aggregated_ping_data.time, 
                gateway_ip, num_probes_sent, num_responses_recv, 
                network_interface_state_uuid, gateway_ip,
                rtt_mean_ns , rtt_variance_ns , rtt_min_ns, rtt_p50_ns, rtt_p75_ns, rtt_p90_ns, rtt_p99_ns, rtt_max_ns 
            FROM desktop_network_interface_state  
            INNER JOIN desktop_aggregated_ping_data 
            ON desktop_network_interface_state.state_uuid = desktop_aggregated_ping_data.network_interface_state_uuid 
            WHERE device_uuid = $1 ORDER BY desktop_aggregated_ping_data.time) AS q
        ORDER BY q.time
            
    ", &[&device_uuid]).await?;

    let mut prev_interface_uuid: Option<Uuid> = None;
    for row in rows {
        let interface_name = row.try_get::<_, String>("interface_name")?;
        // NOTE: Javascript can convert easily from UTC to local time, so push the conversion off until display
        let (time, aggregate_ping_data) = extract_aggregated_ping_data(&row)?;
        let data = FirstHopTimeSeriesData {
            aggregate_ping_data,
            time,
            interface_name,
            is_wireless: row.try_get("is_wireless")?,
            has_link: row.try_get("has_link")?,
        };
        let new_interface_uuid = data.aggregate_ping_data.network_interface_uuid;
        if let Some(prev_state_uuid) = prev_interface_uuid {
            if prev_state_uuid == new_interface_uuid {
                // the same interface is still up continuously, just apprend the data
                results.last_mut().unwrap().push(data);
            } else {
                // the interface changed, create a new series
                results.push(vec![data]);
            }
        } else {
            // this is our first row
            results.push(vec![data]);
        }
        prev_interface_uuid = Some(new_interface_uuid);
    }
    Ok(results)
}
