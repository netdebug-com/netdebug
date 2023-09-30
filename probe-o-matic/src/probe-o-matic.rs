use libconntrack::connection::ConnectionTrackerMsg;
use libconntrack::pcap::{find_interesting_pcap_interfaces, run_blocking_pcap_loop_in_thread};
use log::{info, warn};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    utils::init::netdebug_init();

    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<ConnectionTrackerMsg>();
    let devices = find_interesting_pcap_interfaces(&None)?;
    for dev in devices {
        info!("Got pcap device: {}", dev.name);
        let _handle = run_blocking_pcap_loop_in_thread(dev.name.clone(), None, tx.clone(), None);
    }
    tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            use ConnectionTrackerMsg::*;
            match msg {
                Pkt(pkt) => info!("Got a packet: {:?}", pkt),
                _ => warn!("We can only handle `Pkt` messages, but got: {:?}", msg),
            }
        }
        warn!("Exiting receive loop");
    })
    .await?;
    Ok(())
}
