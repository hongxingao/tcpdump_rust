use pcap::Capture;
use std::env;
use etherparse::{PacketHeaders, IpHeader, TransportHeader, Ipv4HeaderSlice};

fn main() {
    // 从命令行参数获取网络接口名称
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <interface>", args[0]);
        return;
    }
    let interface = &args[1];

    // 打开网络接口进行捕获
    let mut cap = Capture::from_device(interface.as_str()).unwrap().promisc(true).timeout(1000).open().unwrap();

    while let Ok(packet) = cap.next() {
        // 解析以太网帧
        match PacketHeaders::from_ethernet_slice(&packet) {
            Ok(headers) => {
                // 只处理 IPv4 包
                if let Some(IpHeader::Version4(ipv4, _)) = headers.ip {
                    // 检查是否为 TCP 包
                    if let Some(TransportHeader::Tcp(tcp)) = headers.transport {
                        // 打印 TCP 包的信息
                        println!(
                            "Captured TCP packet: :{:?}:{} -> :{:?}:{}",
                            ipv4.source,
                            tcp.source_port,
                            ipv4.destination,
                            tcp.destination_port
                        );
                    }
                }
            }
            Err(e) => {
                eprintln!("Error parsing packet: {:?}", e);
            }
        }
    }
}
