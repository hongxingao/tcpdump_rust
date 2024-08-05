use pcap::{Capture, Savefile};
use std::env;
use etherparse::{PacketHeaders, IpHeader, TransportHeader};

fn main() {
    // 从命令行参数获取网络接口名称和输出文件名
    let args: Vec<String> = env::args().collect();
    let interface: &String;
    let mut output_file: Option<&String> = None;

    if args.len() == 3 && args[1] == "-i" {
        interface = &args[2];
    } else if args.len() == 5 && args[1] == "-i" && args[3] == "-w" {
        interface = &args[2];
        output_file = Some(&args[4]);
    } else {
        eprintln!("Usage: {} -i <interface> [-w <output.pcap>]", args[0]);
        return;
    }

    // 打开网络接口进行捕获
    let mut cap = Capture::from_device(interface.as_str())
        .unwrap()
        .promisc(true)
        .timeout(1000)
        .open()
        .unwrap();

    // 可选的保存文件
    let mut savefile = output_file
        .map(|file| cap.savefile(file).unwrap());

    while let Ok(packet) = cap.next() {
        // 解析以太网帧
        match PacketHeaders::from_ethernet_slice(&packet) {
            Ok(headers) => {
                // 只处理 IPv4 包
                if let Some(IpHeader::Version4(ipv4, _)) = headers.ip {
                    // 检查是否为 TCP 包
                    if let Some(TransportHeader::Tcp(tcp)) = headers.transport {
                        // 获取 TCP 数据长度
                        let data_offset = tcp.data_offset() as usize;
                        let ip_header_len = ipv4.header_len() as usize;
                        let total_header_len = ip_header_len + data_offset;
                        let tcp_data_len = if packet.len() > total_header_len {
                            packet.len() - total_header_len
                        } else {
                            0
                        };

                        // 打印 TCP 包的信息
                        println!(
                            "Captured TCP packet: {:?}:{} -> {:?}:{}, length:{}",
                            ipv4.source,
                            tcp.source_port,
                            ipv4.destination,
                            tcp.destination_port,
                            tcp_data_len
                        );

                        // 如果指定了输出文件，保存捕获的 TCP 包到文件
                        if let Some(ref mut sf) = savefile {
                            sf.write(&packet);  // 省略错误处理
                            //println!("TCP packet written to file");
                        }
                    }
                }
            }
            Err(e) => {
                eprintln!("Error parsing packet: {:?}", e);
            }
        }
    }
}
