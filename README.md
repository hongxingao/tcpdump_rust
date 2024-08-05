使用rust实现的一个简单抓包工具，目前只支持抓取tcp(可保存为pcap)

未测试windows和mac平台，以下是ubuntu20编译运行步骤：

由于依赖了pcap和etherparse，需要安装libpcap,
ubuntu可以使用 sudo apt-get install libpcap-dev 安装

cd tcpdump_rust

cargo build

cd target/debug

./tcpdump_rust -i eth0 或者 ./tcpdump_rust -i eth0 -w ./test.pacp
