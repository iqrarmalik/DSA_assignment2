#include <arpa/inet.h>
#include <chrono>
#include <cstring>
#include <errno.h>
#include <ifaddrs.h>
#include <iostream>
#include <mutex>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netpacket/packet.h>
#include <sstream>
#include <string>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>
#include <vector>
#include <atomic>
#include <condition_variable>
#include <iomanip>
#include <deque>

using HighResClock = std::chrono::steady_clock;
using TimeStamp = std::chrono::time_point<HighResClock>;

// helper: produce human timestamp with milliseconds
static inline std::string formatted_time()
{
    using namespace std::chrono;
    auto now = system_clock::now();
    time_t tt = system_clock::to_time_t(now);
    struct tm tm;
    localtime_r(&tt, &tm);
    char buf[64];
    strftime(buf, sizeof(buf), "%F %T", &tm);
    auto ms = duration_cast<milliseconds>(now.time_since_epoch()).count() % 1000;
    char out[80];
    snprintf(out, sizeof(out), "%s.%03lld", buf, (long long)ms);
    return std::string(out);
}

// container for a captured packet and parsed metadata
struct NetPacket
{
    uint64_t uid = 0;
    TimeStamp captured_at;
    std::vector<uint8_t> frame;
    std::string src; // ip[:port] or mac
    std::string dst; // ip[:port] or mac
    int tries = 0;   // replay attempts
};

// simple LIFO used while parsing headers
template <typename T>
class StackParse
{
    std::vector<T> store_;

public:
    void push(const T &v) { store_.push_back(v); }
    T pop()
    {
        if (store_.empty())
            throw std::runtime_error("stack empty");
        T v = store_.back();
        store_.pop_back();
        return v;
    }
    T &top()
    {
        if (store_.empty())
            throw std::runtime_error("stack empty");
        return store_.back();
    }
    bool empty() const { return store_.empty(); }
    size_t size() const { return store_.size(); }
};

// shared queues and synchronization primitives
static std::deque<NetPacket> capture_queue; // raw frames awaiting parse
static std::mutex capture_mutex;
static std::condition_variable capture_cv;

static std::vector<NetPacket> send_candidates; // packets ready for injection
static std::vector<NetPacket> retry_list;      // failed injections for retry
static std::mutex send_mutex;

static std::atomic<bool> shutdown_flag(false);
static std::atomic<uint64_t> seq_counter(0);
const size_t OVERSIZE_THRESHOLD = 100;
static std::atomic<size_t> oversized_skips(0);

// safe IPv6 text conversion
static std::string ipv6_to_string(const in6_addr &a)
{
    char buf[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &a, buf, sizeof(buf));
    return std::string(buf);
}

// thread: capture raw frames from interface
void sniff_thread(const std::string &iface)
{
    int s = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (s < 0)
    {
        std::cerr << "sniff: socket(): " << strerror(errno) << "\n";
        return;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface.c_str(), IFNAMSIZ - 1);
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';
    if (ioctl(s, SIOCGIFINDEX, &ifr) == -1)
    {
        std::cerr << "sniff: SIOCGIFINDEX: " << strerror(errno) << "\n";
        close(s);
        return;
    }

    struct sockaddr_ll bind_addr;
    memset(&bind_addr, 0, sizeof(bind_addr));
    bind_addr.sll_family = AF_PACKET;
    bind_addr.sll_ifindex = ifr.ifr_ifindex;
    bind_addr.sll_protocol = htons(ETH_P_ALL);

    if (bind(s, (struct sockaddr *)&bind_addr, sizeof(bind_addr)) == -1)
    {
        std::cerr << "sniff: bind(): " << strerror(errno) << "\n";
        close(s);
        return;
    }

    const size_t BUFSZ = 65536;
    std::vector<uint8_t> buf(BUFSZ);

    while (!shutdown_flag.load())
    {
        ssize_t r = recv(s, buf.data(), BUFSZ, 0);
        if (r < 0)
        {
            if (errno == EINTR)
                continue;
            std::cerr << "sniff: recv(): " << strerror(errno) << "\n";
            break;
        }
        if (r == 0)
            continue;
        if (r < 14)
            continue; // not a valid Ethernet frame

        NetPacket pkt;
        pkt.uid = ++seq_counter;
        pkt.captured_at = HighResClock::now();
        pkt.frame.assign(buf.begin(), buf.begin() + r);

        if (pkt.frame.size() > 1500)
        {
            size_t prev = ++oversized_skips;
            if (prev > OVERSIZE_THRESHOLD)
            {
                continue;
            }
        }

        {
            std::lock_guard<std::mutex> lk(capture_mutex);
            capture_queue.push_back(std::move(pkt));
        }
        capture_cv.notify_one();
    }

    close(s);
}

// thread: parse captured frames and extract IP/TCP/UDP metadata
void parse_thread()
{
    while (!shutdown_flag.load())
    {
        std::unique_lock<std::mutex> lk(capture_mutex);
        capture_cv.wait_for(lk, std::chrono::milliseconds(200), []
                            { return !capture_queue.empty() || shutdown_flag.load(); });

        if (capture_queue.empty())
        {
            if (shutdown_flag.load())
                break;
            continue;
        }

        NetPacket pkt = std::move(capture_queue.front());
        capture_queue.pop_front();
        lk.unlock();

        StackParse<std::pair<std::string, size_t>> header_stack;
        header_stack.push({"ETH", 0});

        if (pkt.frame.size() < 14)
            continue;
        uint16_t ethertype = (uint16_t(pkt.frame[12]) << 8) | uint16_t(pkt.frame[13]);

        if (ethertype == 0x0800)
        { // IPv4
            header_stack.push({"IPv4", 14});
            size_t off = 14;
            if (pkt.frame.size() < off + 20)
                continue;

            uint8_t ihl = pkt.frame[off] & 0x0F;
            uint8_t proto = pkt.frame[off + 9];

            struct in_addr sa, da;
            memcpy(&sa.s_addr, &pkt.frame[off + 12], sizeof(uint32_t));
            memcpy(&da.s_addr, &pkt.frame[off + 16], sizeof(uint32_t));

            char s_str[INET_ADDRSTRLEN] = {0}, d_str[INET_ADDRSTRLEN] = {0};
            inet_ntop(AF_INET, &sa, s_str, sizeof(s_str));
            inet_ntop(AF_INET, &da, d_str, sizeof(d_str));
            pkt.src = s_str;
            pkt.dst = d_str;

            size_t ip_hdr_len = size_t(ihl) * 4;
            size_t tOff = off + ip_hdr_len;

            if (proto == IPPROTO_TCP && pkt.frame.size() >= tOff + 20)
            {
                header_stack.push({"TCP", tOff});
                uint16_t sp = (uint16_t(pkt.frame[tOff]) << 8) | uint16_t(pkt.frame[tOff + 1]);
                uint16_t dp = (uint16_t(pkt.frame[tOff + 2]) << 8) | uint16_t(pkt.frame[tOff + 3]);
                pkt.src += ":" + std::to_string(sp);
                pkt.dst += ":" + std::to_string(dp);
            }
            else if (proto == IPPROTO_UDP && pkt.frame.size() >= tOff + 8)
            {
                header_stack.push({"UDP", tOff});
                uint16_t sp = (uint16_t(pkt.frame[tOff]) << 8) | uint16_t(pkt.frame[tOff + 1]);
                uint16_t dp = (uint16_t(pkt.frame[tOff + 2]) << 8) | uint16_t(pkt.frame[tOff + 3]);
                pkt.src += ":" + std::to_string(sp);
                pkt.dst += ":" + std::to_string(dp);
            }
        }
        else if (ethertype == 0x86DD)
        { // IPv6
            header_stack.push({"IPv6", 14});
            size_t off = 14;
            const size_t IPV6_HDR_SIZE = sizeof(struct ip6_hdr);
            if (pkt.frame.size() < off + IPV6_HDR_SIZE)
                continue;

            struct ip6_hdr h6;
            memcpy(&h6, pkt.frame.data() + off, IPV6_HDR_SIZE);
            pkt.src = ipv6_to_string(h6.ip6_src);
            pkt.dst = ipv6_to_string(h6.ip6_dst);

            uint8_t nxt = h6.ip6_nxt;
            size_t tOff = off + IPV6_HDR_SIZE;

            if (nxt == IPPROTO_TCP && pkt.frame.size() >= tOff + 20)
            {
                header_stack.push({"TCP", tOff});
                uint16_t sp = (uint16_t(pkt.frame[tOff]) << 8) | uint16_t(pkt.frame[tOff + 1]);
                uint16_t dp = (uint16_t(pkt.frame[tOff + 2]) << 8) | uint16_t(pkt.frame[tOff + 3]);
                pkt.src += ":" + std::to_string(sp);
                pkt.dst += ":" + std::to_string(dp);
            }
            else if (nxt == IPPROTO_UDP && pkt.frame.size() >= tOff + 8)
            {
                header_stack.push({"UDP", tOff});
                uint16_t sp = (uint16_t(pkt.frame[tOff]) << 8) | uint16_t(pkt.frame[tOff + 1]);
                uint16_t dp = (uint16_t(pkt.frame[tOff + 2]) << 8) | uint16_t(pkt.frame[tOff + 3]);
                pkt.src += ":" + std::to_string(sp);
                pkt.dst += ":" + std::to_string(dp);
            }
        }
        else
        {
            continue; // skip non-IP frames
        }

        {
            std::lock_guard<std::mutex> lk(send_mutex);
            send_candidates.push_back(std::move(pkt));
        }
    }
}

// helper to compare packet address (ip or ip:port) against filter
static bool addr_matches(const std::string &packetAddr, const std::string &filter)
{
    if (filter.empty())
        return true;
    if (packetAddr.empty())
        return false;
    if (filter.find(':') != std::string::npos)
        return packetAddr == filter;
    size_t pos = packetAddr.find(':');
    std::string ip = (pos == std::string::npos) ? packetAddr : packetAddr.substr(0, pos);
    return ip == filter;
}

// thread: inject parsed packets back onto the wire (with simple retry logic)
void inject_thread(const std::string &iface, const std::string &f_src, const std::string &f_dst)
{
    int tx = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (tx < 0)
    {
        std::cerr << "inject: socket(): " << strerror(errno) << "\n";
        return;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface.c_str(), IFNAMSIZ - 1);
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';
    if (ioctl(tx, SIOCGIFINDEX, &ifr) == -1)
    {
        std::cerr << "inject: SIOCGIFINDEX: " << strerror(errno) << "\n";
        close(tx);
        return;
    }

    struct sockaddr_ll dest;
    memset(&dest, 0, sizeof(dest));
    dest.sll_family = AF_PACKET;
    dest.sll_ifindex = ifr.ifr_ifindex;
    dest.sll_halen = ETH_ALEN;

    while (!shutdown_flag.load())
    {
        std::vector<NetPacket> batch;
        {
            std::lock_guard<std::mutex> lk(send_mutex);
            if (!send_candidates.empty())
                batch.swap(send_candidates);
        }

        if (batch.empty())
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
            continue;
        }

        for (auto &pkt : batch)
        {
            if (!addr_matches(pkt.src, f_src))
                continue;
            if (!addr_matches(pkt.dst, f_dst))
                continue;

            if (pkt.frame.size() > 1500 && oversized_skips.load() > OVERSIZE_THRESHOLD)
                continue;

            bool ok = false;
            for (int attempt = 0; attempt <= 2; ++attempt)
            {
                ssize_t s = sendto(tx, pkt.frame.data(), pkt.frame.size(), 0, (struct sockaddr *)&dest, sizeof(dest));
                if (s == (ssize_t)pkt.frame.size())
                {
                    ok = true;
                    break;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }

            if (!ok)
            {
                std::lock_guard<std::mutex> lk(send_mutex);
                pkt.tries++;
                retry_list.push_back(pkt);
            }
            else
            {
                double delay_ms = double(pkt.frame.size()) / 1000.0;
                std::cout << "[INJECTED] id=" << pkt.uid << " time=" << formatted_time()
                          << " src=" << pkt.src << " dst=" << pkt.dst
                          << " delay(ms)=" << std::fixed << std::setprecision(2) << delay_ms
                          << " size=" << pkt.frame.size() << "\n";
            }
        }

        // process retry list
        {
            std::lock_guard<std::mutex> lk(send_mutex);
            if (!retry_list.empty())
            {
                std::vector<NetPacket> keep;
                for (auto &rp : retry_list)
                {
                    if (rp.tries >= 2)
                    {
                        keep.push_back(rp);
                        continue;
                    }
                    bool recovered = false;
                    for (int r = 0; r < 2; ++r)
                    {
                        ssize_t s = sendto(tx, rp.frame.data(), rp.frame.size(), 0, (struct sockaddr *)&dest, sizeof(dest));
                        if (s == (ssize_t)rp.frame.size())
                        {
                            recovered = true;
                            break;
                        }
                        std::this_thread::sleep_for(std::chrono::milliseconds(100));
                    }
                    if (!recovered)
                    {
                        rp.tries++;
                        keep.push_back(rp);
                    }
                    else
                    {
                        std::cout << "[RECOVERY] id=" << rp.uid << " time=" << formatted_time() << "\n";
                    }
                }
                retry_list.swap(keep);
            }
        }
    }

    close(tx);
}

// display helpers
void dump_candidates()
{
    std::lock_guard<std::mutex> lk(send_mutex);
    if (send_candidates.empty())
    {
        std::cout << "No parsed packets.\n";
        return;
    }
    std::cout << "Parsed candidate packets (" << send_candidates.size() << "):\n";
    for (auto &p : send_candidates)
    {
        std::cout << "id=" << p.uid << " time=" << formatted_time() << " src=" << p.src << " dst=" << p.dst << " size=" << p.frame.size() << "\n";
    }
}

void dump_retries()
{
    std::lock_guard<std::mutex> lk(send_mutex);
    if (retry_list.empty())
    {
        std::cout << "No retries.\n";
        return;
    }
    std::cout << "Retry list:\n";
    for (auto &p : retry_list)
    {
        std::cout << "id=" << p.uid << " tries=" << p.tries << " src=" << p.src << " dst=" << p.dst << " size=" << p.frame.size() << "\n";
    }
}

int main(int argc, char **argv)
{
    if (argc < 2)
    {
        std::cerr << "Usage: sudo " << argv[0] << " <interface> [filterSrc] [filterDst]\n";
        return 1;
    }
    std::string iface = argv[1];
    std::string filter_src = (argc >= 3) ? argv[2] : "";
    std::string filter_dst = (argc >= 4) ? argv[3] : "";

    std::cout << "Network Monitor - rewritten starting on: " << iface << "\n";
    if (!filter_src.empty())
        std::cout << "Source filter: " << filter_src << "\n";
    if (!filter_dst.empty())
        std::cout << "Destination filter: " << filter_dst << "\n";

    std::thread t_sniff(sniff_thread, iface);
    std::thread t_parse(parse_thread);
    std::thread t_inject(inject_thread, iface, filter_src, filter_dst);

    auto start = HighResClock::now();
    auto demo_len = std::chrono::seconds(60);
    while (HighResClock::now() - start < demo_len)
    {
        std::this_thread::sleep_for(std::chrono::seconds(10));
        std::cout << "----- status @ " << formatted_time() << " -----\n";
        std::cout << "Captured approx: " << seq_counter.load()
                  << "  queue size: " << capture_queue.size()
                  << "  oversize skipped: " << oversized_skips.load() << "\n";
        dump_candidates();
        dump_retries();
        std::cout << "-------------------------------\n";
    }

    shutdown_flag.store(true);
    capture_cv.notify_all();

    if (t_sniff.joinable())
        t_sniff.join();
    if (t_parse.joinable())
        t_parse.join();
    if (t_inject.joinable())
        t_inject.join();

    std::cout << "Demo ended. Final retry list:\n";
    dump_retries();
    std::cout << "Exit.\n";
        return 0;
}