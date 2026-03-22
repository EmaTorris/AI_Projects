import pyshark
import asyncio
from collections import Counter

INTERFACE = "en0"
CAPTURE_DURATION = 30  # secondi


def capture_traffic(duration: int = CAPTURE_DURATION) -> list:
    print(f"Avvio cattura traffico su {INTERFACE} per {duration} secondi...")

    capture = pyshark.LiveCapture(interface=INTERFACE)
    packets = []

    capture.sniff(timeout=duration)

    for packet in capture._packets:
        packets.append(packet)

    print(f"Catturati {len(packets)} pacchetti")
    return packets


def capture_dns(packet_count: int = 20) -> list:
    print(f"Avvio cattura DNS su {INTERFACE}...")
    capture = pyshark.LiveCapture(
        interface=INTERFACE,
        display_filter="dns"
    )
    dns_packets = []
    for packet in capture.sniff_continuously(packet_count=packet_count):
        dns_packets.append(packet)
    print(f"Catturati {len(dns_packets)} pacchetti DNS")
    return dns_packets


def analyze_outbound_connections(packets: list) -> dict:
    destinations = []

    for packet in packets:
        if hasattr(packet, 'ip'):
            destinations.append(packet.ip.dst)

    counter = Counter(destinations)

    return {
        "total": len(destinations),
        "unique_destinations": len(counter),
        "top_destinations": counter.most_common(5)
    }


def analyze_dns(packets: list) -> dict:
    domains = []

    for packet in packets:
        if hasattr(packet, 'dns'):
            try:
                domain = packet.dns.qry_name
                domains.append(domain)
            except AttributeError:
                continue

    return {
        "total_queries": len(domains),
        "unique_domains": len(set(domains)),
        "domains": list(set(domains))
    }


def calculate_anomaly_score(outbound: dict, dns: dict) -> float:
    score = 0.0

    if outbound["unique_destinations"] > 20:
        score += 0.4

    if dns["total_queries"] > 50:
        score += 0.3

    if dns["unique_domains"] > 20:
        score += 0.3

    return min(score, 1.0)


def run_sandbox(duration: int = CAPTURE_DURATION) -> dict:
    packets = capture_traffic(duration)
    dns_packets = capture_dns(packet_count=20)

    outbound = analyze_outbound_connections(packets)
    dns = analyze_dns(dns_packets)
    anomaly_score = calculate_anomaly_score(outbound, dns)

    return {
        "packets_captured": len(packets),
        "outbound_connections": outbound,
        "dns_analysis": dns,
        "anomaly_score": anomaly_score
    }