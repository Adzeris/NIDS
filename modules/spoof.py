#!/usr/bin/env python3
"""
Spoof detector v3.0.

Signals:
  - ARP mapping change + ARP reply burst
  - Bogon source check
  - TTL anomaly (statistical)
  - Name-service spoof (LLMNR/mDNS/NBNS response abuse)
  - Rogue DHCP OFFER/ACK
  - DNS spoof (unsolicited + conflicting answers)
"""

from scapy.all import sniff, ARP, IP, Ether, srp, UDP, DNS, DNSRR, BOOTP, DHCP
import time
import ipaddress
from collections import defaultdict, deque

from modules.detector_base import BaseDetector, z_score, rolling_stats, inter_arrival_times
from modules.firewall import ensure_chain, flush_chain, block_ip, block_mac
from modules.host_network import (
    get_interface_ip,
    get_local_network,
    get_default_gateway,
    collect_trusted_infrastructure_ips,
)
from modules import arpnft
from modules.detected_mac_persist import persist as persist_detected_mac


class SpoofDetector(BaseDetector):

    NAME = 'spoof'
    VERSION = '3.0'
    CHAIN = 'NIDS_SPOOF'

    STANDARD_TTLS = {32, 64, 128, 255}
    NAME_SERVICE_PORTS = {5355: 'LLMNR', 5353: 'mDNS', 137: 'NBNS'}
    DHCP_MSG_NAMES = {1: 'discover', 2: 'offer', 3: 'request', 5: 'ack'}

    BOGON_NETS = [
        ipaddress.ip_network("127.0.0.0/8"),
        ipaddress.ip_network("192.0.0.0/24"),
        ipaddress.ip_network("192.0.2.0/24"),
        ipaddress.ip_network("198.18.0.0/15"),
        ipaddress.ip_network("198.51.100.0/24"),
        ipaddress.ip_network("203.0.113.0/24"),
        ipaddress.ip_network("240.0.0.0/4"),
    ]

    DHCP_SAFE = {
        ipaddress.ip_address("0.0.0.0"),
        ipaddress.ip_address("255.255.255.255"),
        ipaddress.ip_address("169.254.169.254"),
    }

    def __init__(self, cfg, stop_event, log_callback=None):
        super().__init__(cfg, stop_event, log_callback)

        self._defense_ip = None
        self._local_net = None
        self._gateway_ip = None
        self._gateway_mac = None
        self._safe_ips = set()
        self._trusted_dhcp_servers = set()
        self._trusted_dhcp_macs = set()
        self._trusted_dns_servers = set()
        self._trusted_name_servers = set()
        self._trusted_routers = set()
        self._start_time = None

        self.arp_table = {}
        self.arp_cooldowns = {}
        self.arp_reply_times = defaultdict(deque)
        self.arp_claimed_ips = defaultdict(deque)
        self.arp_target_ips = defaultdict(deque)
        self.arp_burst_cooldowns = {}

        self.ttl_history = defaultdict(lambda: deque(maxlen=200))
        self.ttl_alert_cooldowns = {}
        self.ttl_alert_counts = defaultdict(int)

        self.name_query_times = defaultdict(deque)
        self.name_response_times = defaultdict(deque)
        self.name_claims = defaultdict(deque)
        self.name_alert_cooldowns = {}

        self.dhcp_offer_times = defaultdict(deque)
        self.dhcp_alert_cooldowns = {}

        self.dns_query_times = defaultdict(deque)
        self.dns_response_history = defaultdict(deque)
        self.dns_source_times = defaultdict(deque)
        self.dns_alert_cooldowns = {}

        self.blocked_ips = set()
        self.blocked_macs = set()
        self.stats = {
            'arp_packets': 0,
            'ip_packets': 0,
            'name_responses': 0,
            'dhcp_offers': 0,
            'dns_responses': 0,
            'blocks': 0,
        }

    # -- generic helpers ---------------------------------------------------

    @staticmethod
    def _nearest_initial_ttl(ttl):
        for init in sorted(SpoofDetector.STANDARD_TTLS):
            if ttl <= init:
                return init
        return 255

    @staticmethod
    def _prune_times(dq, now, window):
        while dq and (now - dq[0]) > window:
            dq.popleft()

    @staticmethod
    def _prune_records(dq, now, window):
        while dq and (now - dq[0][0]) > window:
            dq.popleft()

    @staticmethod
    def _clean_qname(qname):
        if qname is None:
            return None
        if isinstance(qname, bytes):
            qname = qname.decode(errors='ignore')
        return str(qname).strip().rstrip('.').lower() or None

    @staticmethod
    def _dhcp_msg_type(raw_value):
        if raw_value is None:
            return None
        if isinstance(raw_value, int):
            return raw_value
        if isinstance(raw_value, bytes):
            raw_value = raw_value.decode(errors='ignore')
        raw = str(raw_value).strip().lower()
        mapping = {
            'discover': 1, 'offer': 2, 'request': 3,
            'decline': 4, 'ack': 5, 'nak': 6,
            'release': 7, 'inform': 8,
        }
        return mapping.get(raw)

    @staticmethod
    def _extract_dhcp_option(options, name):
        for opt in options:
            if isinstance(opt, tuple) and len(opt) >= 2 and opt[0] == name:
                return opt[1]
        return None

    @staticmethod
    def _as_ip_set(raw_value):
        if raw_value is None:
            return set()
        if isinstance(raw_value, (list, tuple)):
            return {str(x).strip() for x in raw_value if str(x).strip()}
        text = str(raw_value).strip()
        return {text} if text else set()

    def _dns_answer_ips(self, dns_layer):
        answers = []
        rr = dns_layer.an
        for _ in range(int(dns_layer.ancount or 0)):
            if not isinstance(rr, DNSRR):
                break
            if rr.type == 1 and rr.rdata is not None:
                answers.append(str(rr.rdata))
            rr = rr.payload
        return sorted(set(answers))

    def _dns_qname(self, dns_layer):
        try:
            if dns_layer.qd is None:
                return None
            return self._clean_qname(dns_layer.qd.qname)
        except Exception:
            return None

    def _classify_bogon(self, addr):
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            return None
        if ip in self.DHCP_SAFE or addr in self._safe_ips:
            return 'safe'
        if any(ip in net for net in self.BOGON_NETS):
            return 'block'
        return None

    def _track_query(self, store, key, now):
        dq = store[key]
        dq.append(now)

    def _recent_query_exists(self, store, key, now, grace_sec):
        dq = store[key]
        self._prune_times(dq, now, grace_sec)
        if dq:
            dq.popleft()
            return True
        return False

    def _is_safe_ip(self, ip):
        return bool(ip and ip in self._safe_ips)

    def _is_trusted_mac(self, mac):
        return bool(mac and (mac == self._gateway_mac or mac in self._trusted_dhcp_macs))

    # -- ARP signals -------------------------------------------------------

    def _handle_arp_mapping_change(self, src_ip, src_mac, now):
        sp_cfg = self.cfg['spoof']
        cooldown = sp_cfg.get('arp_alert_cooldown', 60)

        if src_ip in self.arp_table and self.arp_table[src_ip] != src_mac:
            old_mac = self.arp_table[src_ip]
            key = f"{src_ip}:{src_mac}"
            if key in self.arp_cooldowns and (now - self.arp_cooldowns[key]) <= cooldown:
                return False

            feat = {
                'signal': 'arp_change',
                'ip': src_ip,
                'old_mac': old_mac,
                'new_mac': src_mac,
            }
            self.alert(
                message=f"ARP mapping changed for {src_ip}: {old_mac} -> {src_mac}",
                source_ip=src_ip,
                source_mac=src_mac,
                confidence=0.92,
                features=feat,
            )
            self.arp_cooldowns[key] = now

            if src_mac not in self.blocked_macs:
                block_mac(self.CHAIN, src_mac)
                self.blocked_macs.add(src_mac)
                if arpnft.arp_block_mac(src_mac, self.cfg['interface']):
                    self._emit(f"[BLOCK] Blocked {src_ip} / {src_mac} via iptables+nft")
                else:
                    self._emit(f"[BLOCK] Blocked {src_ip} / {src_mac} via iptables")
                self.stats['blocks'] += 1

            persist_detected_mac(src_mac, src_ip, lambda m: self._emit(m))
            return True
        return False

    def _handle_arp_burst(self, src_ip, src_mac, dst_ip, now):
        sp_cfg = self.cfg['spoof']
        if not sp_cfg.get('arp_burst_watch', True):
            return
        if src_mac in self.blocked_macs:
            return
        if self._is_trusted_mac(src_mac):
            return

        window = sp_cfg.get('arp_burst_window_sec', 10)
        threshold = sp_cfg.get('arp_burst_threshold', 12)
        cooldown = sp_cfg.get('arp_burst_cooldown', 30)
        key = src_mac

        self.arp_reply_times[key].append(now)
        self._prune_times(self.arp_reply_times[key], now, window)

        self.arp_claimed_ips[key].append((now, src_ip))
        self._prune_records(self.arp_claimed_ips[key], now, window)

        self.arp_target_ips[key].append((now, dst_ip))
        self._prune_records(self.arp_target_ips[key], now, window)

        if key in self.arp_burst_cooldowns and (now - self.arp_burst_cooldowns[key]) <= cooldown:
            return

        count = len(self.arp_reply_times[key])
        unique_claimed = len({rec[1] for rec in self.arp_claimed_ips[key]})
        unique_targets = len({rec[1] for rec in self.arp_target_ips[key] if rec[1]})
        iats = inter_arrival_times(list(self.arp_reply_times[key]))
        mean_iat, std_iat = rolling_stats(iats) if len(iats) >= 2 else (0.0, 0.0)
        cv_iat = std_iat / mean_iat if mean_iat > 0 else 9.0

        threshold_hit = count >= threshold
        adaptive_hit = (
            count >= max(4, threshold // 2)
            and (unique_claimed >= 2 or unique_targets >= 2 or cv_iat < 0.35)
        )
        triggered = threshold_hit or adaptive_hit
        if not triggered:
            return

        c_count = min(1.0, count / max(threshold, 1))
        c_variety = min(1.0, (unique_claimed + unique_targets) / 6.0)
        c_timing = max(0.0, 1.0 - min(cv_iat, 1.0))
        confidence = 0.55 * c_count + 0.25 * c_variety + 0.20 * c_timing

        feat = {
            'signal': 'arp_burst',
            'reply_count': count,
            'window_sec': window,
            'unique_claimed_ips': unique_claimed,
            'unique_targets': unique_targets,
            'mean_iat': round(mean_iat, 4),
            'cv_iat': round(cv_iat, 4),
        }
        self.alert(
            message=f"ARP reply burst from {src_ip} / {src_mac} ({count} replies in {window}s)",
            source_ip=src_ip,
            source_mac=src_mac,
            confidence=min(1.0, round(confidence, 4)),
            features=feat,
        )
        self.arp_burst_cooldowns[key] = now

        block_mac(self.CHAIN, src_mac)
        self.blocked_macs.add(src_mac)
        if arpnft.arp_block_mac(src_mac, self.cfg['interface']):
            self._emit(f"[BLOCK] Blocked {src_ip} / {src_mac} via iptables+nft")
        else:
            self._emit(f"[BLOCK] Blocked {src_ip} / {src_mac} via iptables")

        if src_ip and not self._is_safe_ip(src_ip):
            blocked = self.block(
                target=src_ip,
                reason="arp reply burst",
                source_ip=src_ip,
                source_mac=src_mac,
                confidence=min(1.0, round(confidence, 4)),
                features=feat,
                do_block_fn=lambda: block_ip(self.CHAIN, src_ip),
            )
            if blocked:
                self.blocked_ips.add(src_ip)

        self.stats['blocks'] += 1
        persist_detected_mac(src_mac, src_ip, lambda m: self._emit(m))

    def _handle_arp(self, pkt):
        if pkt[ARP].op != 2:
            return

        src_ip = pkt[ARP].psrc
        src_mac = pkt[Ether].src.upper()
        dst_ip = pkt[ARP].pdst
        now = time.time()

        if src_ip == self._defense_ip or src_mac in self.blocked_macs:
            return

        sp_cfg = self.cfg['spoof']
        if sp_cfg.get('arp_watch', True):
            blocked_now = self._handle_arp_mapping_change(src_ip, src_mac, now)
            if blocked_now:
                self.arp_table[src_ip] = src_mac
                return

        self._handle_arp_burst(src_ip, src_mac, dst_ip, now)
        self.arp_table[src_ip] = src_mac

    # -- TTL + bogon signal ------------------------------------------------

    def _handle_ttl_and_bogon(self, pkt):
        src = pkt[IP].src
        now = time.time()

        if src == self._defense_ip or src in self.blocked_ips or src in self._safe_ips:
            return

        bogon = self._classify_bogon(src)
        if bogon == 'safe':
            return
        if bogon == 'block':
            feat = {'signal': 'bogon', 'source_ip': src}
            self.alert(message=f"Bogon/reserved IP detected: {src}", source_ip=src, confidence=0.95, features=feat)
            blocked = self.block(
                target=src,
                reason="bogon address",
                source_ip=src,
                confidence=0.95,
                features=feat,
                do_block_fn=lambda: block_ip(self.CHAIN, src),
            )
            if blocked:
                self.blocked_ips.add(src)
                self.stats['blocks'] += 1
            return

        sp_cfg = self.cfg['spoof']
        if sp_cfg.get('ttl_local_only', True) and self._local_net:
            try:
                if ipaddress.ip_address(src) not in self._local_net:
                    return
            except ValueError:
                return

        ttl = pkt[IP].ttl
        if ttl <= 1 or ttl == 255:
            return

        init_ttl = self._nearest_initial_ttl(ttl)
        self.ttl_history[src].append(init_ttl)
        history = self.ttl_history[src]
        min_samples = sp_cfg.get('ttl_min_samples', 20)
        if len(history) < min_samples:
            return

        max_alerts = sp_cfg.get('ttl_max_alerts_per_source', 3)
        if self.ttl_alert_counts[src] >= max_alerts:
            return

        cooldown = sp_cfg.get('ttl_alert_cooldown', 120)
        if src in self.ttl_alert_cooldowns and (now - self.ttl_alert_cooldowns[src]) <= cooldown:
            return

        ttl_vals = list(history)
        mean_ttl, std_ttl = rolling_stats(ttl_vals)
        z = z_score(init_ttl, mean_ttl, std_ttl)
        anomaly = z > sp_cfg.get('ttl_z_threshold', 2.5)

        if not anomaly:
            return

        self.ttl_alert_counts[src] += 1
        self.ttl_alert_cooldowns[src] = now
        suppress = " (alerts capped for this source)" if self.ttl_alert_counts[src] >= max_alerts else ""

        feat = {
            'signal': 'ttl_anomaly',
            'observed_ttl': ttl,
            'initial_ttl': init_ttl,
            'ttl_mean': round(mean_ttl, 2),
            'ttl_std': round(std_ttl, 2),
            'z_score': round(z, 4),
            'history_len': len(history),
        }
        confidence = min(1.0, z / 5.0) if z > 0 else 0.3
        self.alert(
            message=(
                f"TTL anomaly from {src}: ttl={ttl}, init={init_ttl}, "
                f"mean={mean_ttl:.1f}, z={z:.2f}{suppress}"
            ),
            source_ip=src,
            confidence=confidence,
            features=feat,
        )

    # -- name service spoof (LLMNR/mDNS/NBNS) -----------------------------

    def _track_name_query(self, pkt, src_ip, dport, now):
        if DNS not in pkt:
            return
        dns = pkt[DNS]
        if dns.qr != 0:
            return
        qname = self._dns_qname(dns)
        if not qname:
            return
        service = self.NAME_SERVICE_PORTS.get(dport, str(dport))
        key = (service, src_ip, qname)
        self._track_query(self.name_query_times, key, now)

    def _handle_name_response(self, pkt, src_ip, dst_ip, src_mac, sport, now):
        sp_cfg = self.cfg['spoof']
        if not sp_cfg.get('name_spoof_watch', True):
            return
        if src_ip in self.blocked_ips or src_mac in self.blocked_macs:
            return
        if src_ip in self._trusted_name_servers:
            return

        service = self.NAME_SERVICE_PORTS.get(sport, str(sport))
        window = sp_cfg.get('name_window_sec', 12)
        threshold = sp_cfg.get('name_response_threshold', 8)
        query_grace = sp_cfg.get('name_query_grace_sec', 3)
        conflict_window = sp_cfg.get('name_conflict_window_sec', 20)
        cooldown = sp_cfg.get('name_alert_cooldown', 60)

        source_key = (src_ip, service)
        self.name_response_times[source_key].append(now)
        self._prune_times(self.name_response_times[source_key], now, window)
        count = len(self.name_response_times[source_key])

        qname = None
        answer_ips = []
        expected_query = False
        conflicting_claim = False
        unsolicited = False

        if DNS in pkt:
            dns = pkt[DNS]
            qname = self._dns_qname(dns)
            answer_ips = self._dns_answer_ips(dns)
            if qname:
                query_key = (service, dst_ip, qname)
                expected_query = self._recent_query_exists(
                    self.name_query_times, query_key, now, query_grace)
                unsolicited = not expected_query

                claims_key = (service, qname)
                self._prune_records(self.name_claims[claims_key], now, conflict_window)
                prev_ips = {rec[2] for rec in self.name_claims[claims_key]}
                prev_srcs = {rec[1] for rec in self.name_claims[claims_key]}

                for ip in answer_ips or ['<empty>']:
                    self.name_claims[claims_key].append((now, src_ip, ip))

                new_ips = set(answer_ips or ['<empty>'])
                if prev_ips and new_ips != prev_ips:
                    conflicting_claim = True
                if prev_srcs and src_ip not in prev_srcs:
                    conflicting_claim = True

        cooldown_key = (src_ip, service)
        if cooldown_key in self.name_alert_cooldowns and (now - self.name_alert_cooldowns[cooldown_key]) <= cooldown:
            return

        threshold_hit = count >= threshold
        adaptive_hit = count >= max(3, threshold // 2) and (unsolicited or conflicting_claim)
        triggered = threshold_hit or adaptive_hit
        if not triggered:
            return

        c_count = min(1.0, count / max(threshold, 1))
        c_uns = 1.0 if unsolicited else 0.0
        c_conf = 1.0 if conflicting_claim else 0.0
        confidence = 0.50 * c_count + 0.25 * c_uns + 0.25 * c_conf

        feat = {
            'signal': 'name_spoof',
            'service': service,
            'response_count': count,
            'window_sec': window,
            'unsolicited': unsolicited,
            'conflicting_claim': conflicting_claim,
            'qname': qname,
            'answers': answer_ips,
        }
        qtag = f" {qname}" if qname else ""
        self.alert(
            message=f"{service} spoof response from {src_ip} / {src_mac}{qtag}",
            source_ip=src_ip,
            source_mac=src_mac,
            confidence=min(1.0, round(confidence, 4)),
            features=feat,
        )
        self.name_alert_cooldowns[cooldown_key] = now
        self.stats['name_responses'] += 1

        if src_mac not in self.blocked_macs:
            block_mac(self.CHAIN, src_mac)
            self.blocked_macs.add(src_mac)
            if arpnft.arp_block_mac(src_mac, self.cfg['interface']):
                self._emit(f"[BLOCK] Blocked {src_ip} / {src_mac} via iptables+nft")
            else:
                self._emit(f"[BLOCK] Blocked {src_ip} / {src_mac} via iptables")
            self.stats['blocks'] += 1

        if src_ip and not self._is_safe_ip(src_ip):
            blocked = self.block(
                target=src_ip,
                reason=f"{service} spoof responses",
                source_ip=src_ip,
                source_mac=src_mac,
                confidence=min(1.0, round(confidence, 4)),
                features=feat,
                do_block_fn=lambda: block_ip(self.CHAIN, src_ip),
            )
            if blocked:
                self.blocked_ips.add(src_ip)

        persist_detected_mac(src_mac, src_ip, lambda m: self._emit(m))

    # -- rogue DHCP --------------------------------------------------------

    def _handle_dhcp(self, pkt, src_ip, src_mac, now):
        sp_cfg = self.cfg['spoof']
        if not sp_cfg.get('dhcp_watch', True):
            return
        if src_ip in self.blocked_ips or src_mac in self.blocked_macs:
            return
        if src_ip in self._trusted_dhcp_servers or src_mac in self._trusted_dhcp_macs:
            return

        if DHCP not in pkt:
            return
        msg_raw = self._extract_dhcp_option(pkt[DHCP].options, 'message-type')
        msg_type = self._dhcp_msg_type(msg_raw)
        if msg_type not in (2, 5):  # OFFER or ACK
            return

        window = sp_cfg.get('dhcp_window_sec', 20)
        threshold = sp_cfg.get('dhcp_offer_threshold', 2)
        cooldown = sp_cfg.get('dhcp_alert_cooldown', 60)
        key = (src_ip, src_mac)

        self.dhcp_offer_times[key].append(now)
        self._prune_times(self.dhcp_offer_times[key], now, window)
        count = len(self.dhcp_offer_times[key])

        router_opt = self._extract_dhcp_option(pkt[DHCP].options, 'router')
        routers = self._as_ip_set(router_opt)
        suspicious_router = any(r not in self._trusted_routers for r in routers) if routers else False

        if key in self.dhcp_alert_cooldowns and (now - self.dhcp_alert_cooldowns[key]) <= cooldown:
            return

        threshold_hit = count >= threshold
        adaptive_hit = (count >= max(1, threshold // 2)) and suspicious_router
        triggered = threshold_hit or adaptive_hit
        if not triggered:
            return

        c_count = min(1.0, count / max(threshold, 1))
        c_router = 1.0 if suspicious_router else 0.0
        confidence = 0.70 * c_count + 0.30 * c_router

        feat = {
            'signal': 'rogue_dhcp',
            'dhcp_message': self.DHCP_MSG_NAMES.get(msg_type, str(msg_type)),
            'offer_count': count,
            'window_sec': window,
            'routers': sorted(routers),
            'suspicious_router': suspicious_router,
        }
        self.alert(
            message=(
                f"Rogue DHCP {self.DHCP_MSG_NAMES.get(msg_type, msg_type)} "
                f"from {src_ip} / {src_mac}"
            ),
            source_ip=src_ip,
            source_mac=src_mac,
            confidence=min(1.0, round(confidence, 4)),
            features=feat,
        )
        self.dhcp_alert_cooldowns[key] = now
        self.stats['dhcp_offers'] += 1

        if src_mac not in self.blocked_macs:
            block_mac(self.CHAIN, src_mac)
            self.blocked_macs.add(src_mac)
            if arpnft.arp_block_mac(src_mac, self.cfg['interface']):
                self._emit(f"[BLOCK] Blocked {src_ip} / {src_mac} via iptables+nft")
            else:
                self._emit(f"[BLOCK] Blocked {src_ip} / {src_mac} via iptables")
            self.stats['blocks'] += 1

        if src_ip and not self._is_safe_ip(src_ip):
            blocked = self.block(
                target=src_ip,
                reason="rogue dhcp",
                source_ip=src_ip,
                source_mac=src_mac,
                confidence=min(1.0, round(confidence, 4)),
                features=feat,
                do_block_fn=lambda: block_ip(self.CHAIN, src_ip),
            )
            if blocked:
                self.blocked_ips.add(src_ip)

        persist_detected_mac(src_mac, src_ip, lambda m: self._emit(m))

    # -- DNS spoof ---------------------------------------------------------

    def _track_dns_query(self, pkt, src_ip, now):
        if DNS not in pkt:
            return
        dns = pkt[DNS]
        if dns.qr != 0:
            return
        qname = self._dns_qname(dns)
        if not qname:
            return
        key = (src_ip, int(dns.id), qname)
        self._track_query(self.dns_query_times, key, now)

    def _handle_dns_response(self, pkt, src_ip, dst_ip, now):
        sp_cfg = self.cfg['spoof']
        if not sp_cfg.get('dns_spoof_watch', True):
            return
        if src_ip in self.blocked_ips:
            return
        if src_ip in self._trusted_dns_servers:
            return
        if DNS not in pkt:
            return

        dns = pkt[DNS]
        if dns.qr != 1:
            return

        qname = self._dns_qname(dns)
        if not qname:
            return
        answers = self._dns_answer_ips(dns)

        query_grace = sp_cfg.get('dns_query_grace_sec', 4)
        key = (dst_ip, int(dns.id), qname)
        expected_query = self._recent_query_exists(self.dns_query_times, key, now, query_grace)

        conflict_window = sp_cfg.get('dns_conflict_window_sec', 6)
        hist = self.dns_response_history[key]
        self._prune_records(hist, now, conflict_window)

        answer_sig = tuple(answers)
        conflict = any((prev_src != src_ip or prev_sig != answer_sig) for _, prev_src, prev_sig in hist)
        hist.append((now, src_ip, answer_sig))

        window = sp_cfg.get('dns_window_sec', 20)
        threshold = sp_cfg.get('dns_unsolicited_threshold', 5)
        cooldown = sp_cfg.get('dns_alert_cooldown', 60)

        self.dns_source_times[src_ip].append(now)
        self._prune_times(self.dns_source_times[src_ip], now, window)
        src_count = len(self.dns_source_times[src_ip])
        unsolicited = not expected_query
        unexpected_source = bool(self._trusted_dns_servers and src_ip not in self._trusted_dns_servers)

        if src_ip in self.dns_alert_cooldowns and (now - self.dns_alert_cooldowns[src_ip]) <= cooldown:
            return

        threshold_hit = unsolicited and src_count >= threshold
        adaptive_hit = conflict or unexpected_source or (unsolicited and src_count >= max(2, threshold // 2))
        triggered = threshold_hit or adaptive_hit
        if not triggered:
            return

        c_count = min(1.0, src_count / max(threshold, 1))
        c_uns = 1.0 if unsolicited else 0.0
        c_conf = 1.0 if conflict else 0.0
        c_src = 1.0 if unexpected_source else 0.0
        confidence = 0.40 * c_count + 0.25 * c_uns + 0.25 * c_conf + 0.10 * c_src

        feat = {
            'signal': 'dns_spoof',
            'query': qname,
            'transaction_id': int(dns.id),
            'answers': answers,
            'unsolicited': unsolicited,
            'conflict': conflict,
            'unexpected_source': unexpected_source,
            'response_count': src_count,
            'window_sec': window,
        }
        self.alert(
            message=f"DNS spoof response from {src_ip} for {qname}",
            source_ip=src_ip,
            confidence=min(1.0, round(confidence, 4)),
            features=feat,
        )
        self.dns_alert_cooldowns[src_ip] = now
        self.stats['dns_responses'] += 1

        if src_ip and not self._is_safe_ip(src_ip):
            blocked = self.block(
                target=src_ip,
                reason="dns spoof-like response",
                source_ip=src_ip,
                confidence=min(1.0, round(confidence, 4)),
                features=feat,
                do_block_fn=lambda: block_ip(self.CHAIN, src_ip),
            )
            if blocked:
                self.blocked_ips.add(src_ip)
                self.stats['blocks'] += 1

    # -- packet callback ---------------------------------------------------

    def _handle_udp_signals(self, pkt, src_ip, dst_ip, src_mac, now):
        udp = pkt[UDP]
        sport = int(udp.sport)
        dport = int(udp.dport)

        # Name-service query/response tracking.
        if dport in self.NAME_SERVICE_PORTS:
            self._track_name_query(pkt, src_ip, dport, now)
        if sport in self.NAME_SERVICE_PORTS:
            self._handle_name_response(pkt, src_ip, dst_ip, src_mac, sport, now)

        # DHCP server packets.
        if sport == 67 and dport == 68 and BOOTP in pkt and DHCP in pkt:
            self._handle_dhcp(pkt, src_ip, src_mac, now)

        # DNS query/response tracking.
        if dport == 53 and DNS in pkt:
            self._track_dns_query(pkt, src_ip, now)
        if sport == 53 and DNS in pkt:
            self._handle_dns_response(pkt, src_ip, dst_ip, now)

    def _on_packet(self, pkt):
        now = time.time()
        if now - self._start_time < 1:
            return

        if pkt.haslayer(ARP):
            self.stats['arp_packets'] += 1
            self._handle_arp(pkt)

        if pkt.haslayer(IP):
            self.stats['ip_packets'] += 1
            self._handle_ttl_and_bogon(pkt)
            if pkt.haslayer(UDP):
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
                src_mac = pkt[Ether].src.upper() if pkt.haslayer(Ether) else "unknown"
                self._handle_udp_signals(pkt, src_ip, dst_ip, src_mac, now)

    # -- lifecycle ---------------------------------------------------------

    def reset_state(self):
        self.arp_table.clear()
        if self._gateway_ip and self._gateway_mac:
            self.arp_table[self._gateway_ip] = self._gateway_mac
        self.arp_cooldowns.clear()
        self.arp_reply_times.clear()
        self.arp_claimed_ips.clear()
        self.arp_target_ips.clear()
        self.arp_burst_cooldowns.clear()

        self.ttl_history.clear()
        self.ttl_alert_cooldowns.clear()
        self.ttl_alert_counts.clear()

        self.name_query_times.clear()
        self.name_response_times.clear()
        self.name_claims.clear()
        self.name_alert_cooldowns.clear()

        self.dhcp_offer_times.clear()
        self.dhcp_alert_cooldowns.clear()

        self.dns_query_times.clear()
        self.dns_response_history.clear()
        self.dns_source_times.clear()
        self.dns_alert_cooldowns.clear()

        self.blocked_ips.clear()
        self.blocked_macs.clear()

        for k in self.stats:
            self.stats[k] = 0

    def _load_trust_sets(self):
        sp_cfg = self.cfg['spoof']
        self._trusted_dhcp_servers = {ip.strip() for ip in sp_cfg.get('trusted_dhcp_servers', []) if ip.strip()}
        self._trusted_dhcp_macs = {mac.strip().upper() for mac in sp_cfg.get('trusted_dhcp_macs', []) if mac.strip()}
        self._trusted_dns_servers = {ip.strip() for ip in sp_cfg.get('trusted_dns_servers', []) if ip.strip()}
        self._trusted_name_servers = {ip.strip() for ip in sp_cfg.get('trusted_name_servers', []) if ip.strip()}
        self._trusted_routers = {ip.strip() for ip in sp_cfg.get('trusted_routers', []) if ip.strip()}
        if self._gateway_ip:
            self._trusted_routers.add(self._gateway_ip)
        _trust_gw = sp_cfg.get(
            'whitelist_default_gateway', sp_cfg.get('gateway_auto_whitelist', True))
        if self._gateway_ip and _trust_gw:
            self._trusted_dhcp_servers.add(self._gateway_ip)
            self._trusted_dns_servers.add(self._gateway_ip)

    def run(self):
        cfg = self.cfg
        iface = cfg['interface']
        self._defense_ip = get_interface_ip(iface)
        self._local_net = get_local_network(iface)
        self._gateway_ip = get_default_gateway(iface)
        self._start_time = time.time()

        self._safe_ips = collect_trusted_infrastructure_ips(cfg, iface)

        if self._gateway_ip:
            try:
                ans, _ = srp(
                    Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=self._gateway_ip),
                    iface=iface,
                    timeout=2,
                    verbose=False,
                )
                for _, rcv in ans:
                    self._gateway_mac = rcv[Ether].src.upper()
                    self.arp_table[self._gateway_ip] = self._gateway_mac
                    self.info(f"Gateway: IP={self._gateway_ip} MAC={self._gateway_mac}")
                    break
            except Exception:
                self._gateway_mac = None

        self._load_trust_sets()
        self.reset_state()

        ensure_chain(self.CHAIN)
        flush_chain(self.CHAIN)

        self._emit(
            f"[START] Spoof detector v{self.VERSION} on {iface} "
            f"(IP: {self._defense_ip})"
        )

        try:
            while not self.stop_event.is_set():
                sniff(
                    iface=iface,
                    prn=self._on_packet,
                    store=False,
                    filter="arp or ip",
                    timeout=2,
                    stop_filter=lambda _: self.stop_event.is_set(),
                )
        finally:
            flush_chain(self.CHAIN)
            arpnft.arp_flush_blocked()
            self._emit("[STOP] Spoof detector stopped")


# ---------------------------------------------------------------------------
# Module-level compatibility
# ---------------------------------------------------------------------------
_callback = None
stats = {
    "arp_packets": 0,
    "ip_packets": 0,
    "name_responses": 0,
    "dhcp_offers": 0,
    "dns_responses": 0,
    "blocks": 0,
}


def set_callback(fn):
    global _callback
    _callback = fn


def run_detector(cfg, stop_event=None):
    import threading
    det = SpoofDetector(cfg, stop_event or threading.Event(), _callback)
    det.run()
    stats.update(det.stats)


if __name__ == "__main__":
    import sys
    import os
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from config import load_config
    run_detector(load_config())
