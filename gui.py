#!/usr/bin/env python3
"""
NIDS GUI — PyQt5 desktop application.
Run with:  sudo python3 gui.py
"""

import sys
import os
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QTabWidget, QTextEdit, QPushButton, QLabel, QLineEdit,
    QCheckBox, QGroupBox, QFormLayout, QComboBox, QSpinBox,
    QPlainTextEdit, QFrame, QMessageBox, QListWidget,
    QListWidgetItem, QInputDialog, QStatusBar, QAction, QMenuBar,
    QScrollArea, QToolButton,
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer, QPointF
from PyQt5.QtGui import QFont, QColor, QTextCharFormat, QIcon, QPalette, QPainter, QPen, QBrush

from config import load_config, save_config
from engine import NIDSEngine

APP_VERSION = "2.1.1"

_MAC_MODE_UI_TO_CFG = {"Allow Only": "whitelist", "Block Only": "blacklist"}
_MAC_MODE_CFG_TO_UI = {v: k for k, v in _MAC_MODE_UI_TO_CFG.items()}


# ---------------------------------------------------------------------------
# Worker thread that bridges the engine to the Qt event loop
# ---------------------------------------------------------------------------

class EngineWorker(QThread):
    log_signal = pyqtSignal(str)
    stopped_signal = pyqtSignal()

    def __init__(self, cfg):
        super().__init__()
        self.cfg = cfg
        self.engine = None

    def run(self):
        self.engine = NIDSEngine(cfg=self.cfg, log_callback=self._on_log)
        self.engine.start()

        while self.engine.is_running():
            self.msleep(500)

        self.stopped_signal.emit()

    def _on_log(self, msg):
        self.log_signal.emit(msg)

    def stop_engine(self):
        if self.engine:
            self.engine.stop()


class ClickFocusSpinBox(QSpinBox):
    """Ignore mouse-wheel changes unless the field already has focus."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.setFocusPolicy(Qt.StrongFocus)

    def wheelEvent(self, event):
        if self.hasFocus():
            super().wheelEvent(event)
        else:
            event.ignore()


class EventRateWidget(QWidget):
    """Lightweight bar chart showing events-per-second over a rolling window."""

    def __init__(self, window_sec=60, parent=None):
        super().__init__(parent)
        self._window = window_sec
        self._buckets = [0] * window_sec
        self._peak = 1
        self.setFixedHeight(48)
        self.setMinimumWidth(200)

        self._timer = QTimer(self)
        self._timer.timeout.connect(self._tick)
        self._timer.start(1000)

    def record_event(self):
        self._buckets[-1] += 1

    def _tick(self):
        self._buckets.append(0)
        if len(self._buckets) > self._window:
            self._buckets = self._buckets[-self._window:]
        m = max(self._buckets) if self._buckets else 1
        self._peak = max(m, 1)
        self.update()

    def paintEvent(self, event):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        w, h = self.width(), self.height()
        p.fillRect(0, 0, w, h, QColor("#010409"))

        n = len(self._buckets)
        if n == 0:
            p.end()
            return

        bar_w = max(w / n, 1)
        for i, val in enumerate(self._buckets):
            ratio = val / self._peak
            bar_h = max(int(ratio * (h - 14)), 1) if val > 0 else 0
            x = int(i * bar_w)
            color = QColor("#39d353") if val < self._peak * 0.7 else QColor("#f0883e") if val < self._peak * 0.9 else QColor("#da3633")
            p.fillRect(x, h - bar_h, max(int(bar_w) - 1, 1), bar_h, color)

        current = self._buckets[-1] if self._buckets else 0
        p.setPen(QColor("#8b949e"))
        p.setFont(QFont("sans-serif", 8))
        p.drawText(4, 10, f"Events/sec: {current}  peak: {self._peak}")
        p.end()


# ---------------------------------------------------------------------------
# Stylesheet
# ---------------------------------------------------------------------------

DARK_STYLE = """
QMainWindow, QWidget {
    background-color: #0a0e14;
    color: #c9d1d9;
}
QTabWidget::pane {
    border: 1px solid #1a2332;
    background: #0a0e14;
}
QTabBar::tab {
    background: #0d1117;
    color: #8b949e;
    padding: 8px 20px;
    margin-right: 2px;
    border-top-left-radius: 6px;
    border-top-right-radius: 6px;
    border: 1px solid #1a2332;
    border-bottom: none;
}
QTabBar::tab:selected {
    background: #161b22;
    color: #00e5ff;
    border-bottom: 2px solid #00e5ff;
}
QGroupBox {
    border: 1px solid #1a2332;
    border-radius: 8px;
    margin-top: 12px;
    padding-top: 18px;
    font-weight: bold;
    color: #58a6ff;
}
QGroupBox::title {
    subcontrol-origin: margin;
    left: 14px;
    padding: 0 6px;
}
QPushButton {
    background-color: #161b22;
    color: #c9d1d9;
    border: 1px solid #30363d;
    border-radius: 6px;
    padding: 8px 18px;
    font-weight: bold;
}
QPushButton:hover {
    background-color: #1f2937;
    border-color: #58a6ff;
}
QPushButton#startBtn {
    background-color: #238636;
    color: #ffffff;
    border: none;
}
QPushButton#startBtn:hover {
    background-color: #2ea043;
}
QPushButton#stopBtn {
    background-color: #b62324;
    color: #ffffff;
    border: none;
}
QPushButton#stopBtn:hover {
    background-color: #da3633;
}
QPushButton#flushBtn {
    background-color: #1a5276;
    color: #ffffff;
    border: none;
}
QPushButton#flushBtn:hover {
    background-color: #2471a3;
}
QPlainTextEdit, QTextEdit, QListWidget {
    background-color: #010409;
    color: #39d353;
    border: 1px solid #1a2332;
    border-radius: 6px;
    font-family: 'JetBrains Mono', 'Fira Code', 'Consolas', monospace;
    font-size: 12px;
    padding: 6px;
}
QLineEdit, QSpinBox, QComboBox {
    background-color: #0d1117;
    color: #c9d1d9;
    border: 1px solid #30363d;
    border-radius: 4px;
    padding: 6px 10px;
    min-width: 100px;
}
QLineEdit:focus, QSpinBox:focus, QComboBox:focus {
    border-color: #58a6ff;
}
QScrollArea {
    background: transparent;
    border: none;
}
QCheckBox {
    color: #c9d1d9;
    spacing: 8px;
}
QCheckBox::indicator {
    width: 18px;
    height: 18px;
    border-radius: 4px;
    border: 2px solid #30363d;
    background: #0d1117;
}
QCheckBox::indicator:checked {
    background: #00e5ff;
    border-color: #00e5ff;
}
QLabel {
    color: #c9d1d9;
}
QStatusBar {
    background: #010409;
    color: #8b949e;
}
QMenuBar {
    background: #010409;
    color: #c9d1d9;
}
QMenuBar::item:selected {
    background: #161b22;
}
"""


# ---------------------------------------------------------------------------
# Main Window
# ---------------------------------------------------------------------------

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.cfg = load_config()
        self.worker = None
        self._alert_count = 0
        self._block_count = 0
        self._dismissed_macs = set()

        self.setWindowTitle(f"Network Intrusion Detection System — v{APP_VERSION}")
        self.setMinimumSize(960, 640)
        self.setStyleSheet(DARK_STYLE)

        self._build_menubar()
        self._build_ui()
        self._build_statusbar()

        self._load_config_to_ui()

    # ---- Menu bar --------------------------------------------------------

    def _build_menubar(self):
        mb = self.menuBar()
        file_menu = mb.addMenu("&File")

        save_act = QAction("&Save Config", self)
        save_act.triggered.connect(self._save_config_from_ui)
        file_menu.addAction(save_act)

        reload_act = QAction("&Reload Config", self)
        reload_act.triggered.connect(self._reload_config)
        file_menu.addAction(reload_act)

        file_menu.addSeparator()
        quit_act = QAction("&Quit", self)
        quit_act.triggered.connect(self.close)
        file_menu.addAction(quit_act)

    # ---- Status bar ------------------------------------------------------

    def _build_statusbar(self):
        self.status_label = QLabel("  Idle")
        self.alert_label = QLabel("Alerts: 0")
        self.block_label = QLabel("Blocks: 0")
        sb = self.statusBar()
        sb.addWidget(self.status_label, 1)
        sb.addPermanentWidget(self.alert_label)
        sb.addPermanentWidget(self.block_label)

    # ---- Central UI ------------------------------------------------------

    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(12, 12, 12, 12)

        # Top bar: Start / Stop / Flush DNS + status
        top = QHBoxLayout()
        self.start_btn = QPushButton("Start NIDS")
        self.start_btn.setObjectName("startBtn")
        self.start_btn.clicked.connect(self._start)

        self.stop_btn = QPushButton("Stop NIDS")
        self.stop_btn.setObjectName("stopBtn")
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self._stop)

        self.unblock_btn = QPushButton("Unblock All")
        self.unblock_btn.setObjectName("flushBtn")
        self.unblock_btn.clicked.connect(self._unblock_all)

        self.running_label = QLabel("")
        self.running_label.setStyleSheet("color: #8b949e; font-style: italic;")

        top.addWidget(self.start_btn)
        top.addWidget(self.stop_btn)
        top.addWidget(self.unblock_btn)
        top.addStretch()
        top.addWidget(self.running_label)
        root.addLayout(top)

        # Tabs
        tabs = QTabWidget()
        tabs.addTab(self._build_live_tab(), "Live Monitor")
        tabs.addTab(self._build_config_tab(), "Configuration")
        tabs.addTab(self._build_mac_tab(), "MAC Filter")
        tabs.addTab(self._build_about_tab(), "About")
        root.addWidget(tabs)

    # ---- Tab: Live Monitor -----------------------------------------------

    def _build_live_tab(self):
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setSpacing(4)
        lay.setContentsMargins(0, 4, 0, 0)

        self.log_view = QTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.document().setMaximumBlockCount(5000)
        self.log_view.setMinimumHeight(320)
        lay.addWidget(self.log_view, stretch=1)

        self.blocks_grp = QGroupBox()
        blocks_lay = QVBoxLayout(self.blocks_grp)
        blocks_lay.setContentsMargins(8, 6, 8, 6)
        blocks_lay.setSpacing(4)
        blocks_title = QLabel("Active Blocks")
        blocks_title.setStyleSheet("font-weight: bold; font-size: 11px; color: #90caf9;")
        blocks_lay.addWidget(blocks_title)
        self.blocks_list = QListWidget()
        self.blocks_list.setFixedHeight(60)
        self.blocks_list.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.blocks_list.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        blocks_lay.addWidget(self.blocks_list)
        unblock_row = QHBoxLayout()
        unblock_row.setSpacing(8)
        unblock_sel_btn = QPushButton("Unblock")
        unblock_sel_btn.clicked.connect(self._unblock_selected)
        refresh_blocks_btn = QPushButton("Refresh")
        refresh_blocks_btn.clicked.connect(self._rebuild_blocks_from_firewall)
        unblock_sel_btn.setStyleSheet("padding: 4px 10px;")
        refresh_blocks_btn.setStyleSheet("padding: 4px 10px;")
        unblock_row.addWidget(unblock_sel_btn)
        unblock_row.addWidget(refresh_blocks_btn)
        unblock_row.addStretch()
        blocks_lay.addLayout(unblock_row)
        lay.addWidget(self.blocks_grp, stretch=0)

        btn_row = QHBoxLayout()
        btn_row.setSpacing(6)
        btn_row.setContentsMargins(0, 4, 0, 0)
        clear_btn = QPushButton("Clear Log")
        clear_btn.clicked.connect(self.log_view.clear)
        export_btn = QPushButton("Export Logs")
        export_btn.clicked.connect(self._export_logs)
        btn_row.addWidget(export_btn)
        btn_row.addStretch()
        btn_row.addWidget(clear_btn)
        lay.addLayout(btn_row)

        self._rebuild_blocks_from_firewall()

        return w

    # ---- Tab: Configuration ---------------------------------------------

    def _build_config_tab(self):
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)

        inner = QWidget()
        lay = QVBoxLayout(inner)
        lay.setSpacing(14)
        lay.setContentsMargins(16, 16, 16, 16)

        # Interface
        iface_grp = QGroupBox("Network Interface")
        iface_lay = QFormLayout(iface_grp)
        iface_lay.setVerticalSpacing(10)
        iface_lay.setContentsMargins(14, 20, 14, 14)
        self.iface_edit = QLineEdit()
        self.iface_edit.setMinimumHeight(30)
        iface_lay.addRow("Interface:", self.iface_edit)
        lay.addWidget(iface_grp)

        # Module toggles
        mod_grp = QGroupBox("Modules")
        mod_lay = QVBoxLayout(mod_grp)
        mod_lay.setSpacing(10)
        mod_lay.setContentsMargins(14, 20, 14, 14)
        self.chk_portscan = QCheckBox("Port Scan Detector")
        self.chk_bruteforce = QCheckBox("SSH Brute-Force Detector")
        self.chk_dos = QCheckBox("DoS / ICMP Flood Detector")
        self.chk_spoof = QCheckBox("IP Spoof Detector")
        self.chk_macfilter = QCheckBox("MAC Address Filter")
        for cb in [self.chk_portscan, self.chk_bruteforce, self.chk_dos,
                   self.chk_spoof, self.chk_macfilter]:
            mod_lay.addWidget(cb)
        lay.addWidget(mod_grp)

        advanced_grp = QGroupBox("Advanced Options")
        advanced_lay = QVBoxLayout(advanced_grp)
        advanced_lay.setSpacing(10)
        advanced_lay.setContentsMargins(14, 20, 14, 14)
        self.advanced_toggle = QToolButton()
        self.advanced_toggle.setText("Show Advanced Options")
        self.advanced_toggle.setCheckable(True)
        self.advanced_toggle.setChecked(False)
        self.advanced_toggle.setToolButtonStyle(Qt.ToolButtonTextBesideIcon)
        self.advanced_toggle.setArrowType(Qt.RightArrow)
        advanced_lay.addWidget(self.advanced_toggle)

        self.advanced_content = QWidget()
        advanced_content_lay = QVBoxLayout(self.advanced_content)
        advanced_content_lay.setSpacing(14)
        advanced_content_lay.setContentsMargins(0, 6, 0, 0)
        self.advanced_content.setVisible(False)

        def _toggle_advanced(checked):
            self.advanced_toggle.setText("Hide Advanced Options" if checked else "Show Advanced Options")
            self.advanced_toggle.setArrowType(Qt.DownArrow if checked else Qt.RightArrow)
            self.advanced_content.setVisible(checked)

        self.advanced_toggle.toggled.connect(_toggle_advanced)
        advanced_lay.addWidget(self.advanced_content)

        # Port Scan thresholds
        ps_grp = QGroupBox("Port Scan Thresholds")
        ps_lay = QFormLayout(ps_grp)
        ps_lay.setVerticalSpacing(12)
        ps_lay.setHorizontalSpacing(20)
        ps_lay.setContentsMargins(14, 20, 14, 14)

        self.spin_ps_ports = ClickFocusSpinBox(); self.spin_ps_ports.setRange(1, 9999)
        self.spin_ps_syns = ClickFocusSpinBox(); self.spin_ps_syns.setRange(1, 9999)
        self.spin_ps_window = ClickFocusSpinBox(); self.spin_ps_window.setRange(1, 300)
        self.spin_ps_slow_ports = ClickFocusSpinBox(); self.spin_ps_slow_ports.setRange(1, 9999)
        self.spin_ps_slow_syns = ClickFocusSpinBox(); self.spin_ps_slow_syns.setRange(1, 9999)
        self.spin_ps_slow_window = ClickFocusSpinBox(); self.spin_ps_slow_window.setRange(5, 3600)
        self.spin_ps_block = ClickFocusSpinBox(); self.spin_ps_block.setRange(1, 9999)
        for sp in [
            self.spin_ps_ports,
            self.spin_ps_syns,
            self.spin_ps_window,
            self.spin_ps_slow_ports,
            self.spin_ps_slow_syns,
            self.spin_ps_slow_window,
            self.spin_ps_block,
        ]:
            sp.setMinimumHeight(30)
        ps_lay.addRow("Unique ports:", self.spin_ps_ports)
        ps_lay.addRow("SYN count:", self.spin_ps_syns)
        ps_lay.addRow("Window (sec):", self.spin_ps_window)
        ps_lay.addRow("Slow unique ports:", self.spin_ps_slow_ports)
        ps_lay.addRow("Slow SYN count:", self.spin_ps_slow_syns)
        ps_lay.addRow("Slow window (sec):", self.spin_ps_slow_window)

        udp_sep = QLabel("UDP Scan Detection")
        udp_sep.setStyleSheet("color: #58a6ff; font-weight: bold; margin-top: 8px;")
        ps_lay.addRow(udp_sep)
        self.spin_ps_udp_ports = ClickFocusSpinBox(); self.spin_ps_udp_ports.setRange(1, 9999)
        self.spin_ps_udp_probes = ClickFocusSpinBox(); self.spin_ps_udp_probes.setRange(1, 9999)
        self.spin_ps_udp_window = ClickFocusSpinBox(); self.spin_ps_udp_window.setRange(1, 600)
        for sp in [self.spin_ps_udp_ports, self.spin_ps_udp_probes, self.spin_ps_udp_window]:
            sp.setMinimumHeight(30)
        ps_lay.addRow("UDP unique ports:", self.spin_ps_udp_ports)
        ps_lay.addRow("UDP probe count:", self.spin_ps_udp_probes)
        ps_lay.addRow("UDP window (sec):", self.spin_ps_udp_window)

        ps_lay.addRow("Block duration (sec):", self.spin_ps_block)
        advanced_content_lay.addWidget(ps_grp)

        # Brute-force thresholds
        bf_grp = QGroupBox("Brute-Force Thresholds")
        bf_lay = QFormLayout(bf_grp)
        bf_lay.setVerticalSpacing(12)
        bf_lay.setHorizontalSpacing(20)
        bf_lay.setContentsMargins(14, 20, 14, 14)

        ssh_label = QLabel("SSH")
        ssh_label.setStyleSheet("color: #58a6ff; font-weight: bold;")
        bf_lay.addRow(ssh_label)
        self.spin_bf_threshold = ClickFocusSpinBox(); self.spin_bf_threshold.setRange(1, 999)
        self.spin_bf_window = ClickFocusSpinBox(); self.spin_bf_window.setRange(1, 600)
        for sp in [self.spin_bf_threshold, self.spin_bf_window]:
            sp.setMinimumHeight(30)
        bf_lay.addRow("SSH failed attempts:", self.spin_bf_threshold)
        bf_lay.addRow("SSH window (sec):", self.spin_bf_window)

        ftp_label = QLabel("FTP")
        ftp_label.setStyleSheet("color: #58a6ff; font-weight: bold; margin-top: 8px;")
        bf_lay.addRow(ftp_label)
        self.spin_bf_ftp_threshold = ClickFocusSpinBox(); self.spin_bf_ftp_threshold.setRange(1, 999)
        self.spin_bf_ftp_window = ClickFocusSpinBox(); self.spin_bf_ftp_window.setRange(1, 600)
        for sp in [self.spin_bf_ftp_threshold, self.spin_bf_ftp_window]:
            sp.setMinimumHeight(30)
        bf_lay.addRow("FTP failed attempts:", self.spin_bf_ftp_threshold)
        bf_lay.addRow("FTP window (sec):", self.spin_bf_ftp_window)

        self.spin_bf_block = ClickFocusSpinBox(); self.spin_bf_block.setRange(1, 9999)
        self.spin_bf_block.setMinimumHeight(30)
        bf_lay.addRow("Block duration (sec):", self.spin_bf_block)
        advanced_content_lay.addWidget(bf_grp)

        # DoS thresholds
        dos_grp = QGroupBox("DoS / ICMP Flood Thresholds")
        dos_lay = QFormLayout(dos_grp)
        dos_lay.setVerticalSpacing(12)
        dos_lay.setHorizontalSpacing(20)
        dos_lay.setContentsMargins(14, 20, 14, 14)

        self.spin_dos_pps = ClickFocusSpinBox(); self.spin_dos_pps.setRange(1, 99999)
        self.spin_dos_block = ClickFocusSpinBox(); self.spin_dos_block.setRange(1, 9999)
        for sp in [self.spin_dos_pps, self.spin_dos_block]:
            sp.setMinimumHeight(30)
        dos_lay.addRow("ICMP pps threshold:", self.spin_dos_pps)
        dos_lay.addRow("Block duration (sec):", self.spin_dos_block)
        advanced_content_lay.addWidget(dos_grp)

        # Spoof thresholds
        sp_grp = QGroupBox("Spoof Detection Thresholds")
        sp_lay = QFormLayout(sp_grp)
        sp_lay.setVerticalSpacing(12)
        sp_lay.setHorizontalSpacing(20)
        sp_lay.setContentsMargins(14, 20, 14, 14)

        self.chk_arp_watch = QCheckBox("Enable ARP poisoning detection")
        sp_lay.addRow(self.chk_arp_watch)

        self.spin_sp_arp_cooldown = ClickFocusSpinBox(); self.spin_sp_arp_cooldown.setRange(1, 600)
        self.spin_sp_ttl_dev = ClickFocusSpinBox(); self.spin_sp_ttl_dev.setRange(1, 128)
        self.spin_sp_ttl_samples = ClickFocusSpinBox(); self.spin_sp_ttl_samples.setRange(2, 200)
        self.spin_sp_ttl_cooldown = ClickFocusSpinBox(); self.spin_sp_ttl_cooldown.setRange(1, 3600)
        self.spin_sp_ttl_max_alerts = ClickFocusSpinBox(); self.spin_sp_ttl_max_alerts.setRange(1, 100)
        self.chk_ttl_local_only = QCheckBox("TTL checks local subnet only (recommended)")
        self.spin_sp_block = ClickFocusSpinBox(); self.spin_sp_block.setRange(1, 9999)
        for sp in [self.spin_sp_arp_cooldown, self.spin_sp_ttl_dev,
                   self.spin_sp_ttl_samples, self.spin_sp_ttl_cooldown,
                   self.spin_sp_ttl_max_alerts, self.spin_sp_block]:
            sp.setMinimumHeight(30)
        sp_lay.addRow("ARP alert cooldown (sec):", self.spin_sp_arp_cooldown)
        sp_lay.addRow("TTL deviation threshold:", self.spin_sp_ttl_dev)
        sp_lay.addRow("TTL min samples:", self.spin_sp_ttl_samples)
        sp_lay.addRow("TTL alert cooldown (sec):", self.spin_sp_ttl_cooldown)
        sp_lay.addRow("TTL max alerts per source:", self.spin_sp_ttl_max_alerts)
        sp_lay.addRow(self.chk_ttl_local_only)
        sp_lay.addRow("Block duration (sec):", self.spin_sp_block)

        wl_hint = QLabel("Whitelist / exception settings")
        wl_hint.setStyleSheet("color: #8b949e; margin-top: 6px;")
        sp_lay.addRow(wl_hint)

        self.chk_whitelist_host = QCheckBox("Whitelist Host IP (bridged mode only)")
        sp_lay.addRow(self.chk_whitelist_host)
        self.host_ip_edit = QLineEdit()
        self.host_ip_edit.setPlaceholderText("e.g. 192.168.1.100")
        self.host_ip_edit.setMinimumHeight(30)
        sp_lay.addRow("Host machine IP:", self.host_ip_edit)

        self.chk_gateway_auto_whitelist = QCheckBox(
            "Gateway Auto Whitelist (Warning, turning it off can break the internet if using bridged)"
        )
        sp_lay.addRow(self.chk_gateway_auto_whitelist)

        wl_label = QLabel("IP Whitelist (never blocked by spoof detector):")
        wl_label.setStyleSheet("color: #8b949e; margin-top: 6px;")
        sp_lay.addRow(wl_label)
        self.spoof_wl_list = QListWidget()
        self.spoof_wl_list.setMaximumHeight(100)
        sp_lay.addRow(self.spoof_wl_list)
        wl_btns = QHBoxLayout()
        sp_wl_add = QPushButton("Add IP")
        sp_wl_add.clicked.connect(self._add_spoof_whitelist_ip)
        sp_wl_rm = QPushButton("Remove Selected")
        sp_wl_rm.clicked.connect(lambda: self._rm_mac(self.spoof_wl_list))
        wl_btns.addWidget(sp_wl_add)
        wl_btns.addWidget(sp_wl_rm)
        wl_btns.addStretch()
        sp_lay.addRow(wl_btns)

        advanced_content_lay.addWidget(sp_grp)
        advanced_content_lay.addStretch()
        lay.addWidget(advanced_grp)

        # Save button
        save_row = QHBoxLayout()
        save_btn = QPushButton("Save Configuration")
        save_btn.setMinimumHeight(36)
        save_btn.clicked.connect(self._save_config_from_ui)
        save_row.addStretch()
        save_row.addWidget(save_btn)
        lay.addLayout(save_row)

        lay.addStretch()
        scroll.setWidget(inner)
        return scroll

    # ---- Tab: MAC Filter -------------------------------------------------

    def _build_mac_tab(self):
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setSpacing(12)
        lay.setContentsMargins(10, 10, 10, 10)

        mode_grp = QGroupBox("Filter Mode")
        mode_lay = QHBoxLayout(mode_grp)
        self.mac_mode_combo = QComboBox()
        self.mac_mode_combo.addItems(["Allow Only", "Block Only"])
        mode_lay.addWidget(QLabel("Mode:"))
        mode_lay.addWidget(self.mac_mode_combo)
        mode_lay.addStretch()
        lay.addWidget(mode_grp)

        # Detected / Pending Review
        det_grp = QGroupBox("Detected MACs (Pending Review)")
        det_lay = QVBoxLayout(det_grp)
        self.mac_det_list = QListWidget()
        self.mac_det_list.setMinimumHeight(100)
        det_lay.addWidget(self.mac_det_list)

        det_btns = QHBoxLayout()
        det_allow = QPushButton("Move to Allowed")
        det_allow.clicked.connect(self._detected_to_allowed)
        det_block = QPushButton("Move to Blocked")
        det_block.clicked.connect(self._detected_to_blocked)
        det_dismiss = QPushButton("Dismiss")
        det_dismiss.clicked.connect(self._dismiss_detected)
        det_refresh = QPushButton("Refresh")
        det_refresh.clicked.connect(self._refresh_detected)
        det_btns.addWidget(det_block)
        det_btns.addWidget(det_allow)
        det_btns.addWidget(det_dismiss)
        det_btns.addWidget(det_refresh)
        det_btns.addStretch()
        det_lay.addLayout(det_btns)
        lay.addWidget(det_grp)

        # Blacklist
        bl_grp = QGroupBox("Blocked MACs")
        bl_lay = QVBoxLayout(bl_grp)
        self.mac_bl_list = QListWidget()
        self.mac_bl_list.setMinimumHeight(80)
        bl_lay.addWidget(self.mac_bl_list)

        bl_btns = QHBoxLayout()
        bl_rm = QPushButton("Remove Selected")
        bl_rm.clicked.connect(lambda: self._rm_mac(self.mac_bl_list))
        bl_btns.addWidget(bl_rm)
        bl_btns.addStretch()
        bl_lay.addLayout(bl_btns)
        lay.addWidget(bl_grp)

        # Whitelist
        wl_grp = QGroupBox("Allowed MACs")
        wl_lay = QVBoxLayout(wl_grp)
        self.mac_wl_list = QListWidget()
        self.mac_wl_list.setMinimumHeight(80)
        wl_lay.addWidget(self.mac_wl_list)

        wl_btns = QHBoxLayout()
        wl_rm = QPushButton("Remove Selected")
        wl_rm.clicked.connect(lambda: self._rm_mac(self.mac_wl_list))
        wl_btns.addWidget(wl_rm)
        wl_btns.addStretch()
        wl_lay.addLayout(wl_btns)
        lay.addWidget(wl_grp)

        mac_save_row = QHBoxLayout()
        mac_save_btn = QPushButton("Save MAC Config")
        mac_save_btn.clicked.connect(self._save_config_from_ui)
        mac_save_row.addStretch()
        mac_save_row.addWidget(mac_save_btn)
        lay.addLayout(mac_save_row)

        lay.addStretch()
        scroll.setWidget(w)
        return scroll

    # ---- Tab: About ------------------------------------------------------

    def _build_about_tab(self):
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setAlignment(Qt.AlignCenter)
        lay.setSpacing(16)
        lay.setContentsMargins(40, 30, 40, 30)

        title = QLabel("NIDS")
        title.setStyleSheet("font-size: 32px; font-weight: bold; color: #00e5ff;")
        title.setAlignment(Qt.AlignCenter)
        lay.addWidget(title)

        subtitle = QLabel(f"Network Intrusion Detection System\nv{APP_VERSION}")
        subtitle.setStyleSheet("font-size: 15px; color: #c9d1d9;")
        subtitle.setAlignment(Qt.AlignCenter)
        lay.addWidget(subtitle)

        lay.addSpacing(8)

        desc = QLabel("A real-time intrusion detection and prevention system\n"
                       "that monitors network traffic and automatically blocks threats via iptables.")
        desc.setAlignment(Qt.AlignCenter)
        desc.setWordWrap(True)
        desc.setStyleSheet("font-size: 13px; color: #8b949e;")
        lay.addWidget(desc)

        lay.addSpacing(4)

        modules_label = QLabel("Detection Modules")
        modules_label.setAlignment(Qt.AlignCenter)
        modules_label.setStyleSheet("font-size: 14px; font-weight: bold; color: #58a6ff;")
        lay.addWidget(modules_label)

        modules = QLabel(
            "Port Scan Detection — Scapy SYN analysis with per-source tracking\n"
            "SSH Brute-Force Detection — journalctl monitoring for failed logins\n"
            "DoS / ICMP Flood Detection — tcpdump sampling with pps thresholds\n"
            "IP Spoof Detection — ARP poisoning, TTL anomaly & bogon/subnet validation\n"
            "MAC Address Filtering — Allow Only / Block Only"
        )
        modules.setAlignment(Qt.AlignCenter)
        modules.setStyleSheet("font-size: 12px; color: #8b949e; line-height: 1.6;")
        lay.addWidget(modules)

        lay.addStretch()

        author = QLabel("Made by MD Saadman Kabir")
        author.setAlignment(Qt.AlignCenter)
        author.setStyleSheet("font-size: 13px; font-weight: bold; color: #73a9c2;")
        lay.addWidget(author)

        return w

    # ---- Detected MAC helpers ---------------------------------------------

    def _detected_item_mac(self, item):
        mac = item.data(Qt.UserRole)
        if mac:
            return mac
        return item.text().split(" ")[0]

    def _add_detected_row(self, mac, last_ip=None, first_seen=None):
        mac = mac.strip().upper()
        lip = str(last_ip).strip().upper() if last_ip is not None else ""
        if last_ip and str(last_ip).strip() and lip not in ("N/A", "?"):
            text = str(last_ip).strip()
            tip_parts = [f"MAC {mac}"]
            if first_seen:
                tip_parts.append(str(first_seen))
            tip = "\n".join(tip_parts)
        else:
            text = mac
            tip = "No IP on file" + (f"\n{first_seen}" if first_seen else "")
        it = QListWidgetItem(text)
        it.setData(Qt.UserRole, mac)
        it.setToolTip(tip)
        self.mac_det_list.addItem(it)

    def _get_selected_detected_mac(self):
        items = self.mac_det_list.selectedItems()
        if not items:
            if self.mac_det_list.count() == 0:
                self.statusBar().showMessage("No detected MACs — click Refresh first", 3000)
                return None, None
            self.mac_det_list.setCurrentRow(0)
            items = self.mac_det_list.selectedItems()
            if not items:
                return None, None
        mac = self._detected_item_mac(items[0])
        row = self.mac_det_list.row(items[0])
        return mac, row

    def _detected_to_allowed(self):
        mac, row = self._get_selected_detected_mac()
        if mac is None:
            return
        self.mac_wl_list.addItem(mac)
        self.mac_det_list.takeItem(row)
        self._save_config_from_ui()
        from modules.firewall import unblock_mac
        unblock_mac("NIDS_MACFILTER", mac)
        self.statusBar().showMessage(f"MAC {mac} allowed — block removed", 3000)

    def _detected_to_blocked(self):
        mac, row = self._get_selected_detected_mac()
        if mac is None:
            return
        self.mac_bl_list.addItem(mac)
        self.mac_det_list.takeItem(row)
        self._save_config_from_ui()
        from modules.firewall import ensure_chain, block_mac
        ensure_chain("NIDS_MACFILTER")
        block_mac("NIDS_MACFILTER", mac)
        self.statusBar().showMessage(f"MAC {mac} blocked immediately", 3000)

    def _dismiss_detected(self):
        mac, row = self._get_selected_detected_mac()
        if mac is None:
            return
        self._dismissed_macs.add(mac.upper())
        self.mac_det_list.takeItem(row)
        self.statusBar().showMessage(f"MAC {mac} dismissed (still in config, hidden until restart or new detection)", 3000)

    def _refresh_detected(self):
        """Reload detected MACs from config (picks up runtime detections).
        Dismissed MACs are hidden until a new detection un-dismisses them."""
        cfg = load_config()
        self.mac_det_list.clear()
        for entry in cfg["macfilter"].get("detected_macs", []):
            mac = entry["mac"].upper() if isinstance(entry, dict) else str(entry).upper()
            if mac in self._dismissed_macs:
                continue
            if isinstance(entry, dict):
                self._add_detected_row(
                    entry["mac"],
                    entry.get("last_ip"),
                    entry.get("first_seen"),
                )
            else:
                self._add_detected_row(str(entry))

    # ---- MAC helpers -----------------------------------------------------

    def _add_mac(self, list_widget):
        from modules.firewall import unblock_mac
        text, ok = QInputDialog.getText(
            self, "Add MAC Address",
            "Enter MAC address (e.g. AA:BB:CC:DD:EE:FF):"
        )
        if ok and text.strip():
            mac = text.strip().upper()
            list_widget.addItem(mac)
            if list_widget is self.mac_wl_list:
                unblock_mac("NIDS_MACFILTER", mac)
                self.statusBar().showMessage(f"MAC {mac} allowed — block removed", 3000)
            elif list_widget is self.mac_bl_list:
                from modules.firewall import ensure_chain, block_mac
                ensure_chain("NIDS_MACFILTER")
                block_mac("NIDS_MACFILTER", mac)
                self.statusBar().showMessage(f"MAC {mac} blocked immediately", 3000)

    def _rm_mac(self, list_widget):
        from modules.firewall import unblock_mac, ensure_chain, block_mac
        for item in list_widget.selectedItems():
            mac = item.text().split(" ")[0].upper()
            list_widget.takeItem(list_widget.row(item))
            if list_widget is self.mac_bl_list:
                unblock_mac("NIDS_MACFILTER", mac)
                self._add_detected_row(mac)
                self._save_config_from_ui()
                self.statusBar().showMessage(f"MAC {mac} unblocked — moved to Detected", 3000)
            elif list_widget is self.mac_wl_list:
                self._add_detected_row(mac)
                self._save_config_from_ui()
                self.statusBar().showMessage(f"MAC {mac} moved to Detected for review", 3000)

    def _add_spoof_whitelist_ip(self):
        text, ok = QInputDialog.getText(
            self, "Add IP to Whitelist",
            "Enter IP address to whitelist (e.g. 192.168.1.1):"
        )
        if ok and text.strip():
            self.spoof_wl_list.addItem(text.strip())

    # ---- Config <-> UI ---------------------------------------------------

    def _load_config_to_ui(self):
        c = self.cfg
        self.iface_edit.setText(c["interface"])

        m = c["modules"]
        self.chk_portscan.setChecked(m["portscan"])
        self.chk_bruteforce.setChecked(m["bruteforce"])
        self.chk_dos.setChecked(m["dos"])
        self.chk_spoof.setChecked(m["spoof"])
        self.chk_macfilter.setChecked(m["macfilter"])

        ps = c["portscan"]
        self.spin_ps_ports.setValue(ps["port_threshold"])
        self.spin_ps_syns.setValue(ps["syn_threshold"])
        self.spin_ps_window.setValue(ps["window_sec"])
        self.spin_ps_slow_ports.setValue(ps.get("slow_port_threshold", ps["port_threshold"]))
        self.spin_ps_slow_syns.setValue(ps.get("slow_syn_threshold", ps["syn_threshold"]))
        self.spin_ps_slow_window.setValue(ps.get("slow_window_sec", max(ps["window_sec"], 120)))
        self.spin_ps_udp_ports.setValue(ps.get("udp_port_threshold", 8))
        self.spin_ps_udp_probes.setValue(ps.get("udp_probe_threshold", 12))
        self.spin_ps_udp_window.setValue(ps.get("udp_window_sec", 10))
        self.spin_ps_block.setValue(ps["block_seconds"])

        bf = c["bruteforce"]
        self.spin_bf_threshold.setValue(bf["threshold"])
        self.spin_bf_window.setValue(bf["window_sec"])
        self.spin_bf_ftp_threshold.setValue(bf.get("ftp_threshold", 5))
        self.spin_bf_ftp_window.setValue(bf.get("ftp_window_sec", 60))
        self.spin_bf_block.setValue(bf["block_seconds"])

        d = c["dos"]
        self.spin_dos_pps.setValue(d["threshold_pps"])
        self.spin_dos_block.setValue(d["block_seconds"])

        sp = c["spoof"]
        self.chk_arp_watch.setChecked(sp.get("arp_watch", True))
        self.chk_gateway_auto_whitelist.setChecked(sp.get("gateway_auto_whitelist", True))
        self.chk_whitelist_host.setChecked(sp.get("whitelist_host", False))
        self.host_ip_edit.setText(sp.get("host_ip", ""))
        self.spin_sp_arp_cooldown.setValue(sp.get("arp_alert_cooldown", 30))
        self.spin_sp_ttl_dev.setValue(sp.get("ttl_deviation", 15))
        self.spin_sp_ttl_samples.setValue(sp.get("ttl_min_samples", 10))
        self.spin_sp_ttl_cooldown.setValue(sp.get("ttl_alert_cooldown", 120))
        self.spin_sp_ttl_max_alerts.setValue(sp.get("ttl_max_alerts_per_source", 3))
        self.chk_ttl_local_only.setChecked(sp.get("ttl_local_only", True))
        self.spin_sp_block.setValue(sp.get("block_seconds", 120))
        self.spoof_wl_list.clear()
        for ip in sp.get("whitelist_ips", []):
            self.spoof_wl_list.addItem(ip)

        mc = c["macfilter"]
        ui_mode = _MAC_MODE_CFG_TO_UI.get(mc.get("mode", "whitelist"), "Allow Only")
        idx = self.mac_mode_combo.findText(ui_mode)
        if idx >= 0:
            self.mac_mode_combo.setCurrentIndex(idx)
        self.mac_wl_list.clear()
        for m in mc.get("allowed_macs", []):
            self.mac_wl_list.addItem(m)
        self.mac_bl_list.clear()
        for m in mc.get("blocked_macs", []):
            self.mac_bl_list.addItem(m)
        self.mac_det_list.clear()
        for entry in mc.get("detected_macs", []):
            if isinstance(entry, dict):
                self._add_detected_row(
                    entry["mac"],
                    entry.get("last_ip"),
                    entry.get("first_seen"),
                )
            else:
                self._add_detected_row(str(entry))

    def _save_config_from_ui(self):
        c = self.cfg
        c["interface"] = self.iface_edit.text().strip() or "eth0"

        c["modules"]["portscan"] = self.chk_portscan.isChecked()
        c["modules"]["bruteforce"] = self.chk_bruteforce.isChecked()
        c["modules"]["dos"] = self.chk_dos.isChecked()
        c["modules"]["spoof"] = self.chk_spoof.isChecked()
        c["modules"]["macfilter"] = self.chk_macfilter.isChecked()

        c["portscan"]["port_threshold"] = self.spin_ps_ports.value()
        c["portscan"]["syn_threshold"] = self.spin_ps_syns.value()
        c["portscan"]["window_sec"] = self.spin_ps_window.value()
        c["portscan"]["slow_port_threshold"] = self.spin_ps_slow_ports.value()
        c["portscan"]["slow_syn_threshold"] = self.spin_ps_slow_syns.value()
        c["portscan"]["slow_window_sec"] = self.spin_ps_slow_window.value()
        c["portscan"]["udp_port_threshold"] = self.spin_ps_udp_ports.value()
        c["portscan"]["udp_probe_threshold"] = self.spin_ps_udp_probes.value()
        c["portscan"]["udp_window_sec"] = self.spin_ps_udp_window.value()
        c["portscan"]["block_seconds"] = self.spin_ps_block.value()

        c["bruteforce"]["threshold"] = self.spin_bf_threshold.value()
        c["bruteforce"]["window_sec"] = self.spin_bf_window.value()
        c["bruteforce"]["ftp_threshold"] = self.spin_bf_ftp_threshold.value()
        c["bruteforce"]["ftp_window_sec"] = self.spin_bf_ftp_window.value()
        c["bruteforce"]["block_seconds"] = self.spin_bf_block.value()

        c["dos"]["threshold_pps"] = self.spin_dos_pps.value()
        c["dos"]["block_seconds"] = self.spin_dos_block.value()

        c["spoof"]["arp_watch"] = self.chk_arp_watch.isChecked()
        c["spoof"]["gateway_auto_whitelist"] = self.chk_gateway_auto_whitelist.isChecked()
        c["spoof"]["whitelist_host"] = self.chk_whitelist_host.isChecked()
        c["spoof"]["host_ip"] = self.host_ip_edit.text().strip()
        c["spoof"]["arp_alert_cooldown"] = self.spin_sp_arp_cooldown.value()
        c["spoof"]["ttl_deviation"] = self.spin_sp_ttl_dev.value()
        c["spoof"]["ttl_min_samples"] = self.spin_sp_ttl_samples.value()
        c["spoof"]["ttl_alert_cooldown"] = self.spin_sp_ttl_cooldown.value()
        c["spoof"]["ttl_max_alerts_per_source"] = self.spin_sp_ttl_max_alerts.value()
        c["spoof"]["ttl_local_only"] = self.chk_ttl_local_only.isChecked()
        c["spoof"]["block_seconds"] = self.spin_sp_block.value()
        c["spoof"]["whitelist_ips"] = [
            self.spoof_wl_list.item(i).text()
            for i in range(self.spoof_wl_list.count())
        ]

        c["macfilter"]["mode"] = _MAC_MODE_UI_TO_CFG.get(
            self.mac_mode_combo.currentText(), "whitelist"
        )
        c["macfilter"]["allowed_macs"] = [
            self.mac_wl_list.item(i).text()
            for i in range(self.mac_wl_list.count())
        ]
        c["macfilter"]["blocked_macs"] = [
            self.mac_bl_list.item(i).text()
            for i in range(self.mac_bl_list.count())
        ]

        gui_det_macs = set()
        for i in range(self.mac_det_list.count()):
            it = self.mac_det_list.item(i)
            gui_det_macs.add(self._detected_item_mac(it).upper())

        on_disk = load_config()["macfilter"].get("detected_macs", [])
        det_list = []
        merged = set()
        for entry in on_disk:
            m = (entry["mac"] if isinstance(entry, dict) else entry).upper()
            if m in gui_det_macs:
                det_list.append(entry if isinstance(entry, dict) else {"mac": m, "last_ip": "?", "first_seen": ""})
                merged.add(m)
        ts = time.strftime("%Y-%m-%d %H:%M:%S")
        for m in gui_det_macs:
            if m not in merged:
                det_list.append({"mac": m, "last_ip": "?", "first_seen": ts})
        c["macfilter"]["detected_macs"] = det_list

        save_config(c)
        self.cfg = c
        self.statusBar().showMessage("Configuration saved", 3000)

    def _reload_config(self):
        self.cfg = load_config()
        self._load_config_to_ui()
        self.statusBar().showMessage("Configuration reloaded", 3000)

    # ---- Engine control --------------------------------------------------

    def _start(self):
        self._save_config_from_ui()
        self._alert_count = 0
        self._block_count = 0

        self.log_view.clear()
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.status_label.setText("  Running")
        self.status_label.setStyleSheet("color: #39d353; font-weight: bold;")
        self.running_label.setText("Engine is active")
        self.running_label.setStyleSheet("color: #39d353; font-weight: bold;")

        self.worker = EngineWorker(self.cfg)
        self.worker.log_signal.connect(self._on_log_line)
        self.worker.stopped_signal.connect(self._on_stopped)
        self.worker.start()
        QTimer.singleShot(1500, self._rebuild_blocks_from_firewall)

    def _stop(self):
        if self.worker:
            self.worker.stop_engine()

    def _unblock_all(self):
        import subprocess
        from modules.firewall import flush_chain
        ts = time.strftime("%Y-%m-%d %H:%M:%S")

        from modules.firewall import destroy_chain as _destroy
        for chain in ["NIDS_PORTSCAN", "NIDS_BRUTEFORCE", "NIDS_DOS", "NIDS_SPOOF", "NIDS_MACFILTER"]:
            flush_chain(chain)
        self._on_log_line(f"{ts} [ENGINE] All blocks cleared")
        from modules import arpnft
        arpnft.arp_flush_blocked()

        # Also flush DNS cache
        resolvers = [
            (["systemd-resolve", "--flush-caches"], "systemd-resolved"),
            (["resolvectl", "flush-caches"],         "resolvectl"),
            (["sudo", "killall", "-HUP", "dnsmasq"], "dnsmasq"),
            (["sudo", "nscd", "-i", "hosts"],        "nscd"),
            (["sudo", "rndc", "flush"],              "BIND/named"),
        ]
        for cmd, name in resolvers:
            try:
                res = subprocess.run(cmd, stdout=subprocess.DEVNULL,
                                     stderr=subprocess.DEVNULL, timeout=5)
                if res.returncode == 0:
                    self._on_log_line(f"{ts} [ENGINE] DNS cache flushed via {name}")
                    break
            except (FileNotFoundError, subprocess.TimeoutExpired):
                continue

        # Clear all runtime state so detectors can re-detect
        from modules import portscan, bruteforce, dos, spoof, macfilter
        for mod in [portscan, bruteforce, dos, spoof, macfilter]:
            if hasattr(mod, 'blocked_ips'):
                mod.blocked_ips.clear()
            if hasattr(mod, '_blocked_macs'):
                mod._blocked_macs.clear()
        portscan.seen_ports.clear()
        portscan.seen_syns.clear()
        portscan.slow_seen_ports.clear()
        portscan.slow_seen_syns.clear()
        portscan.udp_seen_ports.clear()
        portscan.udp_seen_probes.clear()
        bruteforce.failures_ssh.clear()
        bruteforce.failures_ftp.clear()
        gw_ip = spoof._gateway_ip
        gw_mac = spoof.arp_table.get(gw_ip) if gw_ip else None
        spoof.arp_table.clear()
        if gw_ip and gw_mac:
            spoof.arp_table[gw_ip] = gw_mac
        spoof.arp_cooldowns.clear()
        spoof.ttl_alert_cooldowns.clear()
        spoof.ttl_alert_counts.clear()
        spoof.blocked_macs.clear()

        self.statusBar().showMessage("All blocks cleared + DNS flushed", 3000)

    _LOG_COLORS = {
        "ALERT":   "#f0883e",
        "BLOCK":   "#da3633",
        "UNBLOCK": "#39d353",
        "INFO":    "#8b949e",
        "START":   "#58a6ff",
        "STOP":    "#58a6ff",
        "ENGINE":  "#58a6ff",
        "WARN":    "#d29922",
        "ERROR":   "#ff7b72",
    }

    def _on_log_line(self, line):
        import re as _re
        tag_m = _re.search(r'\[(\w+)\]', line)
        tag = tag_m.group(1) if tag_m else "INFO"
        color = self._LOG_COLORS.get(tag, "#c9d1d9")

        cursor = self.log_view.textCursor()
        cursor.movePosition(cursor.End)
        fmt = QTextCharFormat()
        fmt.setForeground(QColor(color))
        cursor.insertText(line + "\n", fmt)
        self.log_view.setTextCursor(cursor)
        self.log_view.ensureCursorVisible()

        if tag == "ALERT":
            self._alert_count += 1
            self.alert_label.setText(f"Alerts: {self._alert_count}")
        if tag == "BLOCK":
            self._block_count += 1
            self.block_label.setText(f"Blocks: {self._block_count}")
            self._add_active_block(line)
        if tag == "UNBLOCK":
            self._remove_active_block(line)
        if "added to detected list for review" in line:
            m = _re.search(r"MAC\s+([\dA-Fa-f:]+)\s+added", line)
            if m:
                self._dismissed_macs.discard(m.group(1).upper())
            self._refresh_detected()
        if "All blocks cleared" in line:
            self.blocks_list.clear()

    _CHAIN_HINTS = {
        "port scan": "NIDS_PORTSCAN",
        "Port scan": "NIDS_PORTSCAN",
        "Slow": "NIDS_PORTSCAN",
        "Brute force": "NIDS_BRUTEFORCE",
        "DoS": "NIDS_DOS",
        "flood": "NIDS_DOS",
        "spoof": "NIDS_SPOOF",
        "bogon": "NIDS_SPOOF",
        "ARP": "NIDS_SPOOF",
        "MAC": "NIDS_MACFILTER",
        "dropped via NIDS_MACFILTER": "NIDS_MACFILTER",
        "dropped via NIDS_SPOOF": "NIDS_SPOOF",
    }

    def _infer_chain(self, line):
        for hint, chain in self._CHAIN_HINTS.items():
            if hint in line:
                return chain
        return None

    def _add_active_block(self, line):
        import re as _re
        ip_m = _re.search(r'Blocked\s+(\d+\.\d+\.\d+\.\d+)', line)
        mac_m = _re.search(r'(?:Blocked.*MAC|MAC)\s+([\dA-Fa-f:]{17})', line, _re.IGNORECASE)
        ts_str = time.strftime("%H:%M:%S")
        chain = self._infer_chain(line)

        if mac_m:
            target = mac_m.group(1).upper()
            label = f"MAC {target}  [{ts_str}]  {chain or ''}"
            meta = {"type": "mac", "target": target, "chain": chain}
        elif ip_m:
            target = ip_m.group(1)
            label = f"IP  {target}  [{ts_str}]  {chain or ''}"
            meta = {"type": "ip", "target": target, "chain": chain}
        else:
            return
        item = QListWidgetItem(label)
        item.setData(Qt.UserRole, meta)
        self.blocks_list.addItem(item)

    def _remove_active_block(self, line):
        import re as _re
        ip_m = _re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
        mac_m = _re.search(r'([\dA-Fa-f:]{17})', line, _re.IGNORECASE)
        target = None
        if mac_m:
            target = mac_m.group(1).upper()
        elif ip_m:
            target = ip_m.group(1)
        if not target:
            return
        for i in range(self.blocks_list.count() - 1, -1, -1):
            meta = self.blocks_list.item(i).data(Qt.UserRole)
            if meta and meta.get("target") == target:
                self.blocks_list.takeItem(i)
            elif target in self.blocks_list.item(i).text():
                self.blocks_list.takeItem(i)

    def _unblock_selected(self):
        from modules.firewall import unblock_ip, unblock_mac
        _IP_CHAINS = ["NIDS_PORTSCAN", "NIDS_BRUTEFORCE", "NIDS_DOS", "NIDS_SPOOF"]
        _MAC_CHAINS = ["NIDS_SPOOF", "NIDS_MACFILTER"]

        for item in self.blocks_list.selectedItems():
            meta = item.data(Qt.UserRole)
            if meta and meta.get("chain"):
                chain = meta["chain"]
                if meta["type"] == "ip":
                    unblock_ip(chain, meta["target"])
                else:
                    unblock_mac(chain, meta["target"])
                    from modules import arpnft
                    arpnft.arp_unblock_mac(meta["target"])
            elif meta:
                if meta["type"] == "ip":
                    for c in _IP_CHAINS:
                        unblock_ip(c, meta["target"])
                else:
                    for c in _MAC_CHAINS:
                        unblock_mac(c, meta["target"])
                    from modules import arpnft
                    arpnft.arp_unblock_mac(meta["target"])
            self.blocks_list.takeItem(self.blocks_list.row(item))
        self.statusBar().showMessage("Selected blocks removed", 3000)

    def _rebuild_blocks_from_firewall(self):
        """Populate Active Blocks panel from current iptables/nftables state."""
        from modules.firewall import list_blocked_ips, list_blocked_macs
        from modules import arpnft

        self.blocks_list.clear()
        chain_ip_map = {
            "NIDS_PORTSCAN": "portscan",
            "NIDS_BRUTEFORCE": "bruteforce",
            "NIDS_DOS": "dos",
            "NIDS_SPOOF": "spoof",
        }
        chain_mac_map = {
            "NIDS_SPOOF": "spoof",
            "NIDS_MACFILTER": "macfilter",
        }
        seen_ips = set()
        for chain, module in chain_ip_map.items():
            for ip in list_blocked_ips(chain):
                key = (ip, chain)
                if key in seen_ips:
                    continue
                seen_ips.add(key)
                label = f"IP  {ip}  [{module}]  {chain}"
                item = QListWidgetItem(label)
                item.setData(Qt.UserRole, {"type": "ip", "target": ip, "chain": chain})
                self.blocks_list.addItem(item)

        seen_macs = set()
        for chain, module in chain_mac_map.items():
            for mac in list_blocked_macs(chain):
                key = (mac, chain)
                if key in seen_macs:
                    continue
                seen_macs.add(key)
                label = f"MAC {mac}  [{module}]  {chain}"
                item = QListWidgetItem(label)
                item.setData(Qt.UserRole, {"type": "mac", "target": mac, "chain": chain})
                self.blocks_list.addItem(item)

        for mac in arpnft.arp_list_blocked():
            if not any(
                (m.data(Qt.UserRole) or {}).get("target") == mac
                for m in [self.blocks_list.item(i) for i in range(self.blocks_list.count())]
            ):
                label = f"MAC {mac}  [nftables]  netdev"
                item = QListWidgetItem(label)
                item.setData(Qt.UserRole, {"type": "mac", "target": mac, "chain": None})
                self.blocks_list.addItem(item)

        count = self.blocks_list.count()
        if count:
            self.statusBar().showMessage(f"Active Blocks: {count} rules loaded from firewall", 3000)

    def _export_logs(self):
        import csv, json
        from PyQt5.QtWidgets import QFileDialog
        path, _ = QFileDialog.getSaveFileName(
            self, "Export Logs", f"nids_export_{time.strftime('%Y%m%d_%H%M%S')}",
            "JSON (*.json);;CSV (*.csv);;All Files (*)"
        )
        if not path:
            return

        records = []
        if self.worker and self.worker.engine:
            records = self.worker.engine.get_structured_records()

        if not records:
            self.statusBar().showMessage("No session data to export", 3000)
            return

        fields = ["timestamp", "event_type", "source_ip", "source_mac", "action", "message"]
        try:
            if path.endswith(".csv"):
                with open(path, "w", newline="") as f:
                    w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
                    w.writeheader()
                    w.writerows(records)
            else:
                if not path.endswith(".json"):
                    path += ".json"
                with open(path, "w") as f:
                    json.dump(records, f, indent=2)
            self.statusBar().showMessage(f"Exported {len(records)} entries to {path}", 5000)
        except Exception as e:
            self.statusBar().showMessage(f"Export failed: {e}", 5000)

    def _on_stopped(self):
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.status_label.setText("  Stopped")
        self.status_label.setStyleSheet("color: #da3633;")
        self.running_label.setText("")

    # ---- Close -----------------------------------------------------------

    def closeEvent(self, event):
        if self.worker and self.worker.isRunning():
            self.worker.stop_engine()
            self.worker.wait(3000)
        event.accept()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    app = QApplication(sys.argv)
    app.setApplicationName("NIDS")
    app.setApplicationVersion(APP_VERSION)
    _icon = os.path.join(os.path.dirname(os.path.abspath(__file__)), "icons", "nids.png")
    if os.path.isfile(_icon):
        try:
            os.chmod(_icon, 0o644)
        except OSError:
            pass
        app.setWindowIcon(QIcon(_icon))
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
