#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
PyIPv4v6_TLS_Test - SSL/TLS 测试工具
Copyright (c) 2026 by hets

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

"""
import os
import socket
import ssl
import threading
import queue
import json
import sys
from datetime import datetime
from pathlib import Path

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from tkinter.scrolledtext import ScrolledText


def is_ip_address(host: str) -> bool:
    host = host.strip().strip("[]")
    # crude check for IPv4/IPv6 literals
    if ":" in host:
        return True
    parts = host.split(".")
    if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
        return True
    return False


def append_fallback_log(config_file: str, text: str, log_file: str = None):
    try:
        if log_file:
            final_log_file = log_file
            log_dir = os.path.dirname(os.path.abspath(final_log_file))
            os.makedirs(log_dir, exist_ok=True)
        else:
            config_base = os.path.dirname(sys.executable) if getattr(sys, "frozen", False) else os.path.dirname(os.path.abspath(__file__))
            cfg = config_file or "tls_config.json"
            if not os.path.isabs(cfg):
                cfg = os.path.join(config_base, cfg)
            base_dir = os.path.dirname(os.path.abspath(cfg))
            log_dir = os.path.join(base_dir, "logs")
            os.makedirs(log_dir, exist_ok=True)
            final_log_file = os.path.join(log_dir, "tls_tool.log")
        
        with open(final_log_file, "a", encoding="utf-8") as f:
            f.write(text.rstrip("\n") + "\n")
    except Exception:
        pass


class ConfigManager:
    def __init__(self, config_file="tls_config.json", log_file=None):
        self.config_file = config_file
        self.log_file = log_file
        self._log_lock = threading.Lock()
        
        if not self.log_file:
            try:
                base_dir = os.path.dirname(os.path.abspath(self.config_file)) if self.config_file else os.getcwd()
                log_dir = os.path.join(base_dir, "logs")
                os.makedirs(log_dir, exist_ok=True)
                self.log_file = os.path.join(log_dir, "tls_tool.log")
            except Exception:
                self.log_file = None
        else:
            try:
                log_dir = os.path.dirname(os.path.abspath(self.log_file))
                os.makedirs(log_dir, exist_ok=True)
            except Exception:
                pass

        self.config = self.load_config()
    
    def load_config(self):
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
        except Exception as e:
            print(f"加载配置文件失败: {e}")
            try:
                self.append_log(f"加载配置文件失败: {e}")
            except Exception:
                pass
        return self.get_default_config()
    
    def get_default_config(self):
        return {
            "mode": "client",
            "server": {
                "port": 8443,
                "use_ipv6": False,
                "ssl_version": "默认",
                "auth_mode": "单向认证",
                "server_cert": "",
                "server_key": "",
                "ca_cert": "",
                "auto_reply": True,
                "data_mode": "透明"
            },
            "client": {
                "host": "127.0.0.1",
                "port": 8443,
                "auth_mode": "单向",
                "ssl_version": "默认",
                "client_cert": "",
                "client_key": "",
                "ca_cert": "",
                "hex_send": False
            }
        }
    
    def save_config(self):
        try:
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(self.config, f, indent=2, ensure_ascii=False)
        except Exception as e:
            print(f"保存配置文件失败: {e}")
            try:
                self.append_log(f"保存配置文件失败: {e}")
            except Exception:
                pass

    def append_log(self, line: str):
        if not self.log_file:
            return
        try:
            with self._log_lock:
                with open(self.log_file, "a", encoding="utf-8") as f:
                    f.write(line.rstrip("\n") + "\n")
        except Exception:
            pass
    
    def get_ssl_version(self, version_str):
        ssl_versions = {
            "TLS 1.0": ssl.PROTOCOL_TLSv1 if hasattr(ssl, 'PROTOCOL_TLSv1') else None,
            "TLS 1.1": ssl.PROTOCOL_TLSv1_1 if hasattr(ssl, 'PROTOCOL_TLSv1_1') else None,
            "TLS 1.2": ssl.PROTOCOL_TLSv1_2 if hasattr(ssl, 'PROTOCOL_TLSv1_2') else None,
            "TLS 1.3": ssl.PROTOCOL_TLS if hasattr(ssl, 'PROTOCOL_TLS') else None,
            "默认": None
        }
        return ssl_versions.get(version_str, None)


class TLSServerApp:
    def __init__(self, root: tk.Tk, config_manager):
        self.root = root
        self.config_manager = config_manager
        
        # Server state
        self.server_sock = None
        self.ssl_context = None
        self.clients = {}  # client_socket -> (thread, address)
        self.server_thread = None
        self.running = False
        self.stop_event = threading.Event()
        self.ui_queue = queue.Queue()
        self.lock = threading.Lock()
        
        # Server variables
        self.port_var = tk.IntVar(value=config_manager.config["server"]["port"])
        self.use_ipv6_var = tk.BooleanVar(value=config_manager.config["server"]["use_ipv6"])
        self.ssl_version_var = tk.StringVar(value=config_manager.config["server"]["ssl_version"])
        self.auth_mode_var = tk.StringVar(value=config_manager.config["server"]["auth_mode"])
        self.auto_reply_var = tk.BooleanVar(value=config_manager.config["server"]["auto_reply"])
        self.data_mode_var = tk.StringVar(value=config_manager.config["server"]["data_mode"])
        
        self.server_cert_path = tk.StringVar(value=config_manager.config["server"]["server_cert"])
        self.server_key_path = tk.StringVar(value=config_manager.config["server"]["server_key"])
        self.ca_cert_path = tk.StringVar(value=config_manager.config["server"]["ca_cert"])
        
        self.sent_bytes = tk.IntVar(value=0)
        self.recv_bytes = tk.IntVar(value=0)
        self.send_text_cache = ""
        
        self.build_server_ui()
        
        # Start UI queue processor
        self.root.after(100, self._process_ui_queue)
    
    def build_server_ui(self):
        # Server configuration frame
        config_frame = ttk.LabelFrame(self.root, text="SSL/TCP 服务器配置")
        config_frame.pack(side=tk.TOP, fill=tk.X, padx=8, pady=6)
        
        # Row 1: SSL version, auth mode, certificates
        ttk.Label(config_frame, text="SSL/TLS版本:").grid(row=0, column=0, padx=6, pady=6, sticky=tk.W)
        ssl_versions = ["默认", "TLS 1.0", "TLS 1.1", "TLS 1.2", "TLS 1.3"]
        ttk.Combobox(config_frame, textvariable=self.ssl_version_var, values=ssl_versions, 
                    width=10, state="readonly").grid(row=0, column=1, padx=2, pady=6)
        
        ttk.Label(config_frame, text="认证模式:").grid(row=0, column=2, padx=6, pady=6, sticky=tk.W)
        auth_modes = ["单向认证", "双向认证"]
        ttk.Combobox(config_frame, textvariable=self.auth_mode_var, values=auth_modes, 
                    width=10, state="readonly").grid(row=0, column=3, padx=2, pady=6)
        
        ttk.Button(config_frame, text="服务器证书...", command=self._choose_server_cert).grid(row=0, column=4, padx=6)
        self.server_cert_label = ttk.Label(config_frame, text="未选择")
        self.server_cert_label.grid(row=0, column=5, sticky=tk.W)
        
        ttk.Button(config_frame, text="服务器私钥...", command=self._choose_server_key).grid(row=0, column=6, padx=6)
        self.server_key_label = ttk.Label(config_frame, text="未选择")
        self.server_key_label.grid(row=0, column=7, sticky=tk.W)
        
        ttk.Button(config_frame, text="CA证书...", command=self._choose_ca_cert).grid(row=0, column=8, padx=6)
        self.ca_cert_label = ttk.Label(config_frame, text="未选择")
        self.ca_cert_label.grid(row=0, column=9, sticky=tk.W)
        
        # Row 2: Port, IPv6, control buttons
        ttk.Label(config_frame, text="端口:").grid(row=1, column=0, padx=6, pady=6, sticky=tk.W)
        ttk.Entry(config_frame, textvariable=self.port_var, width=8).grid(row=1, column=1, padx=2, pady=6)
        
        ttk.Checkbutton(config_frame, text="IPv6", variable=self.use_ipv6_var).grid(row=1, column=2, padx=6)
        
        self.listen_btn = ttk.Button(config_frame, text="开始侦听", command=self.toggle_server)
        self.listen_btn.grid(row=1, column=3, padx=6)
        
        # Data options
        ttk.Checkbutton(config_frame, text="自动回复", variable=self.auto_reply_var).grid(row=1, column=4, padx=6)
        
        ttk.Label(config_frame, text="数据模式:").grid(row=1, column=5, padx=6, sticky=tk.W)
        data_modes = ["透明", "数据"]
        ttk.Combobox(config_frame, textvariable=self.data_mode_var, values=data_modes, 
                    width=8, state="readonly").grid(row=1, column=6, padx=2, pady=6)
        
        # Counters
        ttk.Label(config_frame, text="发送:").grid(row=1, column=7, padx=6, sticky=tk.E)
        ttk.Entry(config_frame, textvariable=self.sent_bytes, width=10, state="readonly").grid(row=1, column=8, padx=2)
        
        ttk.Label(config_frame, text="接收:").grid(row=1, column=9, padx=6, sticky=tk.E)
        ttk.Entry(config_frame, textvariable=self.recv_bytes, width=10, state="readonly").grid(row=1, column=10, padx=2)
        
        # Main content area
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=8, pady=6)
        
        # Left: Client list
        client_frame = ttk.LabelFrame(main_frame, text="客户端列表")
        client_frame.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 4))
        
        self.client_listbox = tk.Listbox(client_frame, width=25, height=15)
        self.client_listbox.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)
        
        client_btn_frame = ttk.Frame(client_frame)
        client_btn_frame.pack(fill=tk.X, padx=4, pady=4)
        
        ttk.Button(client_btn_frame, text="断开选中", command=self._disconnect_selected_client).pack(side=tk.LEFT, padx=2)
        ttk.Button(client_btn_frame, text="断开全部", command=self._disconnect_all_clients).pack(side=tk.LEFT, padx=2)
        
        # Right: Log area
        log_frame = ttk.LabelFrame(main_frame, text="日志输出")
        log_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(4, 0))
        
        self.log = ScrolledText(log_frame, wrap=tk.WORD, height=15)
        self.log.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)
        
        # Bottom: Message send area
        bottom_frame = ttk.Frame(self.root)
        bottom_frame.pack(side=tk.BOTTOM, fill=tk.X, padx=8, pady=6)
        
        ttk.Button(bottom_frame, text="清空日志", command=self._clear_log).pack(side=tk.LEFT)
        
        self.send_text = tk.Text(bottom_frame, height=3)
        self.send_text.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=8)
        
        send_btn_frame = ttk.Frame(bottom_frame)
        send_btn_frame.pack(side=tk.RIGHT)
        
        ttk.Checkbutton(send_btn_frame, text="Hex发送").pack(anchor=tk.W)
        ttk.Checkbutton(send_btn_frame, text="群发").pack(anchor=tk.W)
        ttk.Button(send_btn_frame, text="发送", command=self._send_to_selected).pack(pady=4)
        
        # Status bar
        self.status_var = tk.StringVar(value="服务器未启动")
        status = ttk.Label(self.root, textvariable=self.status_var, anchor=tk.W)
        status.pack(fill=tk.X, padx=8, pady=(0, 8))
        
        # Update certificate labels
        self._update_cert_labels()
        self._sync_send_text_cache()

    def _sync_send_text_cache(self):
        try:
            self.send_text_cache = self.send_text.get("1.0", tk.END).strip()
        except Exception:
            pass
        self.root.after(200, self._sync_send_text_cache)
    
    def _choose_server_cert(self):
        path = filedialog.askopenfilename(title="选择服务器证书 (PEM/CRT)", filetypes=[
            ("PEM/CRT", "*.pem *.crt"), ("All", "*.*")
        ])
        if path:
            self.server_cert_path.set(path)
            self.config_manager.config["server"]["server_cert"] = path
            self._update_cert_labels()
    
    def _choose_server_key(self):
        path = filedialog.askopenfilename(title="选择服务器私钥 (PEM/KEY)", filetypes=[
            ("PEM/KEY", "*.pem *.key"), ("All", "*.*")
        ])
        if path:
            self.server_key_path.set(path)
            self.config_manager.config["server"]["server_key"] = path
            self._update_cert_labels()
    
    def _choose_ca_cert(self):
        path = filedialog.askopenfilename(title="选择CA证书 (PEM/CRT)", filetypes=[
            ("PEM/CRT", "*.pem *.crt"), ("All", "*.*")
        ])
        if path:
            self.ca_cert_path.set(path)
            self.config_manager.config["server"]["ca_cert"] = path
            self._update_cert_labels()
    
    def _update_cert_labels(self):
        self.server_cert_label.config(text=os.path.basename(self.server_cert_path.get()) if self.server_cert_path.get() else "未选择")
        self.server_key_label.config(text=os.path.basename(self.server_key_path.get()) if self.server_key_path.get() else "未选择")
        self.ca_cert_label.config(text=os.path.basename(self.ca_cert_path.get()) if self.ca_cert_path.get() else "未选择")
    
    def _clear_log(self):
        self.log.delete("1.0", tk.END)

    
    
    def _log(self, text: str):
        stamp = datetime.now().strftime("%m-%d %H:%M:%S")
        line = f"[{stamp}] {text}"
        self.log.insert(tk.END, line + "\n")
        self.log.see(tk.END)
        try:
            self.config_manager.append_log(line)
        except Exception:
            pass
    
    def _status(self, text: str):
        self.status_var.set(text)
    
    def _process_ui_queue(self):
        while True:
            try:
                msg = self.ui_queue.get_nowait()
                self._log(msg)
            except queue.Empty:
                break
        self.root.after(100, self._process_ui_queue)
    
    def toggle_server(self):
        if not self.running:
            self.start_server()
        else:
            self.stop_server()
    
    def _build_ssl_context(self):
        try:
            auth_mode = self.auth_mode_var.get()
            ssl_version = self.ssl_version_var.get()
            protocol = self.config_manager.get_ssl_version(ssl_version)
            
            if auth_mode == "单向认证":
                context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            else:
                context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            
            applied = "默认"
            if ssl_version.startswith("TLS ") and hasattr(ssl, "TLSVersion"):
                try:
                    mapping = {
                        "TLS 1.0": ssl.TLSVersion.TLSv1,
                        "TLS 1.1": ssl.TLSVersion.TLSv1_1,
                        "TLS 1.2": ssl.TLSVersion.TLSv1_2,
                        "TLS 1.3": ssl.TLSVersion.TLSv1_3,
                    }
                    ver = mapping.get(ssl_version)
                    if ver is not None:
                        if hasattr(context, "minimum_version"):
                            context.minimum_version = ver
                        if hasattr(context, "maximum_version"):
                            context.maximum_version = ver
                        applied = f"固定 {ssl_version}"
                except Exception:
                    pass
            elif protocol:
                context = ssl.SSLContext(protocol)
                if auth_mode == "单向认证":
                    context.verify_mode = ssl.CERT_NONE
                else:
                    context.verify_mode = ssl.CERT_REQUIRED
                applied = f"协议常量 {ssl_version}"
            else:
                if hasattr(context, "minimum_version"):
                    try:
                        context.minimum_version = ssl.TLSVersion.TLSv1
                        if hasattr(context, "maximum_version") and hasattr(ssl, "TLSVersion") and hasattr(ssl.TLSVersion, "TLSv1_3"):
                            context.maximum_version = ssl.TLSVersion.TLSv1_3
                        applied = "默认(自动协商 TLSv1~TLSv1.3)"
                    except Exception:
                        pass
            # 取消针对 TLS 1.0 的套件强制与服务端优先，恢复默认
            
            # Load certificates
            server_cert = self.server_cert_path.get()
            server_key = self.server_key_path.get()
            ca_cert = self.ca_cert_path.get()
            
            if not server_cert or not server_key:
                raise ValueError("服务器证书和私钥必须选择")
            
            context.load_cert_chain(certfile=server_cert, keyfile=server_key)
            
            if auth_mode == "双向认证":
                if not ca_cert:
                    raise ValueError("双向认证需要CA证书")
                context.load_verify_locations(cafile=ca_cert)
            
            try:
                self.version_policy_desc = f"选择={ssl_version}, 应用={applied}"
            except Exception:
                pass
            
            return context
        except Exception as e:
            raise Exception(f"SSL上下文创建失败: {e}")
    
    def start_server(self):
        try:
            self.ssl_context = self._build_ssl_context()
        except Exception as e:
            messagebox.showerror("SSL配置错误", str(e))
            return
        
        self.running = True
        self.stop_event.clear()
        self.listen_btn.config(text="停止侦听")
        self._status(f"服务器启动中... 端口: {self.port_var.get()}")
        try:
            self._log(f"服务器版本策略: {getattr(self, 'version_policy_desc', '未知')}")
        except Exception:
            pass
        
        self.server_thread = threading.Thread(target=self._server_loop, daemon=True)
        self.server_thread.start()
    
    def stop_server(self):
        self.running = False
        self.stop_event.set()
        
        if self.server_sock:
            try:
                self.server_sock.close()
            except Exception:
                pass
        
        with self.lock:
            clients_copy = list(self.clients.items())
        for sock, (thread, addr) in clients_copy:
            try:
                sock.shutdown(socket.SHUT_RDWR)
                sock.close()
            except Exception:
                pass
        
        self.listen_btn.config(text="开始侦听")
        self._status("服务器已停止")
        self._log("服务器已停止")
        
        # Clear client list
        self.client_listbox.delete(0, tk.END)
    
    def _server_loop(self):
        try:
            # Create server socket
            family = socket.AF_INET6 if self.use_ipv6_var.get() else socket.AF_INET
            self.server_sock = socket.socket(family, socket.SOCK_STREAM)
            self.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            # Bind to all interfaces
            bind_addr = "::" if self.use_ipv6_var.get() else "0.0.0.0"
            self.server_sock.bind((bind_addr, self.port_var.get()))
            self.server_sock.listen(10)
            
            self._log(f"服务器启动成功，监听 {bind_addr}:{self.port_var.get()} ({'IPv6' if self.use_ipv6_var.get() else 'IPv4'})")
            self._status(f"服务器运行中 - 端口: {self.port_var.get()}")
            
        except Exception as e:
            self.ui_queue.put(f"服务器启动失败: {e}")
            self.root.after(0, self.stop_server)
            return
        
        while self.running and not self.stop_event.is_set():
            try:
                self.server_sock.settimeout(1.0)  # Allow periodic checks
                client_sock, addr = self.server_sock.accept()
                
                # Wrap with SSL
                try:
                    ssl_sock = self.ssl_context.wrap_socket(client_sock, server_side=True)
                    try:
                        negotiated = ssl_sock.version() or "未知"
                        cipher = ssl_sock.cipher()
                        cipher_desc = cipher[0] if isinstance(cipher, tuple) else str(cipher)
                        self.ui_queue.put(f"客户端连接: {addr[0]}:{addr[1]} — 协商版本 {negotiated}, 套件 {cipher_desc}")
                        
                    except Exception:
                        self.ui_queue.put(f"客户端连接: {addr[0]}:{addr[1]}")
                    
                    # Add to client list
                    with self.lock:
                        client_thread = threading.Thread(target=self._handle_client, 
                                                      args=(ssl_sock, addr), daemon=True)
                        self.clients[ssl_sock] = (client_thread, addr)
                        client_thread.start()
                    
                    # Update UI
                    self.root.after(0, self._update_client_list)
                    
                except ssl.SSLError as e:
                    msg = str(e)
                    if "VERSION_TOO_LOW" in msg or "version too low" in msg:
                        msg = f"{msg} — 客户端使用的协议版本过低，请使用 TLS 1.2 或更高版本"
                    self.ui_queue.put(f"SSL握手失败 {addr}: {msg}")
                    try:
                        client_sock.close()
                    except Exception:
                        pass
                        
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    self.ui_queue.put(f"服务器错误: {e}")
                break
    
    def _start_external_ssl3_server(self) -> bool:
        try:
            openssl = self.external_openssl_path.get()
            port = int(self.port_var.get())
            cert = self.server_cert_path.get()
            key = self.server_key_path.get()
            ca = self.ca_cert_path.get()
            if not openssl or not os.path.exists(openssl):
                messagebox.showerror("OpenSSL", "外部 OpenSSL 路径不存在")
                return False
            if not cert or not key:
                messagebox.showerror("证书", "请先选择服务器证书与私钥")
                return False
            args = [openssl, "s_server", "-accept", str(port), "-cert", cert, "-key", key, "-ssl3",
                    "-no_tls1", "-no_tls1_1", "-no_tls1_2"]
            if self.auth_mode_var.get() == "双向认证" and ca:
                args += ["-CAfile", ca, "-verify", "1", "-verify_return_error"]
            # Prepare minimal OpenSSL configuration to avoid loading unsupported modules
            try:
                tmp_conf = tempfile.NamedTemporaryFile(prefix="openssl_conf_", suffix=".cnf", delete=False)
                tmp_conf.write(b"# minimal openssl config to disable modules\n")
                tmp_conf.flush()
                tmp_conf.close()
                env = os.environ.copy()
                env["OPENSSL_CONF"] = tmp_conf.name
            except Exception:
                env = os.environ.copy()
                env.pop("OPENSSL_CONF", None)
            # Prefer running in the OpenSSL bin directory so DLLs can be found
            cwd = os.path.dirname(openssl) or None
            try:
                self.external_proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env, cwd=cwd)
            except Exception as e:
                messagebox.showerror("OpenSSL", f"启动外部 OpenSSL 失败: {e}")
                return False
            # Start IO threads
            def _pump(stream, tag):
                try:
                    for line in iter(stream.readline, ''):
                        line = line.strip()
                        if line:
                            self.ui_queue.put(f"[OpenSSL {tag}] {line}")
                except Exception:
                    pass
            self.external_stdout_thread = threading.Thread(target=_pump, args=(self.external_proc.stdout, 'OUT'), daemon=True)
            self.external_stderr_thread = threading.Thread(target=_pump, args=(self.external_proc.stderr, 'ERR'), daemon=True)
            self.external_stdout_thread.start()
            self.external_stderr_thread.start()
            return True
        except Exception as e:
            messagebox.showerror("OpenSSL", f"外部 SSLv3 启动错误: {e}")
            return False

    def _handle_client(self, ssl_sock, addr):
        try:
            while self.running and not self.stop_event.is_set():
                ssl_sock.settimeout(1.0)
                try:
                    data = ssl_sock.recv(4096)
                    if not data:
                        break
                    
                    self.recv_bytes.set(self.recv_bytes.get() + len(data))
                    
                    # Display received data
                    try:
                        text = data.decode('utf-8')
                        self.ui_queue.put(f"<- {addr[0]}:{addr[1]}: {text}")
                    except UnicodeDecodeError:
                        self.ui_queue.put(f"<- {addr[0]}:{addr[1]}: HEX {data.hex()}")
                    
                    if self.auto_reply_var.get():
                        mode = self.data_mode_var.get()
                        if mode == "透明":
                            try:
                                ssl_sock.send(data)
                                self.sent_bytes.set(self.sent_bytes.get() + len(data))
                                try:
                                    echo_text = data.decode('utf-8')
                                    self.ui_queue.put(f"-> {addr[0]}:{addr[1]}: {echo_text}")
                                except UnicodeDecodeError:
                                    self.ui_queue.put(f"-> {addr[0]}:{addr[1]}: HEX {data.hex()}")
                            except Exception:
                                pass
                        elif mode == "数据":
                            default_payload = "START100raib18mkuz94k5ha9rys117x8v6g3klz93fn318z1d7pkg6wy2np4zl4zv5ilzpmwgshfv09dkwd7l9qw3l0zz100END"
                            text_to_send = self.send_text_cache if self.send_text_cache else default_payload
                            try:
                                payload = text_to_send.encode('utf-8')
                                ssl_sock.send(payload)
                                self.sent_bytes.set(self.sent_bytes.get() + len(text_to_send))
                                self.ui_queue.put(f"-> {addr[0]}:{addr[1]}: {text_to_send}")
                            except Exception:
                                pass
                        else:
                            reply = f"服务器收到: {len(data)}字节\n"
                            try:
                                ssl_sock.send(reply.encode('utf-8'))
                                self.sent_bytes.set(self.sent_bytes.get() + len(reply))
                                self.ui_queue.put(f"-> {addr[0]}:{addr[1]}: {reply.strip()}")
                            except Exception:
                                pass
                        
                except socket.timeout:
                    continue
                except Exception:
                    break
        except Exception as e:
            self.ui_queue.put(f"客户端处理错误 {addr}: {e}")
        finally:
            self._remove_client(ssl_sock, addr)
    
    def _remove_client(self, ssl_sock, addr):
        try:
            ssl_sock.shutdown(socket.SHUT_RDWR)
            ssl_sock.close()
        except Exception:
            pass
        with self.lock:
            if ssl_sock in self.clients:
                del self.clients[ssl_sock]
        self.ui_queue.put(f"客户端断开: {addr[0]}:{addr[1]}")
        self.root.after(0, self._update_client_list)
    
    def _update_client_list(self):
        self.client_listbox.delete(0, tk.END)
        with self.lock:
            for sock, (thread, addr) in self.clients.items():
                self.client_listbox.insert(tk.END, f"{addr[0]}:{addr[1]}")
    
    def _disconnect_selected_client(self):
        selection = self.client_listbox.curselection()
        if not selection:
            return
        
        with self.lock:
            clients_list = list(self.clients.items())
        
        if selection[0] < len(clients_list):
            sock, (thread, addr) = clients_list[selection[0]]
            self._remove_client(sock, addr)
    
    def _disconnect_all_clients(self):
        with self.lock:
            clients_copy = list(self.clients.items())
        
        for sock, (thread, addr) in clients_copy:
            self._remove_client(sock, addr)
    
    def _send_to_selected(self):
        selection = self.client_listbox.curselection()
        if not selection:
            messagebox.showwarning("未选择", "请先选择一个客户端")
            return
        
        text = self.send_text.get("1.0", tk.END).strip()
        if not text:
            return
        
        with self.lock:
            clients_list = list(self.clients.items())
        
        if selection[0] < len(clients_list):
            sock, (thread, addr) = clients_list[selection[0]]
            try:
                sock.send(text.encode('utf-8'))
                self.sent_bytes.set(self.sent_bytes.get() + len(text))
                self._log(f"-> {addr[0]}:{addr[1]}: {text}")
            except Exception as e:
                self._log(f"发送失败 {addr}: {e}")


class TLSClientApp:
    def __init__(self, root: tk.Tk, config_manager):
        self.root = root
        self.config_manager = config_manager
        
        # Client state
        self.ssl_sock = None
        self.tcp_sock = None
        self.recv_thread = None
        self.connected = False
        self.stop_event = threading.Event()
        self.ui_queue = queue.Queue()

        # Variables from config
        self.host_var = tk.StringVar(value=config_manager.config["client"]["host"])
        self.port_var = tk.IntVar(value=config_manager.config["client"]["port"])
        self.auth_mode_var = tk.StringVar(value=config_manager.config["client"]["auth_mode"])
        self.ssl_version_var = tk.StringVar(value=config_manager.config["client"].get("ssl_version", "默认"))
        self.hex_send_var = tk.BooleanVar(value=config_manager.config["client"]["hex_send"])

        self.sent_bytes = tk.IntVar(value=0)
        self.recv_bytes = tk.IntVar(value=0)

        self.ca_cert_path = tk.StringVar(value=config_manager.config["client"]["ca_cert"])
        self.client_cert_path = tk.StringVar(value=config_manager.config["client"]["client_cert"])
        self.client_key_path = tk.StringVar(value=config_manager.config["client"]["client_key"])

        self._build_ui()

        # drain UI queue periodically
        self.root.after(100, self._process_ui_queue)

    def _build_ui(self):
        # Top Bar: options and counters
        top = ttk.LabelFrame(self.root, text="SSL/TCP 客户端")
        top.pack(side=tk.TOP, fill=tk.X, padx=8, pady=6)

        ttk.Label(top, text="SSL/TLS版本:").grid(row=0, column=0, padx=6, pady=6, sticky=tk.W)
        ttk.Combobox(top, textvariable=self.ssl_version_var, values=["默认", "TLS 1.0", "TLS 1.1", "TLS 1.2", "TLS 1.3"], width=10, state="readonly").grid(
            row=0, column=1, padx=2, pady=6
        )

        ttk.Label(top, text="认证方式:").grid(row=0, column=2, padx=6, pady=6, sticky=tk.W)
        ttk.Combobox(top, textvariable=self.auth_mode_var, values=["单向", "双向"], width=6, state="readonly").grid(
            row=0, column=3, padx=2, pady=6
        )

        # Certificate selectors
        ttk.Button(top, text="客户端证书…", command=self._choose_client_cert).grid(row=0, column=4, padx=6)
        self.client_cert_label = ttk.Label(top, text="未选择")
        self.client_cert_label.grid(row=0, column=5, sticky=tk.W)

        ttk.Button(top, text="客户端私钥…", command=self._choose_client_key).grid(row=0, column=6, padx=6)
        self.client_key_label = ttk.Label(top, text="未选择")
        self.client_key_label.grid(row=0, column=7, sticky=tk.W)

        ttk.Button(top, text="CA证书…", command=self._choose_ca_cert).grid(row=0, column=8, padx=6)
        self.ca_cert_label = ttk.Label(top, text="未选择")
        self.ca_cert_label.grid(row=0, column=9, sticky=tk.W)

        # Address & port
        ttk.Label(top, text="地址:").grid(row=1, column=0, padx=6, pady=6, sticky=tk.W)
        ttk.Entry(top, textvariable=self.host_var, width=18).grid(row=1, column=1, padx=2, pady=6)

        ttk.Label(top, text="端口:").grid(row=1, column=2, padx=6, pady=6, sticky=tk.E)
        ttk.Entry(top, textvariable=self.port_var, width=8).grid(row=1, column=3, padx=2, pady=6, sticky=tk.W)

        self.connect_btn = ttk.Button(top, text="连接", command=self.toggle_connect)
        self.connect_btn.grid(row=1, column=4, padx=6)

        # Counters
        ttk.Label(top, text="发送:").grid(row=1, column=5, padx=6, sticky=tk.E)
        ttk.Entry(top, textvariable=self.sent_bytes, width=10, state="readonly").grid(row=1, column=6, padx=2, sticky=tk.W)

        ttk.Label(top, text="接收:").grid(row=1, column=7, padx=6, sticky=tk.E)
        ttk.Entry(top, textvariable=self.recv_bytes, width=10, state="readonly").grid(row=1, column=8, padx=2, sticky=tk.W)

        # Log area
        self.log = ScrolledText(self.root, wrap=tk.WORD, height=18)
        self.log.pack(fill=tk.BOTH, expand=True, padx=8, pady=6)

        # Bottom: send area
        bottom = ttk.Frame(self.root)
        bottom.pack(side=tk.BOTTOM, fill=tk.X, padx=8, pady=6)

        ttk.Button(bottom, text="清空", command=self._clear_log).pack(side=tk.LEFT)

        self.send_text = tk.Text(bottom, height=4)
        self.send_text.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=8)

        ttk.Checkbutton(bottom, text="Hex", variable=self.hex_send_var).pack(side=tk.LEFT)
        ttk.Button(bottom, text="发送", command=self.send_message).pack(side=tk.RIGHT)

        # Status bar
        self.status_var = tk.StringVar(value="未连接")
        status = ttk.Label(self.root, textvariable=self.status_var, anchor=tk.W)
        status.pack(fill=tk.X, padx=8, pady=(0, 8))

        # Close handling - only set protocol if this is the root window
        if hasattr(self.root, 'protocol'):
            self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        try:
            self._update_cert_labels()
        except Exception:
            pass

    # --- UI helpers ---
    def _choose_client_cert(self):
        path = filedialog.askopenfilename(title="选择客户端证书 (PEM/CRT)", filetypes=[
            ("PEM/CRT", "*.pem *.crt"), ("All", "*.*")
        ])
        if path:
            self.client_cert_path.set(path)
            self.config_manager.config["client"]["client_cert"] = path
            self.client_cert_label.config(text=os.path.basename(path))

    def _choose_client_key(self):
        path = filedialog.askopenfilename(title="选择客户端私钥 (PEM/KEY)", filetypes=[
            ("PEM/KEY", "*.pem *.key"), ("All", "*.*")
        ])
        if path:
            self.client_key_path.set(path)
            self.config_manager.config["client"]["client_key"] = path
            self.client_key_label.config(text=os.path.basename(path))

    def _choose_ca_cert(self):
        path = filedialog.askopenfilename(title="选择CA证书 (PEM/CRT)", filetypes=[
            ("PEM/CRT", "*.pem *.crt"), ("All", "*.*")
        ])
        if path:
            self.ca_cert_path.set(path)
            self.config_manager.config["client"]["ca_cert"] = path
            self.ca_cert_label.config(text=os.path.basename(path))

    def _update_cert_labels(self):
        try:
            self.client_cert_label.config(text=os.path.basename(self.client_cert_path.get()) if self.client_cert_path.get() else "未选择")
        except Exception:
            pass
        try:
            self.client_key_label.config(text=os.path.basename(self.client_key_path.get()) if self.client_key_path.get() else "未选择")
        except Exception:
            pass
        try:
            self.ca_cert_label.config(text=os.path.basename(self.ca_cert_path.get()) if self.ca_cert_path.get() else "未选择")
        except Exception:
            pass

    def _clear_log(self):
        self.log.delete("1.0", tk.END)

    def _log(self, text: str):
        stamp = datetime.now().strftime("%H:%M:%S")
        line = f"[{stamp}] {text}"
        self.log.insert(tk.END, line + "\n")
        self.log.see(tk.END)
        try:
            self.config_manager.append_log(line)
        except Exception:
            pass

    def _status(self, text: str):
        self.status_var.set(text)

    def _process_ui_queue(self):
        while True:
            try:
                msg = self.ui_queue.get_nowait()
            except queue.Empty:
                break
            self._log(msg)
        self.root.after(100, self._process_ui_queue)

    # --- Connection management ---
    def toggle_connect(self):
        if not self.connected:
            self._connect()
        else:
            self._disconnect()

    def _build_context(self) -> ssl.SSLContext:
        mode = self.auth_mode_var.get()
        ssl_version = self.ssl_version_var.get()
        ca = self.ca_cert_path.get() or None
        cert = self.client_cert_path.get() or None
        key = self.client_key_path.get() or None

        if mode == "双向":
            ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
            if ca:
                ctx.load_verify_locations(cafile=ca)
            ctx.check_hostname = False
            if not cert or not key:
                raise ValueError("双向认证需要选择客户端证书与私钥")
            ctx.load_cert_chain(certfile=cert, keyfile=key)
        else:
            if ca:
                ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
                ctx.load_verify_locations(cafile=ca)
                ctx.check_hostname = False
                try:
                    ctx.verify_mode = ssl.CERT_REQUIRED
                except Exception:
                    pass
            else:
                # 单向且不校验证书（便于调试）
                ctx = ssl._create_unverified_context()
                ctx.check_hostname = False
                try:
                    ctx.verify_mode = ssl.CERT_NONE
                except Exception:
                    pass
        
        applied = "默认"
        if ssl_version.startswith("TLS ") and hasattr(ssl, "TLSVersion"):
            try:
                mapping = {
                    "TLS 1.0": ssl.TLSVersion.TLSv1,
                    "TLS 1.1": ssl.TLSVersion.TLSv1_1,
                    "TLS 1.2": ssl.TLSVersion.TLSv1_2,
                    "TLS 1.3": ssl.TLSVersion.TLSv1_3,
                }
                ver = mapping.get(ssl_version)
                if ver is not None:
                    if hasattr(ctx, "minimum_version"):
                        ctx.minimum_version = ver
                    if hasattr(ctx, "maximum_version"):
                        ctx.maximum_version = ver
                    applied = f"固定 {ssl_version}"
            except Exception:
                pass
        elif ssl_version == "默认" and hasattr(ctx, 'minimum_version'):
            try:
                ctx.minimum_version = ssl.TLSVersion.TLSv1
                if hasattr(ctx, 'maximum_version') and hasattr(ssl, 'TLSVersion') and hasattr(ssl.TLSVersion, 'TLSv1_3'):
                    ctx.maximum_version = ssl.TLSVersion.TLSv1_3
                applied = "默认(自动协商 TLSv1~TLSv1.3)"
            except Exception:
                pass
        try:
            self.version_policy_desc = f"选择={ssl_version}, 应用={applied}"
        except Exception:
            pass

        # Cipher preferences to align with legacy TLSv1 clients: prefer 3DES over AES
        # 取消针对 TLS 1.0 的套件强制，恢复默认
        
        return ctx

    def _connect(self):
        host = self.host_var.get().strip().strip("[]")
        port = int(self.port_var.get())
        try:
            ctx = self._build_context()
        except Exception as e:
            messagebox.showerror("SSL 配置错误", str(e))
            return

        try:
            infos = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
        except socket.gaierror as e:
            messagebox.showerror("地址解析失败", f"{host}:{port} -> {e}")
            return

        last_err = None
        for family, socktype, proto, canonname, sockaddr in infos:
            try:
                s = socket.socket(family, socktype, proto)
                # 启用 TCP keepalive，减少中间设备空闲断开概率
                try:
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                except Exception:
                    pass
                # 连接阶段使用有限超时，避免长时间阻塞
                s.settimeout(5)
                s.connect(sockaddr)
                # 连接后恢复为阻塞模式，避免因空闲触发超时
                s.settimeout(None)
                self.tcp_sock = s
                break
            except OSError as e:
                last_err = e
                try:
                    s.close()
                except Exception:
                    pass
                self.tcp_sock = None
        if not self.tcp_sock:
            messagebox.showerror("连接失败", f"无法连接到 {host}:{port}\n{last_err}")
            return

        try:
            server_hostname = None if is_ip_address(host) else host
            self.ssl_sock = ctx.wrap_socket(self.tcp_sock, server_hostname=server_hostname)
            # 包装后的 SSL 套接字也设为阻塞，避免 5s 超时导致误判断开
            try:
                self.ssl_sock.settimeout(None)
            except Exception:
                pass
        except Exception as e:
            try:
                self.tcp_sock.close()
            except Exception:
                pass
            self.tcp_sock = None
            messagebox.showerror("TLS 握手失败", str(e))
            return

        self.connected = True
        self.stop_event.clear()
        self.connect_btn.config(text="断开")
        self._status("已连接")
        self._log(f"已连接到 {host}:{port} — 使用 {'IPv6' if ':' in host else 'IPv4'}")
        try:
            negotiated = self.ssl_sock.version() or "未知"
            cipher = self.ssl_sock.cipher()
            cipher_desc = cipher[0] if isinstance(cipher, tuple) else str(cipher)
            self._log(f"客户端版本策略: {getattr(self, 'version_policy_desc', '未知')} — 协商版本 {negotiated}, 套件 {cipher_desc}")
        except Exception:
            pass

        # Start receiver thread
        self.recv_thread = threading.Thread(target=self._recv_loop, daemon=True)
        self.recv_thread.start()

    def _disconnect(self):
        self.stop_event.set()
        self.connected = False
        try:
            if self.ssl_sock:
                try:
                    self.ssl_sock.shutdown(socket.SHUT_RDWR)
                except Exception:
                    pass
                self.ssl_sock.close()
        finally:
            self.ssl_sock = None
        try:
            if self.tcp_sock:
                self.tcp_sock.close()
        finally:
            self.tcp_sock = None

        self.connect_btn.config(text="连接")
        self._status("未连接")
        self._log("连接已断开")

    def _recv_loop(self):
        while not self.stop_event.is_set() and self.ssl_sock:
            try:
                data = self.ssl_sock.recv(4096)
                if not data:
                    self.ui_queue.put("对端关闭连接")
                    break
                self.recv_bytes.set(self.recv_bytes.get() + len(data))
                try:
                    text = data.decode("utf-8")
                    self.ui_queue.put(f"<- {text}")
                except UnicodeDecodeError:
                    self.ui_queue.put(f"<- HEX {data.hex()}")
            except socket.timeout:
                # 超时不代表断开，继续等待新数据
                continue
            except OSError:
                break
        self.root.after(0, self._disconnect)

    # --- Send ---
    def send_message(self):
        if not self.connected or not self.ssl_sock:
            messagebox.showwarning("未连接", "请先连接服务器")
            return
        text = self.send_text.get("1.0", tk.END).strip()
        if not text:
            return
        try:
            if self.hex_send_var.get():
                payload = bytes.fromhex("".join(text.split()))
            else:
                payload = text.encode("utf-8")
            self.ssl_sock.sendall(payload)
            self.sent_bytes.set(self.sent_bytes.get() + len(payload))
            self._log(f"-> {'HEX ' if self.hex_send_var.get() else ''}{text}")
        except ValueError:
            messagebox.showerror("Hex 格式错误", "请输入合法的十六进制字符串，如: 48 65 6C 6C 6F")
        except Exception as e:
            messagebox.showerror("发送失败", str(e))

    def _on_close(self):
        try:
            self._disconnect()
        finally:
            self.root.destroy()


class TLSToolApplication:
    def __init__(self, root: tk.Tk, mode="client", config_file="tls_config.json", autostart=False, log_file=None):
        self.root = root
        self.mode = mode
        self.autostart = autostart
        self.log_file = log_file
        
        # Set window properties
        self.root.title("IPv4/IPv6 TLS 工具集")
        self.root.geometry("1000x700")
        try:
            if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
                base_dir = sys._MEIPASS
            else:
                base_dir = os.path.dirname(os.path.abspath(__file__))
        except Exception:
            base_dir = os.path.dirname(os.path.abspath(__file__))
        # Normalize config file path to be relative to executable/script directory when not absolute
        try:
            config_base = os.path.dirname(sys.executable) if getattr(sys, "frozen", False) else os.path.dirname(os.path.abspath(__file__))
            if not os.path.isabs(config_file):
                config_file = os.path.join(config_base, config_file)
        except Exception:
            pass
        self.config_manager = ConfigManager(config_file, log_file=self.log_file)
        ico = os.path.join(base_dir, "app.ico")

        png = os.path.join(base_dir, "app.png")
        if os.path.exists(ico):
            try:
                self.root.iconbitmap(ico)
            except Exception:
                pass
        elif os.path.exists(png):
            try:
                self.root.iconphoto(True, tk.PhotoImage(file=png))
            except Exception:
                pass
        
        # Create menu bar
        self.create_menu_bar()
        
        # Create notebook for tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Create tabs based on mode
        if mode == "server" or mode == "both":
            self.server_frame = ttk.Frame(self.notebook)
            self.notebook.add(self.server_frame, text="SSL TCP服务器")
            self.server_app = TLSServerApp(self.server_frame, self.config_manager)
        
        if mode == "client" or mode == "both":
            self.client_frame = ttk.Frame(self.notebook)
            self.notebook.add(self.client_frame, text="SSL TCP客户端")
            self.client_app = TLSClientApp(self.client_frame, self.config_manager)
        
        if mode == "both" and hasattr(self, "server_frame"):
            self.notebook.select(self.server_frame)
        
        if self.autostart:
            def _do_autostart():
                if self.mode in ("server", "both") and hasattr(self, "server_app"):
                    try:
                        self.server_app.start_server()
                    except Exception:
                        pass
                if self.mode in ("client", "both") and hasattr(self, "client_app"):
                    try:
                        self.client_app._connect()
                    except Exception:
                        pass
            self.root.after(200, _do_autostart)
        
        # Bind window close event
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
    
    def create_menu_bar(self):
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="文件", menu=file_menu)
        file_menu.add_command(label="保存配置", command=self.save_config)
        file_menu.add_separator()
        file_menu.add_command(label="退出", command=self.on_close)
        
        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="帮助", menu=help_menu)
        help_menu.add_command(label="关于", command=self.show_about)
    
    def save_config(self):
        # Update config with current values
        if hasattr(self, 'client_app'):
            client_config = self.config_manager.config["client"]
            client_config["host"] = self.client_app.host_var.get()
            client_config["port"] = self.client_app.port_var.get()
            client_config["auth_mode"] = self.client_app.auth_mode_var.get()
            client_config["ssl_version"] = self.client_app.ssl_version_var.get()
            client_config["hex_send"] = self.client_app.hex_send_var.get()
            client_config["client_cert"] = self.client_app.client_cert_path.get()
            client_config["client_key"] = self.client_app.client_key_path.get()
            client_config["ca_cert"] = self.client_app.ca_cert_path.get()
        
        if hasattr(self, 'server_app'):
            server_config = self.config_manager.config["server"]
            server_config["port"] = self.server_app.port_var.get()
            server_config["use_ipv6"] = self.server_app.use_ipv6_var.get()
            server_config["ssl_version"] = self.server_app.ssl_version_var.get()
            server_config["auth_mode"] = self.server_app.auth_mode_var.get()
            server_config["auto_reply"] = self.server_app.auto_reply_var.get()
            server_config["data_mode"] = self.server_app.data_mode_var.get()
            server_config["server_cert"] = self.server_app.server_cert_path.get()
            server_config["server_key"] = self.server_app.server_key_path.get()
            server_config["ca_cert"] = self.server_app.ca_cert_path.get()
        
        self.config_manager.save_config()
        messagebox.showinfo("配置", "配置已保存")
    
    def show_about(self):
        messagebox.showinfo("关于", "IPv4/IPv6 TLS 工具集 v2.0\n\n支持SSL/TLS客户端和服务器模式\n支持IPv4/IPv6双栈\n支持TLS 1.0到TLS 1.3版本")
    
    def on_close(self):
        try:
            if hasattr(self, 'client_app'):
                self.client_app._disconnect()
            if hasattr(self, 'server_app'):
                self.server_app.stop_server()
        finally:
            self.root.destroy()


def _normalize_config_path(config_file: str) -> str:
    try:
        config_base = os.path.dirname(sys.executable) if getattr(sys, "frozen", False) else os.path.dirname(os.path.abspath(__file__))
    except Exception:
        config_base = os.path.dirname(os.path.abspath(__file__))
    cfg = config_file or "tls_config.json"
    if not os.path.isabs(cfg):
        cfg = os.path.join(config_base, cfg)
    return cfg


def _resolve_config_relative(path_value: str, config_file: str) -> str:
    p = (path_value or "").strip()
    if not p:
        return ""
    if os.path.isabs(p):
        return p
    try:
        base_dir = os.path.dirname(os.path.abspath(config_file))
    except Exception:
        base_dir = os.getcwd()
    return os.path.join(base_dir, p)


def _stamp() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _headless_log(config_manager: ConfigManager, text: str):
    line = f"[{_stamp()}] {text}"
    try:
        print(line, flush=True)
    except Exception:
        pass
    try:
        config_manager.append_log(line)
    except Exception:
        pass


class _HeadlessTLSServer:
    def __init__(self, config_manager: ConfigManager, config_file: str, stop_event: threading.Event):
        self.config_manager = config_manager
        self.config_file = config_file
        self.stop_event = stop_event
        self.server_sock = None
        self.clients_lock = threading.Lock()
        self.clients = set()

    def _make_context(self) -> ssl.SSLContext:
        server_cfg = self.config_manager.config.get("server", {})
        ssl_version_str = server_cfg.get("ssl_version", "默认")
        protocol = self.config_manager.get_ssl_version(ssl_version_str) or getattr(ssl, "PROTOCOL_TLS_SERVER", ssl.PROTOCOL_TLS)
        ctx = ssl.SSLContext(protocol)

        if hasattr(ssl, "TLSVersion") and ssl_version_str and ssl_version_str != "默认":
            version_map = {
                "TLS 1.0": getattr(ssl.TLSVersion, "TLSv1", None),
                "TLS 1.1": getattr(ssl.TLSVersion, "TLSv1_1", None),
                "TLS 1.2": getattr(ssl.TLSVersion, "TLSv1_2", None),
                "TLS 1.3": getattr(ssl.TLSVersion, "TLSv1_3", None),
            }
            v = version_map.get(ssl_version_str)
            if v is not None:
                try:
                    ctx.minimum_version = v
                    ctx.maximum_version = v
                except Exception:
                    pass

        cert = _resolve_config_relative(server_cfg.get("server_cert", ""), self.config_file)
        key = _resolve_config_relative(server_cfg.get("server_key", ""), self.config_file)
        if not cert or not key:
            raise RuntimeError("请先在配置文件中设置服务器证书与私钥")
        ctx.load_cert_chain(certfile=cert, keyfile=key)

        auth_mode = server_cfg.get("auth_mode", "单向认证")
        if auth_mode == "双向认证":
            ca = _resolve_config_relative(server_cfg.get("ca_cert", ""), self.config_file)
            if not ca:
                raise RuntimeError("双向认证需要设置CA证书")
            ctx.verify_mode = ssl.CERT_REQUIRED
            ctx.load_verify_locations(cafile=ca)
        else:
            ctx.verify_mode = ssl.CERT_NONE

        return ctx

    def stop(self):
        try:
            if self.server_sock:
                try:
                    self.server_sock.close()
                except Exception:
                    pass
        finally:
            with self.clients_lock:
                clients = list(self.clients)
                self.clients.clear()
            for s in clients:
                try:
                    s.close()
                except Exception:
                    pass

    def _handle_client(self, ssl_sock: ssl.SSLSocket, addr, auto_reply: bool, data_mode: str):
        try:
            while not self.stop_event.is_set():
                try:
                    ssl_sock.settimeout(1.0)
                    data = ssl_sock.recv(4096)
                    if not data:
                        break
                    try:
                        _headless_log(self.config_manager, f"<- {addr[0]}:{addr[1]}: {data.decode('utf-8')}")
                    except Exception:
                        _headless_log(self.config_manager, f"<- {addr[0]}:{addr[1]}: HEX {data.hex()}")

                    if not auto_reply:
                        continue

                    if data_mode == "透明":
                        try:
                            ssl_sock.sendall(data)
                            try:
                                _headless_log(self.config_manager, f"-> {addr[0]}:{addr[1]}: {data.decode('utf-8')}")
                            except Exception:
                                _headless_log(self.config_manager, f"-> {addr[0]}:{addr[1]}: HEX {data.hex()}")
                        except Exception:
                            pass
                    elif data_mode == "数据":
                        default_payload = "START100raib18mkuz94k5ha9rys117x8v6g3klz93fn318z1d7pkg6wy2np4zl4zv5ilzpmwgshfv09dkwd7l9qw3l0zz100END"
                        payload = default_payload.encode("utf-8")
                        try:
                            ssl_sock.sendall(payload)
                            _headless_log(self.config_manager, f"-> {addr[0]}:{addr[1]}: {default_payload}")
                        except Exception:
                            pass
                    else:
                        reply = f"服务器收到: {len(data)}字节\n"
                        try:
                            ssl_sock.sendall(reply.encode("utf-8"))
                            _headless_log(self.config_manager, f"-> {addr[0]}:{addr[1]}: {reply.strip()}")
                        except Exception:
                            pass
                except socket.timeout:
                    continue
                except Exception:
                    break
        finally:
            with self.clients_lock:
                try:
                    self.clients.discard(ssl_sock)
                except Exception:
                    pass
            try:
                ssl_sock.close()
            except Exception:
                pass
            _headless_log(self.config_manager, f"客户端断开: {addr[0]}:{addr[1]}")

    def run(self) -> int:
        server_cfg = self.config_manager.config.get("server", {})
        port = int(server_cfg.get("port", 8443))
        use_ipv6 = bool(server_cfg.get("use_ipv6", False))
        auto_reply = bool(server_cfg.get("auto_reply", True))
        data_mode = server_cfg.get("data_mode", "透明")

        ctx = self._make_context()

        family = socket.AF_INET6 if use_ipv6 else socket.AF_INET
        bind_addr = "::" if use_ipv6 else "0.0.0.0"

        sock = socket.socket(family, socket.SOCK_STREAM)
        self.server_sock = sock
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((bind_addr, port))
        sock.listen(10)
        sock.settimeout(1.0)

        _headless_log(self.config_manager, f"服务器启动成功，监听 {bind_addr}:{port} ({'IPv6' if use_ipv6 else 'IPv4'})")

        try:
            while not self.stop_event.is_set():
                try:
                    client_sock, addr = sock.accept()
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.stop_event.is_set():
                        break
                    _headless_log(self.config_manager, f"accept失败: {e}")
                    continue

                try:
                    ssl_sock = ctx.wrap_socket(client_sock, server_side=True)
                    negotiated = None
                    try:
                        negotiated = ssl_sock.version()
                    except Exception:
                        negotiated = None
                    _headless_log(self.config_manager, f"客户端连接: {addr[0]}:{addr[1]} TLS={negotiated or '未知'}")
                except Exception as e:
                    try:
                        client_sock.close()
                    except Exception:
                        pass
                    _headless_log(self.config_manager, f"SSL握手失败 {addr}: {e}")
                    continue

                with self.clients_lock:
                    self.clients.add(ssl_sock)
                t = threading.Thread(target=self._handle_client, args=(ssl_sock, addr, auto_reply, data_mode), daemon=True)
                t.start()
        finally:
            self.stop()
        return 0


def _headless_client_run(config_manager: ConfigManager, config_file: str, stop_event: threading.Event) -> int:
    client_cfg = config_manager.config.get("client", {})
    host = (client_cfg.get("host") or "").strip() or "127.0.0.1"
    port = int(client_cfg.get("port", 8443))
    auth_mode = (client_cfg.get("auth_mode") or "").strip() or "单向"
    ssl_version_str = (client_cfg.get("ssl_version") or "默认").strip()

    protocol = config_manager.get_ssl_version(ssl_version_str) or getattr(ssl, "PROTOCOL_TLS_CLIENT", ssl.PROTOCOL_TLS)
    ctx = ssl.SSLContext(protocol)
    ctx.check_hostname = False

    if hasattr(ssl, "TLSVersion") and ssl_version_str and ssl_version_str != "默认":
        version_map = {
            "TLS 1.0": getattr(ssl.TLSVersion, "TLSv1", None),
            "TLS 1.1": getattr(ssl.TLSVersion, "TLSv1_1", None),
            "TLS 1.2": getattr(ssl.TLSVersion, "TLSv1_2", None),
            "TLS 1.3": getattr(ssl.TLSVersion, "TLSv1_3", None),
        }
        v = version_map.get(ssl_version_str)
        if v is not None:
            try:
                ctx.minimum_version = v
                ctx.maximum_version = v
            except Exception:
                pass

    ca = _resolve_config_relative(client_cfg.get("ca_cert", ""), config_file)
    if ca:
        try:
            ctx.load_verify_locations(cafile=ca)
            ctx.verify_mode = ssl.CERT_REQUIRED
        except Exception:
            ctx.verify_mode = ssl.CERT_NONE
    else:
        ctx.verify_mode = ssl.CERT_NONE

    if auth_mode in ("双向", "双向认证"):
        cert = _resolve_config_relative(client_cfg.get("client_cert", ""), config_file)
        key = _resolve_config_relative(client_cfg.get("client_key", ""), config_file)
        if cert and key:
            ctx.load_cert_chain(certfile=cert, keyfile=key)

    family = socket.AF_INET6 if ":" in host and not host.startswith("[") else socket.AF_INET
    tcp_sock = socket.socket(family, socket.SOCK_STREAM)
    tcp_sock.settimeout(10.0)
    _headless_log(config_manager, f"客户端连接: {host}:{port}")
    tcp_sock.connect((host.strip("[]"), port))

    server_hostname = None if is_ip_address(host) else host.strip("[]")
    ssl_sock = ctx.wrap_socket(tcp_sock, server_hostname=server_hostname)
    ssl_sock.settimeout(1.0)
    try:
        _headless_log(config_manager, f"客户端已连接 TLS={ssl_sock.version() or '未知'}")
    except Exception:
        _headless_log(config_manager, "客户端已连接")

    try:
        while not stop_event.is_set():
            try:
                data = ssl_sock.recv(4096)
                if not data:
                    break
                try:
                    _headless_log(config_manager, f"<- {data.decode('utf-8')}")
                except Exception:
                    _headless_log(config_manager, f"<- HEX {data.hex()}")
            except socket.timeout:
                continue
            except Exception:
                break
    finally:
        try:
            ssl_sock.close()
        except Exception:
            pass
    return 0 if stop_event.is_set() else 1


def run_headless(mode: str, config_file: str, stop_event: threading.Event = None, log_file: str = None) -> int:
    cfg = _normalize_config_path(config_file)
    config_manager = ConfigManager(cfg, log_file=log_file)
    stop = stop_event or threading.Event()
    _headless_log(config_manager, f"headless启动: mode={mode} config={cfg}")
    if mode == "server":
        server = _HeadlessTLSServer(config_manager, cfg, stop)
        return server.run()
    if mode == "client":
        return _headless_client_run(config_manager, cfg, stop)
    if mode == "both":
        server = _HeadlessTLSServer(config_manager, cfg, stop)
        server_thread = threading.Thread(target=server.run, daemon=True)
        server_thread.start()
        try:
            return _headless_client_run(config_manager, cfg, stop)
        finally:
            stop.set()
            server.stop()
    raise RuntimeError(f"未知mode: {mode}")


def _service_cli(argv: list) -> int:
    import argparse
    try:
        import win32serviceutil
        import win32service
    except Exception as e:
        raise RuntimeError(f"pywin32不可用: {e}")

    parser = argparse.ArgumentParser(prog="service")
    sub = parser.add_subparsers(dest="action", required=True)

    p_install = sub.add_parser("install")
    p_install.add_argument("--name", default="PyIPv6_TLS_Tool")
    p_install.add_argument("--display", default="PyIPv6 TLS Tool")
    p_install.add_argument("--mode", choices=["client", "server", "both"], default="server")
    p_install.add_argument("--config", default="tls_config.json")
    p_install.add_argument("--startup", choices=["auto", "manual"], default="auto")
    p_install.add_argument("--log-dir", default="logs", help="Directory for log files")

    p_uninstall = sub.add_parser("uninstall")
    p_uninstall.add_argument("--name", default="PyIPv6_TLS_Tool")

    p_start = sub.add_parser("start")
    p_start.add_argument("--name", default="PyIPv6_TLS_Tool")

    p_stop = sub.add_parser("stop")
    p_stop.add_argument("--name", default="PyIPv6_TLS_Tool")

    p_status = sub.add_parser("status")
    p_status.add_argument("--name", default="PyIPv6_TLS_Tool")

    args = parser.parse_args(argv)

    if args.action == "install":
        cfg = _normalize_config_path(args.config)
        root_dir = os.path.dirname(os.path.abspath(__file__))
        start_type = win32service.SERVICE_AUTO_START if args.startup == "auto" else win32service.SERVICE_DEMAND_START
        python_class = os.path.splitext(os.path.abspath(__file__))[0] + ".PyIPv6TLSToolService"
        
        # Resolve log dir
        log_dir_val = args.log_dir
        if not os.path.isabs(log_dir_val):
            log_dir_val = os.path.join(root_dir, log_dir_val)
        # Try install; if exists, continue to update options
        try:
            win32serviceutil.InstallService(
                python_class,
                args.name,
                args.display,
                startType=start_type,
                description="TLS server and restarts on failure.",
            )
        except Exception:
            pass
        win32serviceutil.SetServiceCustomOption(args.name, "mode", args.mode)
        win32serviceutil.SetServiceCustomOption(args.name, "config", cfg)
        win32serviceutil.SetServiceCustomOption(args.name, "root", root_dir)
        win32serviceutil.SetServiceCustomOption(args.name, "log_dir", log_dir_val)
        try:
            win32serviceutil.StartService(args.name)
        except Exception:
            pass
        return 0

    if args.action == "uninstall":
        try:
            win32serviceutil.StopService(args.name)
        except Exception:
            pass
        win32serviceutil.RemoveService(args.name)
        return 0

    if args.action == "start":
        win32serviceutil.StartService(args.name)
        return 0

    if args.action == "stop":
        win32serviceutil.StopService(args.name)
        return 0

    if args.action == "status":
        st = win32serviceutil.QueryServiceStatus(args.name)
        print(st)
        return 0

    raise RuntimeError(f"未知action: {args.action}")


try:
    import win32serviceutil
    import win32service
    import win32event
    import servicemanager

    class PyIPv6TLSToolService(win32serviceutil.ServiceFramework):
        _svc_name_ = "PyIPv6_TLS_Tool"
        _svc_display_name_ = "PyIPv6 TLS Tool"
        _svc_description_ = "Runs headless TLS server/client and restarts on failure."

        def __init__(self, args):
            super().__init__(args)
            self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
            self._stop_requested = threading.Event()
            try:
                self._actual_service_name = args[0] if isinstance(args, (list, tuple)) and len(args) > 0 else getattr(self, "_svc_name_", "PyIPv6_TLS_Tool")
            except Exception:
                self._actual_service_name = getattr(self, "_svc_name_", "PyIPv6_TLS_Tool")

        def SvcStop(self):
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            self._stop_requested.set()
            win32event.SetEvent(self.hWaitStop)

        def SvcDoRun(self):
            try:
                service_name = getattr(self, "_actual_service_name", getattr(self, "_svc_name_", "PyIPv6_TLS_Tool"))
                root_dir = win32serviceutil.GetServiceCustomOption(service_name, "root", None)
                mode = win32serviceutil.GetServiceCustomOption(service_name, "mode", "server")
                config_file = win32serviceutil.GetServiceCustomOption(service_name, "config", "tls_config.json")
                log_dir = win32serviceutil.GetServiceCustomOption(service_name, "log_dir", None)
                
                log_file = None
                if log_dir:
                     try:
                         os.makedirs(log_dir, exist_ok=True)
                         log_file = os.path.join(log_dir, "tls_tool.log")
                     except Exception:
                         pass

                if root_dir and os.path.isdir(root_dir):
                    try:
                        os.chdir(root_dir)
                    except Exception:
                        pass
                    try:
                        if root_dir not in sys.path:
                            sys.path.insert(0, root_dir)
                    except Exception:
                        pass

                servicemanager.LogInfoMsg(f"{service_name} starting: mode={mode} config={config_file} log={log_file}")

                while not self._stop_requested.is_set():
                    try:
                        code = run_headless(mode, config_file, stop_event=self._stop_requested, log_file=log_file)
                    except Exception as e:
                        try:
                            cfg = _normalize_config_path(config_file)
                            append_fallback_log(cfg, f"[{_stamp()}] service exception: {e}", log_file=log_file)
                        except Exception:
                            pass
                        code = 1
                    if self._stop_requested.is_set():
                        break
                    if code == 0:
                        win32event.WaitForSingleObject(self.hWaitStop, 1000)
                        continue
                    win32event.WaitForSingleObject(self.hWaitStop, 1000)
            finally:
                try:
                    servicemanager.LogInfoMsg("service stopped")
                except Exception:
                    pass
except Exception:
    PyIPv6TLSToolService = None


def main():
    try:
        # Pre-scan for log dir (do not mutate argv to allow --service to parse it)
        log_file = None
        try:
            if "--log-dir" in sys.argv:
                idx = sys.argv.index("--log-dir")
                if idx + 1 < len(sys.argv):
                    log_dir = sys.argv[idx + 1]
                    try:
                        os.makedirs(log_dir, exist_ok=True)
                        log_file = os.path.join(log_dir, "tls_tool.log")
                    except Exception:
                        pass
        except Exception:
            pass

        if len(sys.argv) > 1 and sys.argv[1].lower() in ("--service", "service"):
            return_code = _service_cli(sys.argv[2:])
            sys.exit(int(return_code))

        if len(sys.argv) > 1 and sys.argv[1].lower() in ("--headless", "headless"):
            mode = "server"
            config_file = "tls_config.json"
            if len(sys.argv) > 2 and sys.argv[2].lower() in ["client", "server", "both"]:
                mode = sys.argv[2].lower()
            if len(sys.argv) > 3:
                config_file = sys.argv[3]
            return_code = run_headless(mode, config_file, log_file=log_file)
            sys.exit(int(return_code))

        mode = "both"
        config_file = "tls_config.json"
        autostart = False

        if len(sys.argv) > 1:
            if sys.argv[1].lower() in ["client", "server", "both"]:
                mode = sys.argv[1].lower()
            if len(sys.argv) > 2:
                config_file = sys.argv[2]
            autostart = True

        root = tk.Tk()
        app = TLSToolApplication(root, mode, config_file, autostart, log_file=log_file)
        root.mainloop()
    except KeyboardInterrupt:
        print("\n程序被用户中断")
        sys.exit(0)
    except Exception as e:
        print(f"程序运行错误: {e}")
        import traceback
        traceback.print_exc()
        try:
            stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            # Re-resolve log_file if needed (though it should be captured by local var)
            # We use the log_file variable we resolved at start
            append_fallback_log(config_file if 'config_file' in locals() else "", f"[{stamp}] 程序运行错误: {e}", log_file=log_file)
            append_fallback_log(config_file if 'config_file' in locals() else "", traceback.format_exc(), log_file=log_file)
        except Exception:
            pass
        sys.exit(1)


if __name__ == "__main__":
    main()
