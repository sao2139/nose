import sys
import subprocess
import os
import datetime
import ctypes # Para verificar permisos de admin en Windows

# --- VERIFICACIÓN DE DEPENDENCIAS ---
try:
    import tkinter as tk
    from tkinter import ttk, messagebox, scrolledtext
    import requests
    import base64
    import tempfile
    import threading
    import pandas as pd
    import io
except ImportError as e:
    print(f"Falta la librería: {e.name}. Instala con: pip install requests pandas")
    try:
        import tkinter.messagebox
        root = tk.Tk()
        root.withdraw()
        tk.messagebox.showerror("Error de Dependencias", f"Falta instalar librerías.\nEjecuta en terminal:\npip install requests pandas")
    except:
        pass
    sys.exit()

# URL de la API de VPN Gate
VPNGATE_API_URL = "http://www.vpngate.net/api/iphone/"

class VPNAueomatorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("vptauqyl_v.2 | [sao::sao3#] Secure Access")
        self.root.geometry("850x600")
        self.root.configure(bg="#050505")

        self.vpn_process = None
        self.server_list = []
        self.current_ovpn_file = None

        self.create_ui()
        self.check_admin_privileges()
        
        # Inicio automático del escaneo
        self.log("Sistema iniciado. Cargando módulos de red...")
        threading.Thread(target=self.fetch_servers, daemon=True).start()

    def check_admin_privileges(self):
        """Verifica si tenemos permisos para crear la interfaz TUN/TAP"""
        if sys.platform.startswith('win'):
            try:
                is_admin = ctypes.windll.shell32.IsUserAnAdmin()
                if not is_admin:
                    self.log("ADVERTENCIA CRÍTICA: NO ERES ADMINISTRADOR.", "error")
                    self.log("VS Code debe ejecutarse como 'Administrador' o fallará la interfaz TAP.", "error")
                    messagebox.showwarning("Permisos Insuficientes", "Para cambiar tu IP, necesitas ejecutar VS Code como Administrador.")
            except:
                pass

    def create_ui(self):
        # --- HEADER ---
        header = tk.Frame(self.root, bg="#111")
        header.pack(fill="x", pady=0)
        
        title_lbl = tk.Label(header, text="PROJECT vptauqyl_v.2", fg="#00ff00", bg="#111", font=("Consolas", 16, "bold"))
        title_lbl.pack(pady=10)
        
        sub_lbl = tk.Label(header, text="Protocol: [sao] [sao3#] | AES-256 Enforcer", fg="#444", bg="#111", font=("Arial", 8))
        sub_lbl.pack(pady=0)

        # --- STATUS BAR ---
        self.status_var = tk.StringVar(value="ESPERANDO COMANDO...")
        self.lbl_status = tk.Label(self.root, textvariable=self.status_var, fg="cyan", bg="#050505", font=("Consolas", 10))
        self.lbl_status.pack(pady=5)

        # --- TABLA DE SERVIDORES ---
        cols = ("País", "IP", "Velocidad", "Ping", "Score")
        self.tree = ttk.Treeview(self.root, columns=cols, show="headings", height=12)
        
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Treeview", background="#111", foreground="#00ff00", fieldbackground="#111", rowheight=25, font=("Consolas", 9))
        style.configure("Treeview.Heading", background="#222", foreground="white", font=("Arial", 9, "bold"))
        style.map("Treeview", background=[("selected", "#004400")])
        
        for col in cols:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=120, anchor="center")
        
        self.tree.pack(padx=20, pady=10, fill="both")

        # --- BOTONES ---
        btn_frame = tk.Frame(self.root, bg="#050505")
        btn_frame.pack(pady=10)
        
        btn_refresh = tk.Button(btn_frame, text="ESCANEAR RED", command=lambda: threading.Thread(target=self.fetch_servers).start(), 
                                bg="#333", fg="white", relief="flat", padx=15, pady=5)
        btn_refresh.pack(side="left", padx=10)

        btn_connect = tk.Button(btn_frame, text=">>> INICIAR TÚNEL <<<", command=self.connect_vpn, 
                                bg="#008000", fg="white", font=("Consolas", 11, "bold"), relief="flat", padx=20, pady=5)
        btn_connect.pack(side="left", padx=10)

        btn_disconnect = tk.Button(btn_frame, text="ABORTAR / CERRAR", command=self.disconnect_vpn, 
                                   bg="#800000", fg="white", relief="flat", padx=15, pady=5)
        btn_disconnect.pack(side="left", padx=10)

        # --- CONSOLA DE LOGS ---
        log_label = tk.Label(self.root, text="SYSTEM LOGS [sao::sao3#]:", fg="#666", bg="#050505", anchor="w", font=("Consolas", 8))
        log_label.pack(fill="x", padx=20)
        
        self.log_area = scrolledtext.ScrolledText(self.root, height=10, bg="black", fg="#00ff00", font=("Consolas", 9))
        self.log_area.pack(padx=20, pady=5, fill="both", expand=True)
        self.log_area.tag_config("signature", foreground="cyan")
        self.log_area.tag_config("error", foreground="red")
        self.log_area.tag_config("success", foreground="#00ff00", font=("Consolas", 9, "bold"))

    def log(self, text, type="info"):
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        self.log_area.insert(tk.END, f"[{timestamp}] ")
        self.log_area.insert(tk.END, "[sao] [sao3#] ", "signature")
        self.log_area.insert(tk.END, f">> {text}\n")
        
        if type == "error":
            self.log_area.tag_add("error", "end-2l", "end-1c")
        elif type == "success":
            self.log_area.tag_add("success", "end-2l", "end-1c")

        self.log_area.see(tk.END)

    def fetch_servers(self):
        self.status_var.set("CONTACTANDO NODOS VPN GATE...")
        try:
            response = requests.get(VPNGATE_API_URL, timeout=15)
            data = response.text.split('\n')[1:] 
            cleaned_data = [line for line in data if line.strip() and not line.startswith('*')]
            
            if not cleaned_data:
                raise ValueError("Respuesta vacía del servidor.")

            csv_io = io.StringIO('\n'.join(cleaned_data))
            df = pd.read_csv(csv_io)
            df = df[df['OpenVPN_ConfigData_Base64'].notna()]
            df = df.sort_values(by='Score', ascending=False).head(100)

            self.server_list = df.to_dict('records')
            self.root.after(0, self.update_table)
            self.log(f"Lista actualizada: {len(self.server_list)} servidores activos encontrados.")
            self.status_var.set(f"LISTO: {len(self.server_list)} SERVIDORES DISPONIBLES.")
            
        except Exception as e:
            self.status_var.set("ERROR DE CONEXIÓN API")
            self.log(f"Fallo al obtener lista de servidores: {e}", "error")

    def update_table(self):
        for i in self.tree.get_children():
            self.tree.delete(i)
        for srv in self.server_list:
            mbps = round(srv['Speed'] / 1000000, 2)
            self.tree.insert("", "end", values=(srv['CountryShort'], srv['IP'], f"{mbps} Mbps", srv['Ping'], srv['Score']))

    def connect_vpn(self):
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("Destino Requerido", "Debes seleccionar un servidor (País) de la lista.")
            return

        if self.vpn_process:
            self.disconnect_vpn()

        item = self.tree.item(selected[0])
        index = self.tree.index(selected[0])
        server_data = self.server_list[index]
        
        target_country = server_data['CountryShort']
        target_ip = server_data['IP']
        
        self.log(f"Iniciando secuencia de conexión hacia {target_country} ({target_ip})...")
        self.status_var.set(f"CONECTANDO A {target_country}...")
        
        try:
            config_content = base64.b64decode(server_data['OpenVPN_ConfigData_Base64']).decode('utf-8')
            
            self.current_ovpn_file = tempfile.NamedTemporaryFile(delete=False, suffix='.ovpn', mode='w')
            self.current_ovpn_file.write(config_content)
            self.current_ovpn_file.close()
            
            threading.Thread(target=self.run_openvpn_process, args=(self.current_ovpn_file.name,), daemon=True).start()
            
        except Exception as e:
            self.log(f"Error procesando configuración: {e}", "error")

    def run_openvpn_process(self, config_path):
        openvpn_path = "openvpn"
        
        if sys.platform.startswith('win'):
            possible_paths = [
                r"C:\Program Files\OpenVPN\bin\openvpn.exe",
                r"C:\Program Files (x86)\OpenVPN\bin\openvpn.exe"
            ]
            for p in possible_paths:
                if os.path.exists(p):
                    openvpn_path = p
                    break
            
            # --- CORRECCIÓN CRÍTICA DE CIFRADO ---
            # Permite negociar AES-256 (moderno) y AES-128 (antiguo)
            cmd = [
                openvpn_path, 
                '--config', config_path,
                '--data-ciphers', 'AES-256-GCM:AES-128-GCM:AES-256-CBC:AES-128-CBC'
            ]
            
        elif sys.platform.startswith('linux'):
            cmd = ['sudo', 'openvpn', '--config', config_path]
        else:
            self.log("Sistema operativo no reconocido.", "error")
            return

        self.log(f"Ejecutando binario: {openvpn_path}")

        try:
            startupinfo = None
            if sys.platform.startswith('win'):
                startupinfo = subprocess.STARTUPINFO()
                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

            self.vpn_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
                bufsize=1,
                startupinfo=startupinfo
            )
            
            for line in self.vpn_process.stdout:
                line = line.strip()
                if line:
                    if "Note:" in line or "warning" in line.lower():
                        continue 
                    self.log(line)
                    
                if "Initialization Sequence Completed" in line:
                    self.status_var.set(">>> CONEXIÓN SEGURA ESTABLECIDA <<<")
                    self.log("TÚNEL ENCRIPTADO ACTIVO. TU IP ESTÁ OCULTA.", "success")
                    self.root.configure(bg="#002200") 
            
        except FileNotFoundError:
            self.log(f"ERROR CRÍTICO: No se encontró '{openvpn_path}'.", "error")
        except Exception as e:
            self.log(f"Error de ejecución: {e}", "error")

    def disconnect_vpn(self):
        if self.vpn_process:
            self.log("Enviando señal de terminación al túnel...")
            self.vpn_process.terminate()
            self.vpn_process = None
            
        if self.current_ovpn_file:
            try:
                os.remove(self.current_ovpn_file.name)
            except:
                pass
        
        self.status_var.set("DESCONECTADO - INSEGURO")
        self.root.configure(bg="#050505")
        self.log("Conexión cerrada. Protocolo finalizado.")

if __name__ == "__main__":
    if sys.platform.startswith('linux') and os.geteuid() != 0:
        print("ADVERTENCIA: En Linux ejecuta con 'sudo'.")
    
    root = tk.Tk()
    app = VPNAueomatorApp(root)
    root.mainloop()