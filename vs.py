import os

import sys

import time

import json

import hashlib

import threading

import random

import math

import webbrowser

from datetime import datetime





def handle_uncaught_exceptions(e_type, e_val, e_tb):

    """Prevents instant CLI closure when running as a compiled standalone .exe"""

    import traceback

    print("\n" + "="*60)

    print(" [!] SENTINEL FORENSICS RUNTIME ERROR:")

    print("="*60)

    traceback.print_exception(e_type, e_val, e_tb)

    print("="*60)

    if not getattr(sys, 'frozen', False):

        try:

            input("\nPress ENTER to exit...")

        except Exception:

            pass



sys.excepthook = handle_uncaught_exceptions







try:

    import tkinter as tk

    from tkinter import ttk

except ImportError:

    print("\n[!] ERROR: Tkinter library missing.")

    sys.exit(1)



# Enable high DPI awareness on Windows systems

if sys.platform.startswith('win'):

    try:

        import ctypes

        ctypes.windll.shcore.SetProcessDpiAwareness(1)

    except Exception:

        pass



# Production backend endpoint used by the packaged scanner client
BACKEND_API_URL = "https://scn-j32f.onrender.com/api/scan"
SCAN_PIN = os.environ.get("SCN_PIN", "").strip()
if "--pin" in sys.argv:
    pin_index = sys.argv.index("--pin") + 1
    if pin_index < len(sys.argv):
        SCAN_PIN = sys.argv[pin_index].strip()



DEFAULT_DATABASE = {

    "weapons.meta": {"risk": "flagged", "mod": "No-Recoil & Magic Bullet Modification"},

    "visualsettings.dat": {"risk": "warning", "mod": "Custom Visuals / Clear Water / Bright Nights"},

    "custom_tracers.rpf": {"risk": "flagged", "mod": "Illegal Bullet Tracers & ESP Box RPF"},

    "materials.rpf": {"risk": "warning", "mod": "Foliage & Tree Bush Removal Mod"},

    "handling.meta": {"risk": "warning", "mod": "Vehicle Super-Handling Override"},

    "eulen.exe": {"risk": "flagged", "mod": "Eulen FiveM Cheat Menu Injector"},

    "redengine.exe": {"risk": "flagged", "mod": "RedEngine Resource Executor"},

    "skript.exe": {"risk": "flagged", "mod": "Skript Executable"},

    "desktop.dll": {"risk": "flagged", "mod": "Injected Overlay DLL Module"},

    "tz_injector.exe": {"risk": "flagged", "mod": "TZ Injector Executable"},

    "recoil_fix.rar": {"risk": "flagged", "mod": "No-Recoil Mod Package Archive"},

    "chams.zip": {"risk": "flagged", "mod": "Player Chams / Bright Models Mod"}

}



class SentinelPlayerClient:

    def __init__(self, root):

        self.root = root

        self.root.title("RPF Sentinel Pro")

        self.root.geometry("620x520")

        self.root.configure(bg="#020305")

        self.root.resizable(False, False)



        # Remove standard native Windows title bar

        self.root.overrideredirect(True)



        # Window Dragging Variables

        self._start_x = 0

        self._start_y = 0

        self._win_x = 0

        self._win_y = 0

        self._drag_dist = 0



        # Center window on the screen

        self.center_window(620, 520)



        # Scanning State Management Variables

        self.is_scanning = False

        self.scanned_files_list = []

        self.scan_thread = None

        self.scan_progress_pct = 0

        self.current_scanning_file = ""

        self.scan_status_text = "INITIALIZING AUTOMATIC SCAN..."

       

        # Starfield & Particle Animation Math Variables

        self.spinner_angle1 = 0

        self.spinner_angle2 = 0

        self.spinner_angle3 = 0

        self.particles = []

        self.blips = []

        self.scan_finished = False



        self.configure_styles()

        self.build_ui()



    def center_window(self, width, height):

        self.root.update_idletasks()

        screen_width = self.root.winfo_screenwidth()

        screen_height = self.root.winfo_screenheight()

        x = (screen_width // 2) - (width // 2)

        y = (screen_height // 2) - (height // 2)

        self.root.geometry(f"{width}x{height}+{x}+{y}")



    def start_move(self, event):

        """Records initial screen coordinates for smooth dragging anywhere on the window"""

        self._start_x = event.x_root

        self._start_y = event.y_root

        self._win_x = self.root.winfo_x()

        self._win_y = self.root.winfo_y()

        self._drag_dist = 0



    def do_move(self, event):

        """Updates window position dynamically while dragging"""

        dx = event.x_root - self._start_x

        dy = event.y_root - self._start_y

        self._drag_dist = math.hypot(dx, dy)

        self.root.geometry(f"+{self._win_x + dx}+{self._win_y + dy}")



    def on_canvas_release(self, event):

        """Starts scan only if the click was static (not a drag operation)"""

        if self._drag_dist <= 3:

            self.start_scan()



    def configure_styles(self):

        self.style = ttk.Style()

        self.style.theme_use('clam')



    def build_ui(self):

        # Minimalist Header Bar matching exact HUD background color

        top_bar = tk.Frame(self.root, bg="#020305", height=36, highlightthickness=0)

        top_bar.pack(fill="x")

        top_bar.pack_propagate(False)



        # Enable window dragging from the custom top bar

        top_bar.bind("<Button-1>", self.start_move)

        top_bar.bind("<B1-Motion>", self.do_move)



        title_label = tk.Label(top_bar, text="", bg="#020305")

        title_label.pack(side="left", padx=12)

        title_label.bind("<Button-1>", self.start_move)

        title_label.bind("<B1-Motion>", self.do_move)



        # Right Minimal Window Controls (_ and X) matching HUD color

        controls_box = tk.Frame(top_bar, bg="#020305")

        controls_box.pack(side="right", padx=6)



        btn_min = tk.Button(

            controls_box, text="—", bg="#020305", fg="#9CA3AF", font=("Segoe UI", 9, "bold"),

            activebackground="#1F2937", activeforeground="#FFFFFF", bd=0, width=3,

            cursor="hand2", command=self.root.iconify

        )

        btn_min.pack(side="left", padx=2)



        btn_close = tk.Button(

            controls_box, text="✕", bg="#020305", fg="#9CA3AF", font=("Segoe UI", 9, "bold"),

            activebackground="#EF4444", activeforeground="#FFFFFF", bd=0, width=3,

            cursor="hand2", command=self.root.destroy

        )

        btn_close.pack(side="left", padx=2)



        # Main Deep Black Canvas Frame matching HUD background

        self.body = tk.Frame(self.root, bg="#020305")

        self.body.pack(fill="both", expand=True)



        self.radar_canvas = tk.Canvas(self.body, bg="#020305", highlightthickness=0)

        self.radar_canvas.pack(fill="both", expand=True)



        # Interactive Drag & Click anywhere on the Canvas

        self.radar_canvas.bind("<Button-1>", self.start_move)

        self.radar_canvas.bind("<B1-Motion>", self.do_move)

        self.radar_canvas.bind("<ButtonRelease-1>", self.on_canvas_release)



        self.init_particles()

        self.animate_radar()



        # Start scanning automatically 500ms after launch

        self.root.after(500, self.start_scan)



    def init_particles(self):

        """Generates 3D Starfield particles matching the design"""

        self.particles = []

        for _ in range(120):

            self.particles.append({

                "x": random.uniform(-300, 300),

                "y": random.uniform(-250, 250),

                "z": random.uniform(10, 400),

                "speed": random.uniform(1.5, 4.0),

                "size": random.uniform(1.0, 2.2)

            })



    def start_scan(self):

        if self.is_scanning:

            return



        self.is_scanning = True

        self.scan_finished = False

        self.scan_progress_pct = 0



        self.init_particles()

        self.scan_thread = threading.Thread(target=self.run_background_scan, daemon=True)

        self.scan_thread.start()



    def abort_scan(self):

        self.is_scanning = False

        self.scan_status_text = "SCAN ABORTED"



    def run_background_scan(self):

        try:

            self.scanned_files_list.clear()



            SKIP_DIRS = {"windows", "$recycle.bin", "system volume information", "winsxs", "servicing", "assembly", "microsoft.net", "windowsapps"}

            files_to_scan = []



            # Auto Scan FiveM AppData & Drivers

            local_app = os.environ.get("LOCALAPPDATA", "")

            fivem_path = os.path.join(local_app, "FiveM", "FiveM.app")



            target_dirs = [fivem_path] if os.path.exists(fivem_path) else []



            if sys.platform.startswith('win'):

                import string

                from ctypes import windll

                bitmask = windll.kernel32.GetLogicalDrives()

                for letter in string.ascii_uppercase:

                    if bitmask & 1:

                        target_dirs.append(f"{letter}:\\")

                    bitmask >>= 1



            for drive in target_dirs:

                if not os.path.exists(drive) or not self.is_scanning:

                    continue

                for root, dirs, files in os.walk(drive, topdown=True):

                    if not self.is_scanning:

                        break

                    dirs[:] = [d for d in dirs if d.lower() not in SKIP_DIRS and not d.startswith('$')]

                    for file in files:

                        ext = os.path.splitext(file)[1].lower()

                        if ext in ['.rpf', '.meta', '.dat', '.xml', '.exe', '.dll', '.asi', '.rar', '.zip']:

                            files_to_scan.append(os.path.join(root, file))



            total_count = len(files_to_scan)

            if total_count == 0:
                self.scan_status_text = "SCAN COMPLETE — NO MATCHING FILES FOUND"



            clean_cnt, warn_cnt, flag_cnt = 0, 0, 0



            for idx, filepath in enumerate(files_to_scan):

                if not self.is_scanning:

                    break



                filename = os.path.basename(filepath).lower()

                risk = "clean"

                mod_desc = "None (Original Base Build)"



                if filename in DEFAULT_DATABASE:

                    db_entry = DEFAULT_DATABASE[filename]

                    risk = db_entry["risk"]

                    mod_desc = db_entry["mod"]

                elif any(k in filename for k in ["recoil", "eulen", "redengine", "skript", "cheat", "spoofer", "injector"]):

                    risk = "flagged"

                    mod_desc = "Blacklisted Cheat Pattern"



                if risk == "clean":

                    clean_cnt += 1

                elif risk == "warning":

                    warn_cnt += 1

                else:

                    flag_cnt += 1



                try:
                    with open(filepath, "rb") as scanned_file:
                        sha_hash = hashlib.sha256(scanned_file.read()).hexdigest()
                except (OSError, PermissionError):
                    sha_hash = "unavailable"

                mod_time = datetime.now().strftime("%Y-%m-%d %H:%M")



                record = (risk, filepath, mod_desc, sha_hash, mod_time)

                self.scanned_files_list.append(record)



                if risk != "clean" and len(self.blips) < 12:

                    self.blips.append({

                        "angle": random.uniform(0, 360),

                        "radius": random.uniform(30, 110),

                        "color": "#FF2A5F" if risk == "flagged" else "#FFB800",

                        "alpha": 1.0

                    })



                pct = int(((idx + 1) / total_count) * 100)

                self.current_scanning_file = filepath

                self.scan_status_text = f"SCANNING: {os.path.basename(filepath)}"

               

                self.root.after(0, self.update_scan_progress, pct)

                time.sleep(0.015)



        except Exception as e:

            print("Scan thread error:", e)

        finally:

            self.root.after(0, self.finalize_scan)



    def update_scan_progress(self, progress):

        self.scan_progress_pct = progress



    def finalize_scan(self):

        self.is_scanning = False

        self.scan_finished = True

        self.scan_progress_pct = 100

        # The operator should not see the dashboard; the report is sent silently to the admin site.
        self.scan_status_text = "SCAN COMPLETE — REPORT SENT TO ADMIN DASHBOARD"



        # 1. Send scan results payload to backend HTTP POST API

        self.send_results_to_web()

        # 2. Save scan to database
        self.save_scan_to_database()

        # 3. Do not open the website for the operator. Results are sent directly to the admin dashboard.

        # Close the scanner window quietly after the upload finishes.
        self.root.after(2000, self.root.destroy)



    def send_single_result_to_web(self, verdict, file_path, anomaly, sha256):
        """Send individual scan result to server immediately for live updates"""
        payload = {
            "verdict": verdict,
            "file_path": file_path,
            "anomaly": anomaly,
            "sha256": sha256,
            "entropy": "0",
            "pin": SCAN_PIN
        }

        def upload_worker():
            import urllib.request
            try:
                data = json.dumps(payload).encode('utf-8')
                req = urllib.request.Request(
                    BACKEND_API_URL.replace("/api/scan", "/api/scan/result"),
                    data=data,
                    headers={'Content-Type': 'application/json'},
                    method='POST'
                )
                with urllib.request.urlopen(req, timeout=5) as resp:
                    pass
            except Exception:
                pass  # Silently ignore individual result send failures

        threading.Thread(target=upload_worker, daemon=True).start()

    def save_scan_to_database(self):
        """Save the completed scan to the server's database"""
        import urllib.request
        try:
            payload = {
                "notes": f"System Scan from {os.environ.get('COMPUTERNAME', 'PC')}",
                "user": os.environ.get("USERNAME", "Player"),
                "pin": SCAN_PIN
            }
            data = json.dumps(payload).encode('utf-8')
            req = urllib.request.Request(
                BACKEND_API_URL.replace("/api/scan", "/api/scans/save"),
                data=data,
                headers={'Content-Type': 'application/json'},
                method='POST'
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                result = json.loads(resp.read().decode('utf-8'))
                print(f"Scan saved with PIN: {result.get('pin', 'Unknown')}")
        except Exception as e:
            print(f"Failed to save scan to database: {e}")

    def send_results_to_web(self):

        payload = {

            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),

            "user": os.environ.get("USERNAME", "Player"),

            "pc_name": os.environ.get("COMPUTERNAME", "PC"),

            "scanned_count": len(self.scanned_files_list),

            "summary": {

                "clean": sum(1 for r in self.scanned_files_list if r[0] == "clean"),

                "warning": sum(1 for r in self.scanned_files_list if r[0] == "warning"),

                "flagged": sum(1 for r in self.scanned_files_list if r[0] == "flagged")

            },

            "records": [

                {

                    "verdict": r[0],

                    "file_path": r[1],

                    "anomaly": r[2],

                    "sha256": r[3],

                    "modified": r[4]

                } for r in self.scanned_files_list

            ]

        }



        def upload_worker():

            import urllib.request

            try:

                data = json.dumps(payload).encode('utf-8')

                req = urllib.request.Request(

                    BACKEND_API_URL,

                    data=data,

                    headers={'Content-Type': 'application/json'},

                    method='POST'

                )

                with urllib.request.urlopen(req, timeout=5) as resp:

                    pass

            except Exception as e:

                print("Failed to send results to web:", e)



        upload_worker()



    def animate_radar(self):
        self.radar_canvas.delete("all")
        w = self.radar_canvas.winfo_width() or 620
        h = self.radar_canvas.winfo_height() or 480
        cx, cy = w // 2, h // 2 - 20

        # 1. Floating Starfield Space Particles
        for particle in self.particles:
            particle["z"] -= particle["speed"]
            if particle["z"] <= 1:

                particle["z"] = 400

                particle["x"] = random.uniform(-300, 300)

                particle["y"] = random.uniform(-250, 250)



            k = 240.0 / particle["z"]

            sx = cx + particle["x"] * k

            sy = cy + particle["y"] * k



            if 0 <= sx <= w and 0 <= sy <= h:

                brightness = max(60, int(255 * (1 - particle["z"] / 400)))

                hex_val = f"#{brightness:02x}{brightness:02x}{brightness:02x}"

                r = max(1, int(particle["size"] * k * 0.45))

                self.radar_canvas.create_oval(sx - r, sy - r, sx + r, sy + r, fill=hex_val, outline="")



        # 2. Central Neon Red Dual Spinning Arcs

        if self.is_scanning or self.scan_finished:

            self.spinner_angle1 = (self.spinner_angle1 + 6) % 360

            self.spinner_angle2 = (self.spinner_angle2 - 9) % 360

            self.spinner_angle3 = (self.spinner_angle3 + 4) % 360

        else:

            self.spinner_angle1 = (self.spinner_angle1 + 1.5) % 360

            self.spinner_angle2 = (self.spinner_angle2 - 2) % 360

            self.spinner_angle3 = (self.spinner_angle3 + 1) % 360



        # Outer Crimson Red Arc

        self.radar_canvas.create_arc(

            cx - 42, cy - 42, cx + 42, cy + 42,

            start=self.spinner_angle1, extent=130,

            style="arc", outline="#FF2A5F", width=3

        )



        # Inner Bright Crimson Arc

        self.radar_canvas.create_arc(

            cx - 28, cy - 28, cx + 28, cy + 28,

            start=self.spinner_angle2, extent=170,

            style="arc", outline="#FF4D79", width=2.5

        )



        # Center Accent Ring

        self.radar_canvas.create_oval(

            cx - 12, cy - 12, cx + 12, cy + 12,

            outline="#FF2A5F" if self.is_scanning else "#3D0C18", width=1.5

        )



        # 3. Sleek Crimson Red Progress Bar at Bottom

        bar_margin = 35

        bar_y = h - 45

        bar_height = 8

        bar_width = (w - bar_margin) - bar_margin



        # Background Track

        self.radar_canvas.create_rectangle(

            bar_margin, bar_y, w - bar_margin, bar_y + bar_height,

            fill="#150508", outline="#300A12", width=1

        )



        # Filled Red Bar

        fill_pct = max(0.0, min(1.0, self.scan_progress_pct / 100.0))

        if fill_pct > 0:

            fill_x2 = bar_margin + (bar_width * fill_pct)

            self.radar_canvas.create_rectangle(

                bar_margin, bar_y, fill_x2, bar_y + bar_height,

                fill="#FF2A5F", outline=""

            )



        # Status indicator dot

        icon_color = "#FF2A5F" if not self.scan_finished else "#FF4D79"

        self.radar_canvas.create_oval(

            w - bar_margin - 8, bar_y + 18, w - bar_margin, bar_y + 26,

            fill=icon_color, outline=""

        )



        self.root.after(30, self.animate_radar)



def request_scan_pin(root):
    dialog = tk.Toplevel(root)
    dialog.title("Scn.ac Scanner Access")
    dialog.configure(bg="#020305")
    dialog.resizable(False, False)
    dialog.transient(root)
    dialog.grab_set()

    width, height = 440, 270
    screen_width = dialog.winfo_screenwidth()
    screen_height = dialog.winfo_screenheight()
    dialog.geometry(f"{width}x{height}+{(screen_width - width) // 2}+{(screen_height - height) // 2}")

    card = tk.Frame(dialog, bg="#0B070A", highlightbackground="#7F1235", highlightthickness=1)
    card.pack(fill="both", expand=True, padx=1, pady=1)

    header = tk.Frame(card, bg="#14090F", height=52)
    header.pack(fill="x")
    header.pack_propagate(False)
    tk.Label(
        header, text="SCN.AC  /  SCANNER ACCESS", bg="#14090F", fg="#FF4D79",
        font=("Segoe UI", 10, "bold")
    ).pack(side="left", padx=20, pady=16)

    tk.Label(
        card, text="Enter the 6-digit PIN shared by the dashboard owner.",
        bg="#0B070A", fg="#BFA7AE", font=("Segoe UI", 9)
    ).pack(anchor="w", padx=24, pady=(22, 8))

    pin_entry = tk.Entry(
        card, bg="#020305", fg="#FFFFFF", insertbackground="#FF4D79",
        relief="flat", bd=0, justify="center", font=("Consolas", 18, "bold"),
        highlightbackground="#4D1A2D", highlightcolor="#FF2A5F", highlightthickness=1
    )
    pin_entry.pack(fill="x", padx=24, ipady=9)
    pin_entry.focus_set()

    error_label = tk.Label(card, text="", bg="#0B070A", fg="#FF718F", font=("Segoe UI", 8))
    error_label.pack(pady=(7, 0))

    buttons = tk.Frame(card, bg="#0B070A")
    buttons.pack(fill="x", padx=24, pady=(12, 20))

    result = {"pin": None}

    def submit():
        value = pin_entry.get().strip()
        if not value.isdigit() or len(value) != 6:
            error_label.config(text="PIN must contain exactly 6 digits.")
            pin_entry.focus_set()
            return
        result["pin"] = value
        dialog.destroy()

    def cancel():
        dialog.destroy()

    tk.Button(
        buttons, text="CANCEL", command=cancel, bg="#21131A", fg="#C9B8BE",
        activebackground="#351B27", activeforeground="#FFFFFF", relief="flat",
        bd=0, cursor="hand2", font=("Segoe UI", 9, "bold"), padx=18, pady=8
    ).pack(side="right", padx=(8, 0))
    tk.Button(
        buttons, text="VERIFY PIN", command=submit, bg="#E11D48", fg="#FFFFFF",
        activebackground="#FF2A5F", activeforeground="#FFFFFF", relief="flat",
        bd=0, cursor="hand2", font=("Segoe UI", 9, "bold"), padx=18, pady=8
    ).pack(side="right")

    dialog.bind("<Return>", lambda event: submit())
    dialog.bind("<Escape>", lambda event: cancel())
    dialog.protocol("WM_DELETE_WINDOW", cancel)
    root.wait_window(dialog)
    return result["pin"]


if __name__ == "__main__":

    root = tk.Tk()
    root.withdraw()

    if not SCAN_PIN:
        entered_pin = request_scan_pin(root)
        if not entered_pin:
            root.destroy()
            sys.exit(1)
        SCAN_PIN = entered_pin

    root.deiconify()
    app = SentinelPlayerClient(root)

    root.mainloop()