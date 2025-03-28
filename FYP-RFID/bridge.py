import tkinter as tk
from tkinter import messagebox, simpledialog
import json
import socket
import threading
import requests
from datetime import datetime
import time

# Configuration
CONFIG_FILE = "rfid_config.json"
RENDER_URL = "https://comp-fyp.onrender.com/api/rfid-update"
LISTEN_PORT = 5000

try:
    with open(CONFIG_FILE, 'r') as f:
        config = json.load(f)
except FileNotFoundError:
    config = {"shelves": [], "return_boxes": []}

detected_epcs = {}
notified_ips = set()

root = tk.Tk()
root.title("RFID Bridge")
root.geometry("700x600")

log_frame = tk.Frame(root)
log_frame.pack(fill="both", expand=True, padx=10, pady=5)
tk.Label(log_frame, text="EPC Detection Log", font=("Arial", 12, "bold")).pack()
log_inner_frame = tk.Frame(log_frame)
log_inner_frame.pack(fill="both", expand=True)
log_scroll = tk.Scrollbar(log_inner_frame, orient="vertical")
log_scroll.pack(side="right", fill="y")
log_text = tk.Text(log_inner_frame, height=5, width=80, state="disabled", yscrollcommand=log_scroll.set)
log_text.pack(fill="both", expand=True)
log_scroll.config(command=log_text.yview)

button_frame = tk.Frame(root)
button_frame.pack(pady=5)
tk.Button(button_frame, text="Add Bookshelf", command=lambda: add_box("shelf")).pack(side="left", padx=5)
tk.Button(button_frame, text="Add Return Box", command=lambda: add_box("return_box")).pack(side="left", padx=5)
tk.Button(button_frame, text="Edit", command=lambda: edit_selected()).pack(side="left", padx=5)
tk.Button(button_frame, text="Remove", command=lambda: remove_selected()).pack(side="left", padx=5)

lists_frame = tk.Frame(root)
lists_frame.pack(fill="x", padx=10, pady=5)

shelves_frame = tk.Frame(lists_frame)
shelves_frame.pack(side="left", fill="both", expand=True, padx=(0, 5))
tk.Label(shelves_frame, text="Existed Bookshelves", font=("Arial", 12, "bold")).pack()
shelves_inner_frame = tk.Frame(shelves_frame, borderwidth=1, relief="sunken")
shelves_inner_frame.pack(fill="both", expand=True)
shelves_scroll = tk.Scrollbar(shelves_inner_frame, orient="vertical")
shelves_scroll.pack(side="right", fill="y")
shelves_text = tk.Text(shelves_inner_frame, height=20, width=40, yscrollcommand=shelves_scroll.set, borderwidth=0)
shelves_text.pack(fill="both", expand=True)
shelves_scroll.config(command=shelves_text.yview)

return_boxes_frame = tk.Frame(lists_frame)
return_boxes_frame.pack(side="right", fill="both", expand=True, padx=(5, 0))
tk.Label(return_boxes_frame, text="Existed Return Boxes", font=("Arial", 12, "bold")).pack()
return_boxes_inner_frame = tk.Frame(return_boxes_frame, borderwidth=1, relief="sunken")
return_boxes_inner_frame.pack(fill="both", expand=True)
return_boxes_scroll = tk.Scrollbar(return_boxes_inner_frame, orient="vertical")
return_boxes_scroll.pack(side="right", fill="y")
return_boxes_text = tk.Text(return_boxes_inner_frame, height=20, width=40, yscrollcommand=return_boxes_scroll.set, borderwidth=0)
return_boxes_text.pack(fill="both", expand=True)
return_boxes_scroll.config(command=return_boxes_text.yview)

status_widgets = {}

def get_item_type(ip):
    if ip in [s["ip"] for s in config["shelves"]]:
        return "shelf"
    elif ip in [b["ip"] for b in config["return_boxes"]]:
        return "return_box"
    return None

def check_stale_epcs():
    now = datetime.now().timestamp()
    for ip, epcs in list(detected_epcs.items()):
        if not isinstance(epcs, dict):
            print(f"Warning: Skipping invalid epcs for IP {ip}: {epcs}")
            continue
        to_remove = []
        for epc, data in epcs.items():
            if epc == "status" or not isinstance(data, dict) or "last_seen" not in data:
                continue
            if now - data["last_seen"] > 5:
                to_remove.append(epc)
                if data.get("sent", False):
                    log_message(f"EPC '{epc}' no longer detected by {get_item_type(ip)} reader {ip}", ip)
                    send_to_render(ip, epc, get_item_type(ip), detected=False)
        for epc in to_remove:
            del epcs[epc]
        if len(epcs) == 1 and "status" in epcs:
            update_status(ip, 'grey')

def periodic_check_stale_epcs():
    while True:
        check_stale_epcs()
        time.sleep(5)

threading.Thread(target=periodic_check_stale_epcs, daemon=True).start()

def log_message(message, ip=None):
    log_text.config(state="normal")
    log_text.insert(tk.END, f"{datetime.now().strftime('%H:%M:%S')} - {message}\n")
    log_text.config(state="disabled")
    log_text.see(tk.END)
    if ip and ip in detected_epcs:
        detected_epcs[ip].setdefault('log', []).append(f"{datetime.now().strftime('%H:%M:%S')} - {message}")

def get_next_default_name(box_type):
    base_name = "Bookshelf" if box_type == "shelf" else "Return Box"
    items = config["shelves"] if box_type == "shelf" else config["return_boxes"]
    count = 1
    while True:
        name = f"{base_name} {count}"
        if not any(item["name"] == name for item in items):
            return name
        count += 1

def update_lists():
    shelves_text.config(state="normal")
    shelves_text.delete("1.0", tk.END)
    return_boxes_text.config(state="normal")
    return_boxes_text.delete("1.0", tk.END)
    status_widgets.clear()

    for i, shelf in enumerate(config["shelves"]):
        ip = shelf["ip"]
        status = detected_epcs.get(ip, {}).get('status', 'grey')
        line = f"{i+1}.0"
        shelves_text.insert(tk.END, "  ")
        canvas = tk.Canvas(shelves_text, width=10, height=10)
        light = canvas.create_oval(2, 2, 8, 8, fill=status)
        shelves_text.window_create(tk.END, window=canvas)
        shelves_text.insert(tk.END, f" {shelf['name']} ({ip})\n")
        status_widgets[ip] = {'canvas': canvas, 'light': light, 'text_widget': shelves_text, 'line': i+1}

    for i, box in enumerate(config["return_boxes"]):
        ip = box["ip"]
        status = detected_epcs.get(ip, {}).get('status', 'grey')
        line = f"{i+1}.0"
        return_boxes_text.insert(tk.END, "  ")
        canvas = tk.Canvas(return_boxes_text, width=10, height=10)
        light = canvas.create_oval(2, 2, 8, 8, fill=status)
        return_boxes_text.window_create(tk.END, window=canvas)
        return_boxes_text.insert(tk.END, f" {box['name']} ({ip})\n")
        status_widgets[ip] = {'canvas': canvas, 'light': light, 'text_widget': return_boxes_text, 'line': i+1}

    shelves_text.config(state="disabled")
    return_boxes_text.config(state="disabled")

def update_status(ip, status):
    if ip not in detected_epcs:
        detected_epcs[ip] = {}
    detected_epcs[ip]['status'] = status
    if ip in status_widgets:
        canvas = status_widgets[ip]['canvas']
        light = status_widgets[ip]['light']
        canvas.itemconfig(light, fill=status)

def save_config():
    with open(CONFIG_FILE, 'w') as f:
        json.dump(config, f, indent=4)

def add_box(box_type):
    dialog = tk.Toplevel(root)
    dialog.title(f"Add {box_type.replace('_', ' ')}")
    dialog.geometry("350x200")
    dialog.transient(root)
    dialog.grab_set()
    dialog.update_idletasks()
    x = root.winfo_x() + (root.winfo_width() - dialog.winfo_width()) // 2
    y = root.winfo_y() + (root.winfo_height() - dialog.winfo_height()) // 2
    dialog.geometry(f"+{x}+{y}")

    tk.Label(dialog, text="Name:", font=("Arial", 10)).pack(pady=10)
    name_entry = tk.Entry(dialog, width=30)
    name_entry.insert(0, get_next_default_name(box_type))
    name_entry.pack(pady=5)
    tk.Label(dialog, text="IP:", font=("Arial", 10)).pack(pady=10)
    ip_entry = tk.Entry(dialog, width=30)
    ip_entry.insert(0, "192.168.1.1")
    ip_entry.pack(pady=5)

    def submit():
        name = name_entry.get().strip()
        ip = ip_entry.get().strip()
        if name and ip:
            key = "shelves" if box_type == "shelf" else "return_boxes"
            config[key].append({"name": name, "ip": ip})
            save_config()
            update_lists()
            dialog.destroy()
            try:
                requests.post(f"https://comp-fyp.onrender.com/api/{key}", 
                              json={"name": name, "readerIp": ip},
                              headers={"Content-Type": "application/json"})
            except Exception as e:
                log_message(f"Error registering {box_type} {ip} with Render: {str(e)}")
        else:
            messagebox.showwarning("Input Error", "Both Name and IP are required.")

    tk.Button(dialog, text="Add", command=submit).pack(pady=20)

def edit_selected():
    selected_ip = get_selected_ip()
    if selected_ip:
        for i, shelf in enumerate(config["shelves"]):
            if shelf["ip"] == selected_ip:
                edit_item("shelf", i, shelf)
                return
        for i, box in enumerate(config["return_boxes"]):
            if box["ip"] == selected_ip:
                edit_item("return_box", i, box)
                return

def edit_item(box_type, idx, item):
    dialog = tk.Toplevel(root)
    dialog.title(f"Edit {box_type.replace('_', ' ')}")
    dialog.geometry("350x200")
    dialog.transient(root)
    dialog.grab_set()
    dialog.update_idletasks()
    x = root.winfo_x() + (root.winfo_width() - dialog.winfo_width()) // 2
    y = root.winfo_y() + (root.winfo_height() - dialog.winfo_height()) // 2
    dialog.geometry(f"+{x}+{y}")

    tk.Label(dialog, text="Name:", font=("Arial", 10)).pack(pady=10)
    name_entry = tk.Entry(dialog, width=30)
    name_entry.insert(0, item["name"])
    name_entry.pack(pady=5)
    tk.Label(dialog, text="IP:", font=("Arial", 10)).pack(pady=10)
    ip_entry = tk.Entry(dialog, width=30)
    ip_entry.insert(0, item["ip"])
    ip_entry.pack(pady=5)

    def submit():
        name = name_entry.get().strip()
        ip = ip_entry.get().strip()
        if name and ip:
            key = "shelves" if box_type == "shelf" else "return_boxes"
            config[key][idx] = {"name": name, "ip": ip}
            save_config()
            update_lists()
            dialog.destroy()
        else:
            messagebox.showwarning("Input Error", "Both Name and IP are required.")

    tk.Button(dialog, text="Save", command=submit).pack(pady=20)

def remove_selected():
    selected_ip = get_selected_ip()
    if selected_ip:
        for i, shelf in enumerate(config["shelves"]):
            if shelf["ip"] == selected_ip:
                config["shelves"].pop(i)
                save_config()
                update_lists()
                try:
                    response = requests.delete(f"https://comp-fyp.onrender.com/api/shelves/{selected_ip}")
                    log_message(f"Deleted shelf {selected_ip} from server - Status: {response.status_code}")
                    if selected_ip in detected_epcs:
                        del detected_epcs[selected_ip]
                except Exception as e:
                    log_message(f"Error deleting shelf {selected_ip} from server: {str(e)}")
                return
        for i, box in enumerate(config["return_boxes"]):
            if box["ip"] == selected_ip:
                config["return_boxes"].pop(i)
                save_config()
                update_lists()
                try:
                    response = requests.delete(f"https://comp-fyp.onrender.com/api/return-boxes/{selected_ip}")
                    log_message(f"Deleted return box {selected_ip} from server - Status: {response.status_code}")
                    if selected_ip in detected_epcs:
                        del detected_epcs[selected_ip]
                except Exception as e:
                    log_message(f"Error deleting return box {selected_ip} from server: {str(e)}")
                return

def get_selected_ip():
    for ip, widgets in status_widgets.items():
        if widgets['text_widget'].tag_names(f"{widgets['line']}.0") and "selected" in widgets['text_widget'].tag_names(f"{widgets['line']}.0"):
            return ip
    return None

def show_item_log(ip):
    for widget_ip, widgets in status_widgets.items():
        text_widget = widgets['text_widget']
        line = widgets['line']
        text_widget.tag_remove("selected", f"{line}.0", f"{line}.end")
        text_widget.tag_remove("highlight", f"{line}.0", f"{line}.end")
        if widget_ip == ip:
            text_widget.tag_add("selected", f"{line}.0", f"{line}.end")
            text_widget.tag_add("highlight", f"{line}.0", f"{line}.end")
            text_widget.tag_configure("selected", foreground="blue")
            text_widget.tag_configure("highlight", background="lightblue")

    log_text.config(state="normal")
    log_text.delete("1.0", tk.END)
    if ip in detected_epcs and 'log' in detected_epcs[ip]:
        for entry in detected_epcs[ip]['log']:
            log_text.insert(tk.END, f"{entry}\n")
    else:
        log_text.insert(tk.END, "No EPC detection logs for this device.\n")
    log_text.config(state="disabled")

def show_item_log_window(ip):
    item_name = get_item_name(ip)
    log_window = tk.Toplevel(root)
    log_window.title(f"{item_name}:{ip}")
    log_window.geometry("400x300")
    log_window.transient(root)
    log_window.grab_set()
    log_window.update_idletasks()
    x = root.winfo_x() + (root.winfo_width() - log_window.winfo_width()) // 2
    y = root.winfo_y() + (root.winfo_height() - log_window.winfo_height()) // 2
    log_window.geometry(f"+{x}+{y}")

    log_frame = tk.Frame(log_window)
    log_frame.pack(fill="both", expand=True, padx=5, pady=5)
    log_scroll = tk.Scrollbar(log_frame, orient="vertical")
    log_scroll.pack(side="right", fill="y")
    log_display = tk.Text(log_frame, height=15, width=50, state="disabled", yscrollcommand=log_scroll.set)
    log_display.pack(fill="both", expand=True)
    log_scroll.config(command=log_display.yview)

    log_display.config(state="normal")
    if ip in detected_epcs and 'log' in detected_epcs[ip]:
        for entry in detected_epcs[ip]['log']:
            log_display.insert(tk.END, f"{entry}\n")
    else:
        log_display.insert(tk.END, "No EPC detection logs for this device.\n")
    log_display.config(state="disabled")

def get_item_name(ip):
    for shelf in config["shelves"]:
        if shelf["ip"] == ip:
            return shelf["name"]
    for box in config["return_boxes"]:
        if box["ip"] == ip:
            return box["name"]
    return "Unknown"

def on_text_click(event, ip):
    if ip:
        show_item_log(ip)

def on_text_double_click(event, ip):
    if ip:
        show_item_log_window(ip)

def get_ip_from_text(text_widget, event):
    index = text_widget.index(f"@{event.x},{event.y}")
    line = int(index.split('.')[0])
    for ip, widgets in status_widgets.items():
        if widgets['text_widget'] == text_widget and widgets['line'] == line:
            return ip
    return None

def extract_epc(data):
    hex_data = data.hex().upper()
    if len(hex_data) >= 20:
        return hex_data[8:20]
    return None

def tcp_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server.bind(('0.0.0.0', LISTEN_PORT))
        server.listen(5)
        log_message(f"TCP server listening on port {LISTEN_PORT}")
        local_ip = socket.gethostbyname(socket.gethostname())
        base_ip = ".".join(local_ip.split(".")[:-1]) + "."
        for i in range(1, 255):
            ip = f"{base_ip}{i}"
            if ip in [s["ip"] for s in config["shelves"] + config["return_boxes"]]:
                log_message(f"Configured RFID reader IP: {ip}")
    except Exception as e:
        log_message(f"Failed to start TCP server: {str(e)}")
        return

    while True:
        try:
            client, addr = server.accept()
            ip = addr[0]
            threading.Thread(target=handle_client, args=(client, ip), daemon=True).start()
        except:
            break

def handle_client(client, ip):
    box_type = get_item_type(ip)
    
    if not box_type:
        if ip not in notified_ips:
            log_message(f"(detect IP {ip} can be connect)")
            notified_ips.add(ip)
        client.close()
        return

    if ip not in detected_epcs:
        detected_epcs[ip] = {}
        update_status(ip, 'green')
        send_connection_status(ip, True)
        log_message(f"Client connected: {ip} ({box_type})", ip)

    while True:
        try:
            data = client.recv(1024)
            if not data:
                break
            epc = extract_epc(data)
            if epc:
                now = datetime.now().timestamp()
                if epc not in detected_epcs[ip]:
                    detected_epcs[ip][epc] = {"last_seen": now, "sent": False}
                    log_message(f"EPC '{epc}' detected by {box_type} reader {ip}", ip)
                    send_to_render(ip, epc, box_type)
                    detected_epcs[ip][epc]["sent"] = True
                else:
                    detected_epcs[ip][epc]["last_seen"] = now
        except Exception as e:
            log_message(f"Error handling client {ip}: {str(e)}", ip)
            update_status(ip, 'red')
            break

    now = datetime.now().timestamp()
    for epc in list(detected_epcs[ip].keys()):
        if epc != "status" and now - detected_epcs[ip][epc]["last_seen"] > 5:
            if detected_epcs[ip][epc]["sent"]:
                log_message(f"EPC '{epc}' no longer detected by {box_type} reader {ip}", ip)
                send_to_render(ip, epc, box_type, detected=False)
            del detected_epcs[ip][epc]
    if len(detected_epcs[ip]) == 1 and "status" in detected_epcs[ip]:
        update_status(ip, 'grey')

    send_connection_status(ip, False)
    client.close()

def send_to_render(ip, epc, box_type, detected=True, retries=3):
    for attempt in range(retries):
        try:
            response = requests.post(RENDER_URL, json={
                "readerIp": ip,
                "epc": epc,
                "type": box_type,
                "detected": detected
            }, headers={"Content-Type": "application/json"}, timeout=5)
            log_message(f"EPC '{epc}' {'forwarded to' if detected else 'removed from'} Render from {ip} - Status: {response.status_code}", ip)
            return
        except Exception as e:
            log_message(f"Attempt {attempt + 1} failed for EPC '{epc}': {str(e)}", ip)
            if attempt < retries - 1:
                time.sleep(2)
            else:
                log_message(f"Failed to send EPC '{epc}' after {retries} attempts", ip)

def send_connection_status(ip, connected):
    try:
        response = requests.post("https://comp-fyp.onrender.com/api/connection-status", json={
            "readerIp": ip,
            "connected": connected
        }, headers={"Content-Type": "application/json"})
        log_message(f"Sent connection status for {ip}: {'connected' if connected else 'disconnected'} - Status: {response.status_code}", ip)
    except Exception as e:
        log_message(f"Error sending connection status for {ip}: {str(e)}", ip)

shelves_text.bind("<Button-1>", lambda event: on_text_click(event, get_ip_from_text(shelves_text, event)))
shelves_text.bind("<Double-1>", lambda event: on_text_double_click(event, get_ip_from_text(shelves_text, event)))
return_boxes_text.bind("<Button-1>", lambda event: on_text_click(event, get_ip_from_text(return_boxes_text, event)))
return_boxes_text.bind("<Double-1>", lambda event: on_text_double_click(event, get_ip_from_text(return_boxes_text, event)))

threading.Thread(target=tcp_server, daemon=True).start()

update_lists()
root.mainloop()