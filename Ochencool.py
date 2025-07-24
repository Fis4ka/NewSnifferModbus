import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from collections import deque
import threading
import time
import datetime
import csv
import traceback

# Attempt to import pyserial (for COM port access)
try:
    import serial
except ImportError:
    serial = None

running = False
buffer = deque(maxlen=1000)  # limited buffer:contentReference[oaicite:11]{index=11}
total_packets = crc_ok = crc_bad = 0

# Set up main window
root = tk.Tk()
root.title("Modbus RTU Sniffer")
root.geometry("800x600")

# Settings frame (COM port, baud, filter, auto-save)
config_frame = tk.LabelFrame(root, text="Settings")
config_frame.pack(fill="x", padx=5, pady=5)
tk.Label(config_frame, text="COM Port:").grid(row=0, column=0, sticky="w")
com_entry = tk.Entry(config_frame, width=10)
com_entry.insert(0, "COM1")
com_entry.grid(row=0, column=1, padx=5, pady=2)
tk.Label(config_frame, text="Baud Rate:").grid(row=0, column=2, sticky="w")
baud_entry = tk.Entry(config_frame, width=10)
baud_entry.insert(0, "9600")
baud_entry.grid(row=0, column=3, padx=5, pady=2)
tk.Label(config_frame, text="Address Filter (hex):").grid(row=0, column=4, sticky="w")
filter_entry = tk.Entry(config_frame, width=5)
filter_entry.grid(row=0, column=5, padx=5, pady=2)
# Auto-save options
auto_var = tk.BooleanVar()
auto_check = tk.Checkbutton(config_frame, text="Auto Save (min):", variable=auto_var)
auto_check.grid(row=0, column=6, padx=5, pady=2)
auto_interval = tk.Entry(config_frame, width=5)
auto_interval.insert(0, "5")
auto_interval.grid(row=0, column=7, padx=5, pady=2)

# Buttons and counters frame
button_frame = tk.Frame(root)
button_frame.pack(fill="x", padx=5, pady=5)
start_button = tk.Button(button_frame, text="Start", width=12)
start_button.pack(side="left", padx=5)
stop_button = tk.Button(button_frame, text="Stop", width=12, state="disabled")
stop_button.pack(side="left", padx=5)
save_button = tk.Button(button_frame, text="Save Log", width=12)
save_button.pack(side="left", padx=5)
clear_button = tk.Button(button_frame, text="Clear Log", width=12)
clear_button.pack(side="left", padx=5)
total_label = tk.Label(button_frame, text="Total: 0")
total_label.pack(side="left", padx=10)
ok_label = tk.Label(button_frame, text="CRC OK: 0")
ok_label.pack(side="left", padx=10)
bad_label = tk.Label(button_frame, text="CRC BAD: 0")
bad_label.pack(side="left", padx=10)

# Treeview log table with columns
log_frame = tk.Frame(root)
log_frame.pack(fill="both", expand=True, padx=5, pady=5)
tree = ttk.Treeview(log_frame,
    columns=("Time","Address","Function","CRC","Status","HEX"),
    show="headings", selectmode="browse")
# Define headings
for col in ("Time","Address","Function","CRC","Status","HEX"):
    tree.heading(col, text=col)
    tree.column(col, width=100)
tree.column("HEX", width=200)
tree.pack(side="left", fill="both", expand=True)
# Vertical scrollbar
vsb = ttk.Scrollbar(log_frame, orient="vertical", command=tree.yview)
vsb.pack(side="right", fill="y")
tree.configure(yscrollcommand=vsb.set)
# Color tags for rows:contentReference[oaicite:12]{index=12}
tree.tag_configure('ok', background='lightgreen')
tree.tag_configure('bad', background='tomato')

def calc_crc16(data: bytes):
    """Compute Modbus CRC-16 (poly 0xA001) for a byte array."""
    crc = 0xFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            if crc & 0x0001:
                crc = (crc >> 1) ^ 0xA001
            else:
                crc >>= 1
    return crc

def read_thread():
    """Thread to read bytes from the serial port into the buffer."""
    global running
    try:
        port = com_entry.get()
        baud = int(baud_entry.get())
    except Exception as e:
        messagebox.showerror("Error", f"Invalid port or baud: {e}")
        running = False
        return
    if serial is None:
        messagebox.showerror("Error", "pySerial not installed")
        running = False
        return
    try:
        ser = serial.Serial(port, baudrate=baud, timeout=0.1)
    except Exception as e:
        messagebox.showerror("Error", f"Cannot open serial port: {e}")
        running = False
        return
    while running:
        try:
            n = ser.in_waiting
            if n:
                data = ser.read(n)  # read all available bytes
                if data:
                    buffer.append(data)  # store frame fragment
            time.sleep(0.01)
        except Exception:
            # Log the full traceback:contentReference[oaicite:13]{index=13}
            err = traceback.format_exc()
            tree.insert("", "end", values=(
                datetime.datetime.now().strftime("%H:%M:%S"),
                "", "", "", "ERROR", ""), tags=('bad',))
            print(err)
            time.sleep(1)
    ser.close()

def analyze_thread():
    """Thread to process buffered frames, update Treeview and counters."""
    global total_packets, crc_ok, crc_bad
    while running:
        if buffer:
            frame = buffer.popleft()
            now = datetime.datetime.now().strftime("%H:%M:%S")
            addr = func = crc_val = status = hex_str = ""
            hex_str = frame.hex().upper()
            # Apply filter if set
            fstr = filter_entry.get().strip()
            try:
                if fstr:
                    filt = int(fstr, 16)
                else:
                    filt = None
            except:
                filt = None
            try:
                if len(frame) >= 4:
                    addr_val = frame[0]
                    if (filt is None) or (addr_val == filt):
                        addr = f"0x{addr_val:02X}"
                        func_byte = frame[1]
                        if func_byte & 0x80:
                            # Exception response:contentReference[oaicite:14]{index=14}:contentReference[oaicite:15]{index=15}
                            func = f"0x{func_byte:02X}"
                            ex_code = frame[2] if len(frame)>2 else 0
                            status = f"Exception 0x{ex_code:02X}"
                        else:
                            func = f"0x{func_byte:02X}"
                        # Check CRC (last 2 bytes: low, high)
                        crc_received = frame[-2] | (frame[-1] << 8)
                        crc_val = f"0x{crc_received:04X}"
                        crc_calc = calc_crc16(frame[:-2])
                        if crc_received == crc_calc:
                            status = status or "OK"
                            tag = 'ok'
                            crc_ok += 1
                        else:
                            status = status or "BAD CRC"
                            tag = 'bad'
                            crc_bad += 1
                        total_packets += 1
                    else:
                        # Address not matching filter; skip
                        continue
                else:
                    # Incomplete frame
                    status = "Incomplete"
                    tag = 'bad'
                    total_packets += 1
            except Exception:
                err = traceback.format_exc()
                tree.insert("", "end", values=(now, addr, func, crc_val, "ERROR", hex_str), tags=('bad',))
                print(err)
                continue
            # Insert row into Treeview
            tree.insert("", "end", values=(now, addr, func, crc_val, status, hex_str), tags=(tag,))
            # Update counters display
            total_label.config(text=f"Total: {total_packets}")
            ok_label.config(text=f"CRC OK: {crc_ok}")
            bad_label.config(text=f"CRC BAD: {crc_bad}")
        else:
            time.sleep(0.01)

def save_log():
    """Save all log rows to a CSV file."""
    file_path = filedialog.asksaveasfilename(defaultextension=".csv",
                                             filetypes=[("CSV files","*.csv")])
    if not file_path:
        return
    try:
        with open(file_path, 'w', newline='') as f:
            writer = csv.writer(f)  # write rows:contentReference[oaicite:16]{index=16}
            writer.writerow(["Time","Address","Function","CRC","Status","HEX"])
            for row_id in tree.get_children():
                writer.writerow(tree.item(row_id)['values'])
        messagebox.showinfo("Save Log", "Log saved successfully.")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to save log: {e}")

def clear_log():
    """Clear the Treeview log and reset counters."""
    global total_packets, crc_ok, crc_bad
    for row_id in tree.get_children():
        tree.delete(row_id)
    total_packets = crc_ok = crc_bad = 0
    total_label.config(text="Total: 0")
    ok_label.config(text="CRC OK: 0")
    bad_label.config(text="CRC BAD: 0")

def start_sniffer():
    """Start the reader and analyzer threads."""
    global running, total_packets, crc_ok, crc_bad
    if running:
        return
    # Reset counters
    total_packets = crc_ok = crc_bad = 0
    running = True
    stop_button.config(state="normal")
    start_button.config(state="disabled")
    threading.Thread(target=read_thread, daemon=True).start()
    threading.Thread(target=analyze_thread, daemon=True).start()
    # Schedule auto-save if enabled
    if auto_var.get():
        try:
            mins = int(auto_interval.get())
            if mins > 0:
                root.after(mins * 60000, periodic_save)
        except:
            pass

def periodic_save():
    """Auto-save log at intervals if running."""
    if running:
        save_log()
        try:
            mins = int(auto_interval.get())
            if mins > 0:
                root.after(mins * 60000, periodic_save)
        except:
            pass

def stop_sniffer():
    """Stop the sniffer threads."""
    global running
    running = False
    stop_button.config(state="disabled")
    start_button.config(state="normal")

# Button callbacks
start_button.config(command=start_sniffer)
stop_button.config(command=stop_sniffer)
save_button.config(command=save_log)
clear_button.config(command=clear_log)

root.mainloop()
