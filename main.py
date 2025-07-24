import logging
import serial
import struct
import time
import threading
import tkinter as tk
from tkinter import ttk, messagebox
#qeqweqweqwe dsdf
# --- CRC16 Modbus implementation ---
def crc16(data: bytes) -> int:
    crc = 0xFFFF
    for pos in data:
        crc ^= pos
        for _ in range(8):
            if (crc & 0x0001) != 0:
                crc >>= 1
                crc ^= 0xA001
            else:
                crc >>= 1
    return crc

def parse_modbus_request(frame: bytes):
    if not frame or len(frame) < 2:
        return ""
    addr = frame[0]
    func = frame[1]
    info = f"Addr: {addr} | Func: {func:02X}"
    if func == 0x01:
        if len(frame) >= 6:
            reg = int.from_bytes(frame[2:4], "big")
            cnt = int.from_bytes(frame[4:6], "big")
            info += f" | Coil Addr: {reg} | Qty: {cnt}"
    elif func == 0x03 or func == 0x04:
        if len(frame) >= 6:
            reg = int.from_bytes(frame[2:4], "big")
            cnt = int.from_bytes(frame[4:6], "big")
            info += f" | Reg: {reg} | Cnt: {cnt}"
    elif func == 0x06:
        if len(frame) >= 6:
            reg = int.from_bytes(frame[2:4], "big")
            val = int.from_bytes(frame[4:6], "big")
            info += f" | Reg: {reg} | Val: {val}"
    elif func == 0x10:
        if len(frame) >= 7:
            reg = int.from_bytes(frame[2:4], "big")
            cnt = int.from_bytes(frame[4:6], "big")
            info += f" | Reg: {reg} | Cnt: {cnt}"
    return info

HELP_TEXT = """\
Комментарии по каждому параметру вывода:

DEVICE_ADDR: [N]
    — Адрес Modbus-устройства (Slave Address), к которому обращается мастер. Число в десятичной системе.

CRC: [OK/BAD/INCOMPLETE]
    — Проверка контрольной суммы пакета (Cyclic Redundancy Check).
      OK — CRC совпадает, пакет корректный.
      BAD/INCOMPLETE — CRC не совпадает или пакет обрезан.

HEX: [байты]
    — Весь Modbus RTU-кадр в шестнадцатеричном виде (HEX).
      Например: 21 03 02 00 14 39 8C

Addr: [N]
    — То же, что DEVICE_ADDR — адрес устройства, выдернутый из первого байта пакета.

Func: [код]
    — Код функции Modbus (например, 03 — чтение удерживаемых регистров, 06 — запись регистра и т.д.)

Reg: [число]
    — В запросе: начальный адрес регистра (обычно байты 2 и 3).
      В ответе: может отсутствовать, т.к. вместо него идут данные.

Cnt: [число]
    — В запросе: количество регистров/катушек для чтения/записи.
      В ответе: может отсутствовать, либо показывает количество байт данных (для чтения).

Пример расшифровки:
DEVICE_ADDR: 33 | CRC: OK | HEX: 21 03 02 00 14 39 8C | Addr: 33 | Func: 03 | ...

— 21: Адрес устройства (33)
— 03: Код функции (03 - чтение регистров)
— 02: Количество байт данных (2)
— 00 14: Данные (значение регистра — 20)
— 39 8C: CRC

"""

class ModbusRS485SnifferGUI:
    def __init__(self, master):
        self.master = master
        master.title("Сниффер ТехноКом Modbus RTU RS485")

        self.serial_conn = None
        self.sniffing = False
        self.thread = None

        # --- Интерфейс выбора порта и скорости ---
        frame = ttk.Frame(master)
        frame.pack(padx=10, pady=10, fill="x")

        ttk.Label(frame, text="COM-порт:").grid(row=0, column=0, sticky="w")
        self.port_var = tk.StringVar()
        self.port_combo = ttk.Combobox(frame, textvariable=self.port_var, width=12, state="readonly")
        self.port_combo['values'] = self.get_serial_ports()
        self.port_combo.grid(row=0, column=1, sticky="ew", padx=(0, 10))

        ttk.Label(frame, text="Скорость:").grid(row=0, column=2, sticky="w")
        self.baud_var = tk.StringVar(value="19200")
        self.baud_combo = ttk.Combobox(frame, textvariable=self.baud_var, width=10, state="readonly")
        self.baud_combo['values'] = ["9600", "19200", "38400", "57600", "115200"]
        self.baud_combo.grid(row=0, column=3, sticky="ew", padx=(0, 10))

        self.start_button = ttk.Button(frame, text="Старт", command=self.start_sniffer)
        self.start_button.grid(row=0, column=4, padx=(0, 2))
        self.stop_button = ttk.Button(frame, text="Стоп", command=self.stop_sniffer, state="disabled")
        self.stop_button.grid(row=0, column=5, padx=(0, 2))

        self.help_button = ttk.Button(frame, text="Help", command=self.show_help)
        self.help_button.grid(row=0, column=6)

        # Поле для вывода логов
        self.log_text = tk.Text(master, wrap="none", height=25, width=110, font=("Courier New", 10))
        self.log_text.pack(padx=10, pady=(0, 10), fill="both", expand=True)
        self.log_text.config(state="disabled")

        # Привязка к закрытию окна
        master.protocol("WM_DELETE_WINDOW", self.on_close)

    def get_serial_ports(self):
        """Автоматически ищет доступные COM-порты."""
        try:
            import serial.tools.list_ports
            ports = [p.device for p in serial.tools.list_ports.comports()]
            return ports if ports else ["COM1", "COM2"]
        except ImportError:
            return ["COM1", "COM2"]

    def start_sniffer(self):
        """Запуск сниффера в отдельном потоке."""
        port = self.port_var.get()
        baud = int(self.baud_var.get())
        if not port or not baud:
            messagebox.showerror("Ошибка", "Выберите порт и скорость.")
            return
        self.log_text.config(state="normal")
        self.log_text.delete(1.0, "end")
        self.log_text.config(state="disabled")
        self.sniffing = True
        self.start_button.config(state="disabled")
        self.stop_button.config(state="normal")
        self.thread = threading.Thread(target=self.sniff, args=(port, baud), daemon=True)
        self.thread.start()

    def stop_sniffer(self):
        """Остановить сниффер."""
        self.sniffing = False
        self.start_button.config(state="normal")
        self.stop_button.config(state="disabled")
        if self.serial_conn and self.serial_conn.is_open:
            try:
                self.serial_conn.close()
            except Exception:
                pass
        self.log("Сниффер остановлен.", clear=False)

    def log(self, msg, clear=False):
        """Пишет сообщение в логовое окно."""
        self.log_text.config(state="normal")
        if clear:
            self.log_text.delete(1.0, "end")
        self.log_text.insert("end", f"{msg}\n")
        self.log_text.see("end")
        self.log_text.config(state="disabled")

    def sniff(self, port, baud):
        """Основной цикл сниффера."""
        try:
            self.serial_conn = serial.Serial(
                port=port,
                baudrate=baud,
                bytesize=serial.EIGHTBITS,
                parity=serial.PARITY_NONE,
                stopbits=serial.STOPBITS_ONE,
                timeout=0.01
            )
            self.log(f"Подключено к {port} @ {baud} бод (8N1)")
        except Exception as e:
            self.log(f"Ошибка подключения: {e}")
            self.stop_sniffer()
            return

        last_data_time = time.time()
        buffer = bytearray()
        direction = "RX"

        self.log("Сниффер запущен. Для остановки нажмите 'Стоп'.")
        try:
            while self.sniffing:
                now = time.time()
                waiting = self.serial_conn.in_waiting
                if waiting > 0:
                    data = self.serial_conn.read(waiting)
                    buffer.extend(data)
                    last_data_time = now
                else:
                    # Если была пауза - ищем кадры по CRC
                    if buffer and (now - last_data_time > 0.01):
                        idx = 0
                        while idx + 4 <= len(buffer):  # Минимум 4 байта на кадр
                            for end in range(idx+4, len(buffer)+1):
                                candidate = buffer[idx:end]
                                if len(candidate) < 4:
                                    continue
                                frame_wo_crc = candidate[:-2]
                                crc_recv = int.from_bytes(candidate[-2:], 'little')
                                crc_calc = crc16(frame_wo_crc)
                                if crc_calc == crc_recv:
                                    hex_str = ' '.join(f"{b:02X}" for b in candidate)
                                    address = candidate[0]
                                    extra = parse_modbus_request(candidate)
                                    self.log(
                                        f"{direction} | DEVICE_ADDR: {address} | CRC: OK | HEX: {hex_str} | {extra}"
                                    )
                                    idx = end
                                    break
                            else:
                                idx += 1
                        if idx < len(buffer):
                            remain = buffer[idx:]
                            hex_str = ' '.join(f"{b:02X}" for b in remain)
                            address = remain[0] if len(remain) > 0 else "-"
                            extra = parse_modbus_request(remain)
                            self.log(
                                f"{direction} | DEVICE_ADDR: {address} | CRC: BAD/INCOMPLETE | HEX: {hex_str} | {extra}"
                            )
                        buffer.clear()
                        direction = "RX" if direction == "TX" else "TX"
                    time.sleep(0.001)
        except Exception as e:
            self.log(f"Ошибка: {e}")
        finally:
            if self.serial_conn and self.serial_conn.is_open:
                self.serial_conn.close()
            self.sniffing = False
            self.start_button.config(state="normal")
            self.stop_button.config(state="disabled")
            self.log("Сниффер остановлен.", clear=False)

    def show_help(self):
        """Показать справку по параметрам в отдельном окне."""
        help_win = tk.Toplevel(self.master)
        help_win.title("Help — Комментарии к параметрам")
        help_win.geometry("700x550")
        text = tk.Text(help_win, wrap="word", font=("Courier New", 10))
        text.insert("1.0", HELP_TEXT)
        text.config(state="disabled")
        text.pack(fill="both", expand=True, padx=12, pady=12)
        btn = ttk.Button(help_win, text="Закрыть", command=help_win.destroy)
        btn.pack(pady=(0, 12))

    def on_close(self):
        """Обработка закрытия окна."""
        self.sniffing = False
        time.sleep(0.1)
        self.master.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = ModbusRS485SnifferGUI(root)
    root.mainloop()