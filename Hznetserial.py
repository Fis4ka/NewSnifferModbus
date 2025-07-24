import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext
import threading
from collections import deque
import csv
from datetime import datetime
import traceback

# Расчёт CRC16 (Modbus) по стандартному алгоритму
def modbus_crc16(data: bytes) -> int:
    """Calculate CRC16 (Modbus) for data (bytes)."""
    crc = 0xFFFF
    for aByte in data:
        crc ^= aByte
        for _ in range(8):
            if crc & 0x0001:
                crc >>= 1
                crc ^= 0xA001
            else:
                crc >>= 1
    return crc

class ModbusSnifferGUI:
    def __init__(self, master):
        self.master = master
        master.title("Modbus RTU Sniffer")
        
        # Флаги и буфер
        self.running = False               # флаг работы сниффера
        self.buffer = deque()             # буфер считанных байт
        self.total_packets = 0
        self.crc_ok = 0
        self.crc_bad = 0
        
        # Метки и поля ввода COM-порта и скорости
        ttk.Label(master, text="COM Port:").grid(row=0, column=0, padx=5, pady=5, sticky='w')
        self.com_entry = ttk.Entry(master, width=10)
        self.com_entry.grid(row=0, column=1, padx=5, pady=5, sticky='w')
        self.com_entry.insert(0, "COM1")
        
        ttk.Label(master, text="Baudrate:").grid(row=0, column=2, padx=5, pady=5, sticky='w')
        self.baud_entry = ttk.Entry(master, width=10)
        self.baud_entry.grid(row=0, column=3, padx=5, pady=5, sticky='w')
        self.baud_entry.insert(0, "9600")
        
        # Автосохранение (checkbox + поле интервала)
        self.autosave_var = tk.BooleanVar()
        self.autosave_check = ttk.Checkbutton(master, text="Auto-save (min)", variable=self.autosave_var,
                                              command=self.toggle_autosave)
        self.autosave_check.grid(row=0, column=4, padx=5, pady=5, sticky='w')
        self.interval_entry = ttk.Entry(master, width=5)
        self.interval_entry.grid(row=0, column=5, padx=5, pady=5, sticky='w')
        self.interval_entry.insert(0, "1")  # по умолчанию 1 минута
        
        # Кнопки управления
        self.start_button = ttk.Button(master, text="Start", command=self.start_sniffer)
        self.start_button.grid(row=1, column=0, padx=5, pady=5)
        self.stop_button = ttk.Button(master, text="Stop", command=self.stop_sniffer, state='disabled')
        self.stop_button.grid(row=1, column=1, padx=5, pady=5)
        self.save_button = ttk.Button(master, text="Save Log", command=self.save_log)
        self.save_button.grid(row=1, column=2, padx=5, pady=5)
        self.clear_button = ttk.Button(master, text="Clear Log", command=self.clear_log)
        self.clear_button.grid(row=1, column=3, padx=5, pady=5)
        
        # Таблица Treeview для логов пакетов
        self.tree = ttk.Treeview(master, columns=("Time", "Address", "Function", "CRC", "Status", "Hex"),
                                  show='headings')
        for col, width in [("Time",100), ("Address",70), ("Function",70),
                           ("CRC",70), ("Status",80), ("Hex",200)]:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=width)
        # Теги для раскраски строк
        self.tree.tag_configure('ok', background='#d0ffd0')
        self.tree.tag_configure('bad', background='#ffd0d0')
        self.tree.grid(row=2, column=0, columnspan=6, padx=5, pady=5, sticky='nsew')
        
        # Скроллбары для таблицы
        vsb = ttk.Scrollbar(master, orient="vertical", command=self.tree.yview)
        vsb.grid(row=2, column=6, sticky='ns')
        self.tree.configure(yscrollcommand=vsb.set)
        hsb = ttk.Scrollbar(master, orient="horizontal", command=self.tree.xview)
        hsb.grid(row=3, column=0, columnspan=6, sticky='ew')
        self.tree.configure(xscrollcommand=hsb.set)
        
        # Статистика сниффера
        self.stats_label = ttk.Label(master, text="Total: 0    CRC OK: 0    CRC BAD: 0")
        self.stats_label.grid(row=4, column=0, columnspan=4, padx=5, pady=5, sticky='w')
        
        # Поле лога ошибок (скроллируемое)
        self.log_text = scrolledtext.ScrolledText(master, height=8, state='disabled')
        self.log_text.grid(row=5, column=0, columnspan=7, padx=5, pady=5, sticky='nsew')
        
        # Растягиваем таблицу и лог при изменении размера окна
        master.grid_rowconfigure(2, weight=1)
        master.grid_columnconfigure(5, weight=1)
        
    def log_error(self, msg):
        """Вывод сообщения об ошибке с трассировкой в текстовый лог."""
        self.log_text.configure(state='normal')
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.log_text.insert(tk.END, f"[{timestamp}] {msg}\n")
        self.log_text.configure(state='disabled')
        self.log_text.see(tk.END)
        
    def update_stats(self):
        """Обновляет метку со статистикой пакетов."""
        self.stats_label.config(text=f"Total: {self.total_packets}    CRC OK: {self.crc_ok}    CRC BAD: {self.crc_bad}")
        
    def start_sniffer(self):
        """Обработка нажатия Start: валидация параметров, запуск потоков."""
        com = self.com_entry.get().strip()
        baud = self.baud_entry.get().strip()
        if not com:
            messagebox.showerror("Error", "Please enter COM port (e.g., COM3).")
            return
        try:
            baud = int(baud)
        except ValueError:
            messagebox.showerror("Error", "Baudrate must be an integer.")
            return
        
        # Переключаем кнопки
        self.start_button.config(state='disabled')
        self.stop_button.config(state='normal')
        # Сбрасываем статистику и логи
        self.total_packets = 0; self.crc_ok = 0; self.crc_bad = 0
        self.update_stats()
        self.log_text.configure(state='normal'); self.log_text.delete("1.0", tk.END); self.log_text.configure(state='disabled')
        for item in self.tree.get_children(): self.tree.delete(item)
        
        # Запускаем потоки
        self.running = True
        self.buffer.clear()
        self.read_thread = threading.Thread(target=self.read_from_port, args=(com, baud), daemon=True)
        self.read_thread.start()
        self.analyze_thread = threading.Thread(target=self.analyze_buffer, daemon=True)
        self.analyze_thread.start()
        # Если включено автосохранение, запускаем первый таймер
        if self.autosave_var.get():
            self.schedule_save()
        
    def stop_sniffer(self):
        """Останавливает потоки сниффера."""
        self.running = False
        self.stop_button.config(state='disabled')
        self.start_button.config(state='normal')
        # Отключаем автосохранение
        if hasattr(self, 'save_after_id'):
            self.master.after_cancel(self.save_after_id)
            del self.save_after_id
        
    def save_log(self):
        """Сохраняет лог таблицы в CSV-файл по выбору пользователя."""
        file_path = filedialog.asksaveasfilename(defaultextension=".csv",
                                                 filetypes=[("CSV files","*.csv"),("All files","*.*")])
        if not file_path:
            return
        try:
            with open(file_path, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(["Time", "Address", "Function", "CRC", "Status", "HEX"])
                for item in self.tree.get_children():
                    writer.writerow(self.tree.item(item, 'values'))
            self.log_error(f"Log saved to {file_path}")
        except Exception as e:
            self.log_error("Error saving log: " + str(e))
            self.log_error(traceback.format_exc())
        
    def clear_log(self):
        """Очищает таблицу и статистику."""
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.total_packets = 0; self.crc_ok = 0; self.crc_bad = 0
        self.update_stats()
        
    def toggle_autosave(self):
        """Включает/выключает автосохранение."""
        if self.autosave_var.get():
            self.schedule_save()
        else:
            if hasattr(self, 'save_after_id'):
                self.master.after_cancel(self.save_after_id)
                del self.save_after_id
    
    def schedule_save(self):
        """Запланировать следующее автосохранение через заданный интервал."""
        try:
            minutes = float(self.interval_entry.get())
            if minutes <= 0:
                raise ValueError
        except ValueError:
            messagebox.showerror("Error", "Auto-save interval must be a positive number.")
            self.autosave_var.set(False)
            return
        ms = int(minutes * 60 * 1000)
        self.save_after_id = self.master.after(ms, self.auto_save_action)
        
    def auto_save_action(self):
        """Действие автосохранения: сохраняет CSV с датой/временем в имени."""
        default_name = datetime.now().strftime("modbus_log_%Y%m%d_%H%M%S.csv")
        try:
            with open(default_name, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(["Time", "Address", "Function", "CRC", "Status", "HEX"])
                for item in self.tree.get_children():
                    writer.writerow(self.tree.item(item, 'values'))
            self.log_error(f"Auto-saved log to {default_name}")
        except Exception as e:
            self.log_error("Error auto-saving log: " + str(e))
            self.log_error(traceback.format_exc())
        # Планируем следующее автосохранение
        self.schedule_save()
        
    def read_from_port(self, port, baud):
        """Поток чтения: открывает порт и читает байты, помещая их в буфер."""
        try:
            import sys, os
            if sys.platform.startswith('win'):
                # Windows: формируем имя \\.\COMx для COM10+
                com_name = port.upper()
                if not com_name.startswith('COM'):
                    com_name = 'COM' + com_name
                com_name = r'\\\\.\\' + com_name
                # Пробуем задать параметры порта через cmd 'mode'
                try:
                    os.system(f"mode {port}: baud={baud} parity=n data=8 stop=1")
                except Exception as e:
                    self.log_error("Warning: could not set COM params via mode: " + str(e))
                ser = open(com_name, 'rb', buffering=0)
            else:
                # POSIX (для Linux/Unix): открываем файл устройства (нужно имя порта)
                ser = open(port, 'rb', buffering=0)
            self.log_error(f"Opened port {port} at {baud} baud")
            while self.running:
                data = ser.read(1)  # читаем по одному байту
                if data:
                    self.buffer.extend(data)
                else:
                    import time
                    time.sleep(0.01)
            ser.close()
        except Exception as e:
            self.log_error("Error reading from port: " + str(e))
            self.log_error(traceback.format_exc())
        
    def analyze_buffer(self):
        """Поток анализа: разбирает пакеты из буфера, проверяет CRC, обновляет UI."""
        import time
        while self.running:
            try:
                # Обрабатываем все полные кадры в буфере
                # Минимальная длина кадра: 4 байта (Addr, Func, CRC1, CRC2)
                while len(self.buffer) >= 4:
                    addr = self.buffer[0]
                    func = self.buffer[1]
                    # Определяем ожидаемую длину кадра
                    if func >= 0x80:
                        # Exception response: Addr, Func, ErrorCode, CRC1, CRC2
                        frame_len = 5
                    elif func in (1,2,3,4):
                        if len(self.buffer) < 3:
                            break
                        byte_count = self.buffer[2]
                        frame_len = 3 + byte_count + 2
                    elif func in (5,6,15,16):
                        frame_len = 8
                    else:
                        # Неизвестная функция – сбрасываем байт, чтобы не застрять
                        self.buffer.popleft()
                        continue
                    if len(self.buffer) < frame_len:
                        break
                    # Извлекаем кадр из буфера
                    frame = bytes([self.buffer.popleft() for _ in range(frame_len)])
                    # Проверяем CRC: последние 2 байта = проверка (младший байт первый)
                    received_crc = frame[-2] + (frame[-1] << 8)
                    calc_crc = modbus_crc16(frame[:-2])
                    crc_ok = (received_crc == calc_crc)
                    status = "CRC OK" if crc_ok else "CRC BAD"
                    if crc_ok:
                        self.crc_ok += 1
                    else:
                        self.crc_bad += 1
                    self.total_packets += 1
                    # Формируем поля для отображения
                    time_str = datetime.now().strftime("%H:%M:%S.%f")[:-3]
                    address_str = f"{frame[0]:02X}"
                    func_code = frame[1]
                    func_str = f"{func_code:02X}"
                    crc_str = f"{received_crc:04X}"
                    hex_str = frame.hex().upper()
                    # Обработка исключения Modbus, если есть
                    if func_code >= 0x80:
                        exc_code = frame[2]
                        exc_map = {
                            1: "Illegal Function", 2: "Illegal Data Addr",
                            3: "Illegal Data Value", 4: "Device Failure",
                            5: "Acknowledge", 6: "Device Busy",
                            7: "NACK", 8: "Memory Error",
                            10: "Gateway Path Unavail", 11: "Gateway Tgt Fail"
                        }
                        exc_text = exc_map.get(exc_code, f"Code {exc_code:02X}")
                        status = f"EXC: {exc_text}"
                    tag = 'ok' if crc_ok else 'bad'
                    # Вставляем строку в таблицу
                    self.tree.insert('', 'end', values=(time_str, address_str, func_str, crc_str, status, hex_str), tags=(tag,))
                    self.update_stats()
                time.sleep(0.01)
            except Exception as e:
                self.log_error("Error in analysis: " + str(e))
                self.log_error(traceback.format_exc())
                time.sleep(0.5)

if __name__ == "__main__":
    root = tk.Tk()
    gui = ModbusSnifferGUI(root)
    root.mainloop()
