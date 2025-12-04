import tkinter as tk
from tkinter.scrolledtext import ScrolledText
import os

def open_report_window(file_path):
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Report not found: {file_path}")

    with open(file_path, "r", encoding="utf-8") as f:
        content = f.read()

    root = tk.Tk()
    root.title("SVDF Report Viewer")
    root.geometry("900x600")

    text_area = ScrolledText(root, wrap='word', font=("Consolas", 11))
    text_area.pack(expand=True, fill='both')
    text_area.insert('1.0', content)
    text_area.config(state='disabled')   # make it read-only

    root.mainloop()

if __name__ == "__main__":
    # CHANGE THIS if your report file name is different
    report_file = os.path.join("reports", "final_report.txt")

    open_report_window(report_file)
