import os
import re
import subprocess
import threading
import tkinter as tk
from tkinter import scrolledtext, messagebox
from PIL import Image, ImageTk
import xss
from nuclei import run_nuclei_scan


def sanitize_filename(name):
    """
    Replaces invalid filename characters with underscores.
    """
    return re.sub(r'[^\w\-_\.]', '_', name)


def clean_output(text):
    """
    Cleans ANSI escape codes, redundant whitespace, and unnecessary characters from the given text.
    """
    ansi_escape = re.compile(r'(?:\x1B[@-_]|[\x80-\x9F][@-_])[0-?]*[ -/]*[@-~]')
    cleaned_text = ansi_escape.sub('', text)
    return re.sub(r'\n+', '\n', cleaned_text).strip()

def run_command(command, output_widget, command_tag="terminal_red", output_tag="default"):
    """
    Executes a shell command and displays its output in the GUI with proper styling.
    """
    try:
        # Insert the command with the specified tag
        output_widget.insert(tk.END, f"Running Command: {command}\n", command_tag)
        output_widget.yview(tk.END)

        process = subprocess.Popen(
            command, shell=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )

        output = []
        for line in iter(process.stdout.readline, ''):
            if not line:
                break
            clean_line = clean_output(line)
            output.append(clean_line)
            output_widget.insert(tk.END, clean_line + "\n", output_tag)
            output_widget.yview(tk.END)

        process.wait()
        return output

    except Exception as e:
        output_widget.insert(tk.END, f"An error occurred: {e}\n", "red")
        output_widget.yview(tk.END)
        return []  # Return an empty list to avoid NoneType issues


def directory_scan_ffuf(domain, output_widget=None):
    """
    Performs a directory scan using ffuf for a single domain.
    Saves results to results/directory/{domain}.txt only if there are 200 or 403 responses.
    """
    try:
        wordlist = "common.txt"  # Sabit wordlist dosyası
        sanitized_domain = sanitize_filename(domain)  # Dosya ismi için domain temizliği
        results_folder = "results/directory"  # Sonuçların kaydedileceği ana klasör
        os.makedirs(results_folder, exist_ok=True)  # Klasörü oluştur (varsa hata yapmaz)

        temp_output_file = os.path.join(results_folder, f"{sanitized_domain}_temp.txt")  # Geçici dosya
        final_output_file = os.path.join(results_folder, f"{sanitized_domain}.txt")  # Nihai dosya

        if not os.path.exists(wordlist):
            raise FileNotFoundError(f"Wordlist '{wordlist}' not found.")

        if output_widget:
            output_widget.insert(tk.END, f"[+] Scanning directories for {domain} using ffuf...\n", "default")
            output_widget.yview(tk.END)

        # ffuf komutu
        command = f"ffuf -w {wordlist} -u {domain}/FUZZ -mc 200,403 -o {temp_output_file} -of md"
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        stdout, stderr = process.communicate()

        if stdout:
            if output_widget:
                output_widget.insert(tk.END, clean_output(stdout), "default")
        if stderr:
            if output_widget:
                output_widget.insert(tk.END, clean_output(stderr), "red")

        # Geçici dosyayı temiz formatta düzenleyerek kaydet
        if os.path.exists(temp_output_file):
            with open(temp_output_file, "r") as temp_file:
                content = temp_file.readlines()

            formatted_results = []
            current_entry = {}

            for line in content:
                line = line.strip()
                if line.startswith("|"):  # FFUF çıktısındaki tablo satırları
                    columns = [col.strip() for col in line.split("|")]
                    if len(columns) > 5 and columns[5] in ["200", "403"]:  # Sadece 200 ve 403 durum kodları
                        current_entry = {
                            "Status Code": columns[5],
                            "URL": columns[2],
                            "Content Length": columns[6],
                            "Content Words": columns[7],
                            "Content Lines": columns[8],
                            "Content Type": columns[9]
                        }
                        formatted_results.append(current_entry)

            if formatted_results:  # Eğer sonuçlar varsa
                with open(final_output_file, "w") as final_file:
                    final_file.write(f"# FFUF Report for: {domain}\n\n")
                    for entry in formatted_results:
                        final_file.write(f"Status Code: {entry['Status Code']}\n")
                        final_file.write(f"URL: {entry['URL']}\n")
                        final_file.write(f"Content Length: {entry['Content Length']}\n")
                        final_file.write(f"Content Words: {entry['Content Words']}\n")
                        final_file.write(f"Content Lines: {entry['Content Lines']}\n")
                        final_file.write(f"Content Type: {entry['Content Type']}\n\n")

                if output_widget:
                    output_widget.insert(tk.END, f"\n[+] 200 or 403 responses found for {domain}. Results saved to {final_output_file}.\n", "light_green")
            else:  # Hiç uygun sonuç yoksa
                os.remove(temp_output_file)  # Geçici dosyayı sil
                if output_widget:
                    output_widget.insert(tk.END, f"\n[!] No 200 or 403 responses found for {domain}. Skipping.\n", "red")

    except Exception as e:
        if output_widget:
            output_widget.insert(tk.END, f"[-] Error during directory scan for {domain}: {e}\n", "red")
            output_widget.yview(tk.END)


def process_subdomains_for_scan(output_widget):
    """
    Processes subdomains from subdomains.txt and performs directory scan for each.
    """
    subdomains_file = "subdomains.txt"

    if not os.path.exists(subdomains_file):
        raise FileNotFoundError(f"Subdomains file '{subdomains_file}' not found. Please run subdomain scan first.")

    with open(subdomains_file, "r") as file:
        subdomains = [line.strip() for line in file if line.strip()]

    for subdomain in subdomains:
        directory_scan_ffuf(subdomain, output_widget)


def fetch_subdomains(domain, output_widget):
    """
    Performs subdomain scanning using multiple tools, filters results, and saves them.
    """
    commands = [
        f"subfinder -d {domain} -silent | ./httpx -mc 200",
        f"curl -s 'https://api.certspotter.com/v1/issuances?domain=tesla.com&include_subdomains=true&expand=dns_names' | jq -r '.[] | .dns_names[]' | grep -Po '(([\w.-]+)\\.[A-Za-z]{2,})' | sort -u | ./httpx -mc 200"
        #f"amass enum -d {domain} | ./httpx -mc 200",
        f"curl -s 'https://crt.sh/?q=%25.{domain}&output=json' | jq -r '.[].name_value' | sed 's/\\*\\.//g' | ./httpx -mc 200",
        f"assetfinder --subs-only {domain} | ./httpx -mc 200",
        f"findomain -t {domain} | ./httpx -mc 200",
        f"theHarvester -d {domain} -b all | ./httpx -mc 200",
        f"curl -s 'https://api.subdomain.center/?domain={domain}' | jq -r '.[]' | sort -u | ./httpx -mc 200",
        f"curl -s 'https://api.hackertarget.com/hostsearch/?q={domain}'",
        f"curl -s 'https://jldc.me/anubis/subdomains/{domain}' | jq -r '.' | grep -o '\\w.*{domain}'",
        f"curl -s 'https://otx.alienvault.com/api/v1/indicators/domain/{domain}/url_list?limit=100&page=1' | grep -o '\"hostname\": *\"[^\"]*' | sed 's/\"hostname\": \"//g' | sort -u"
        f"curl -s 'https://rapiddns.io/subdomain/{domain}?full=1#result' | grep -e '<td>.*{domain}</td>' | grep -oP '(?<=<td>)[^<]+' | sort -u"
    ]


    unique_domains = set()

    for command in commands:
        result = run_command(command, output_widget)
        unique_domains.update(result)

    # Filter and save cleaned URLs
    with open("subdomains.txt", "w") as outfile:
        cleaned_urls = set()
        for url in unique_domains:
            url = url.rstrip("/")  # Remove trailing "/"
            # Check if the URL matches a valid domain format
            if re.match(r'^https?://[^?/-]+\.[a-z]{2,}$', url):
                cleaned_urls.add(url)

        for url in cleaned_urls:
            outfile.write(url + "\n")

    if cleaned_urls:
        output_widget.insert(tk.END, "Subdomain scan completed. Filtered unique URLs saved to 'subdomains.txt'.\n", "light_green")
    else:
        output_widget.insert(tk.END, "No valid subdomains found. Please check the commands and target.\n", "red")

    output_widget.yview(tk.END)
def run_paramspider(output_widget):
    """
    Executes ParamSpider on subdomains and saves results only if there are valid outputs.
    Results are displayed in the output_widget.
    """
    try:
        input_file = "subdomains.txt"
        results_folder = "results/paramspider"
        os.makedirs(results_folder, exist_ok=True)  # Klasörü oluştur (varsa hata yapmaz)

        if not os.path.exists(input_file):
            raise FileNotFoundError(f"{input_file} not found. Please run subdomain scan first.")

        with open(input_file, "r") as file:
            subdomains = file.readlines()

        for subdomain in subdomains:
            subdomain = subdomain.strip()
            if not subdomain:
                continue

            sanitized_domain = re.sub(r'^https?://', '', subdomain)

            output_widget.insert(tk.END, f"Running ParamSpider on: {sanitized_domain}\n", "default")
            output_widget.yview(tk.END)

            command = f"paramspider -d {sanitized_domain}"
            try:
                process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                stdout, stderr = process.communicate()

                # Çıktıyı GUI'de göster
                if stdout:
                    output_widget.insert(tk.END, stdout, "default")
                if stderr:
                    output_widget.insert(tk.END, stderr, "red")

                # Anlamlı sonuçlar için kontrol
                result_lines = [
                    line.strip() for line in stdout.splitlines()
                    if line.strip() and "=" in line  # "=" içeren satırlar anlamlı kabul edilir
                ]

                if result_lines:  # Eğer anlamlı sonuç varsa
                    output_file = os.path.join(results_folder, f"{sanitized_domain}.txt")
                    with open(output_file, "w") as outfile:
                        outfile.write("\n".join(result_lines))
                    output_widget.insert(tk.END, f"[+] Results saved to {output_file}\n", "light_green")
                else:  # Eğer sonuç yoksa
                    output_widget.insert(tk.END, f"[!] No valid results found for {sanitized_domain}. Skipping.\n", "red")

            except subprocess.CalledProcessError as e:
                output_widget.insert(tk.END, f"Error running ParamSpider on {sanitized_domain}: {e}\n", "red")

            output_widget.yview(tk.END)

        output_widget.insert(tk.END, "All ParamSpider scans completed successfully.\n", "light_green")

    except Exception as e:
        output_widget.insert(tk.END, f"An error occurred during ParamSpider execution: {e}\n", "red")
        messagebox.showerror("Error", str(e))



def start_full_scan(domain, output_widget):
    """
    Starts the full scanning process.
    """
    def run_all():
        fetch_subdomains(domain, output_widget)  # Subdomain taraması
        run_paramspider(output_widget)  # ParamSpider taraması
        process_subdomains_for_scan(output_widget)  # Directory taraması
        xss.run_xss_scan(domain, output_widget)  # XSS tarama
        move_scan_results_to_reports(output_widget)  # Sonuçları taşıma

    threading.Thread(target=run_all).start()


def move_scan_results_to_reports(output_widget):
    """
    Ensures the 'results' folder exists and moves the specified files into it.
    """
    try:
        reports_folder = "results"
        os.makedirs(reports_folder, exist_ok=True)

        files_to_move = ["subdomains.txt", "xss_kxss.txt", "xss_qsreplace.txt", "nuclei.txt"]

        for file_name in os.listdir():
            if file_name.endswith(".txt") and file_name not in files_to_move:
                files_to_move.append(file_name)

        for file_name in files_to_move:
            if os.path.exists(file_name):
                destination = os.path.join(reports_folder, file_name)
                os.rename(file_name, destination)
                output_widget.insert(tk.END, f"Moved {file_name} to {reports_folder}/\n", "light_green")
            else:
                output_widget.insert(tk.END, f"File not found: {file_name}\n", "red")

        output_widget.yview(tk.END)

    except Exception as e:
        output_widget.insert(tk.END, f"Error moving files: {e}\n", "red")
        output_widget.yview(tk.END)


def main():
    """
    Sets up the main GUI for the Bug Hunter Scanner.
    """
    root = tk.Tk()
    root.title("Bug Hunter GUI")
    root.geometry("1000x750")
    root.configure(bg="#1E1E2E")

    header_frame = tk.Frame(root, bg="#1E1E2E")
    header_frame.pack(pady=(20, 10))

    try:
        logo_image = Image.open("13.png")
        logo_image = logo_image.resize((80, 80), Image.LANCZOS)
        logo_photo = ImageTk.PhotoImage(logo_image)
        logo_label = tk.Label(header_frame, image=logo_photo, bg="#1E1E2E")
        logo_label.image = logo_photo
        logo_label.pack(side=tk.LEFT, padx=(0, 20))
    except Exception:
        pass

    banner_label = tk.Label(
        header_frame, text="Bug Hunter - Full Scanner",
        font=("Helvetica", 26, "bold"), bg="#1E1E2E", fg="#A6E3A1"
    )
    banner_label.pack(side=tk.LEFT)

    domain_frame = tk.Frame(root, bg="#1E1E2E")
    domain_frame.pack(pady=(30, 10))

    domain_label = tk.Label(
        domain_frame, text="Enter Domain:", font=("Helvetica", 16, "bold"),
        bg="#1E1E2E", fg="#C9CBFF"
    )
    domain_label.grid(row=0, column=0, padx=5)

    domain_entry = tk.Entry(
        domain_frame, width=40, bg="#2B2B35", fg="#FFFFFF", font=("Helvetica", 14),
        insertbackground="white", relief="flat", bd=5
    )
    domain_entry.grid(row=0, column=1, padx=10, pady=5)
    domain_entry.config(highlightbackground="#1E1E2E", highlightthickness=1)

    output_text = scrolledtext.ScrolledText(
        root,
        wrap=tk.WORD,
        width=90,
        height=20,
        bg="#2B2B35",
        fg="#00FF00",
        insertbackground="white",
        font=("Courier", 14),
        relief="flat",
        bd=5
    )
    output_text.pack(pady=20, padx=20)

    output_text.tag_configure("terminal_red", foreground="#00FF00")
    output_text.tag_configure("default", foreground="#FFFFFF")
    output_text.tag_configure("light_green", foreground="#00FF00")
    output_text.tag_configure("red", foreground="#FF0000")

    fetch_button = tk.Button(
        root,
        text="Start Full Scan",
        command=lambda: start_full_scan(domain_entry.get(), output_text),
        font=("Helvetica", 14, "bold"),
        bg="#FFA500",
        fg="#FFFFFF",
        relief="flat",
        width=20,
        height=2
    )
    fetch_button.pack(pady=(0, 30))

    footer_label = tk.Label(
        root,
        text="Coded By Tmrswrr",
        font=("Kristen ITC", 12, "italic"),
        bg="#1E1E2E",
        fg="#C9CBFF"
    )
    footer_label.place(relx=0.85, rely=0.95, anchor="center")

    root.mainloop()


if __name__ == "__main__":
    main()

