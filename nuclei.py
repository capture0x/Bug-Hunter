import os
import re
from subprocess import Popen, PIPE

def clean_output(text):
    """
    Cleans ANSI escape codes, redundant whitespace, and unnecessary characters from the given text.
    """
    ansi_escape = re.compile(r'(?:\x1B[@-_]|[\x80-\x9F][@-_])[0-?]*[ -/]*[@-~]')
    cleaned_text = ansi_escape.sub('', text)
    return re.sub(r'\n+', '\n', cleaned_text).strip()

def run_nuclei_scan(domain, output_widget, template=None):
    """
    Executes Nuclei on a given domain and optional template, 
    displays output in a widget, and saves results to nuclei.txt.
    """
    output_file = "nuclei.txt"

    try:
        if not os.path.exists("subdomains.txt"):
            output_widget.insert("end", "No subdomains found. Please run subdomain scan first.\n", "red")
            output_widget.yview("end")
            return

        with open("subdomains.txt", "r") as file:
            subdomains = file.readlines()

        with open(output_file, "w") as outfile:
            for subdomain in subdomains:
                subdomain = subdomain.strip()
                if not subdomain:
                    continue

                command = f"nuclei -u {subdomain} -t ."
                if template:
                    command += f" -t {template}"

                output_widget.insert("end", f"Running Nuclei on {subdomain}...\n", "terminal_red")
                output_widget.yview("end")

                process = Popen(command, shell=True, text=True, stdout=PIPE, stderr=PIPE)
                for line in iter(process.stdout.readline, ''):
                    if not line:
                        break
                    clean_line = clean_output(line)
                    output_widget.insert("end", clean_line + "\n", "default")
                    output_widget.yview("end")
                    outfile.write(clean_line + "\n")  # Sonuçları dosyaya yaz

                process.wait()

        output_widget.insert("end", f"Nuclei scan completed. Results saved to {output_file}.\n", "light_green")
        output_widget.yview("end")

    except Exception as e:
        output_widget.insert("end", f"An error occurred during Nuclei scan: {e}\n", "red")
        output_widget.yview("end")

