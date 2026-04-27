import os
import re
import shlex
import signal
import subprocess

_ANSI_RE = re.compile(r'(?:\x1B[@-_]|[\x80-\x9F][@-_])[0-?]*[ -/]*[@-~]')
_MULTI_NL = re.compile(r'\n+')


def _clean(text):
    return _MULTI_NL.sub('\n', _ANSI_RE.sub('', text)).strip()


def _kill(process):
    try:
        os.killpg(os.getpgid(process.pid), signal.SIGTERM)
    except Exception:
        try:
            process.terminate()
        except Exception:
            pass


def run_nuclei_scan(domain, log, stop_event=None, template=None):
    out_dir = os.path.join('results', 'nuclei')
    os.makedirs(out_dir, exist_ok=True)
    out_file = os.path.join(out_dir, 'nuclei.txt')
    templates = template or 'nuclei-templates/'

    try:
        subs_path = os.path.join('results', 'subdomains.txt')
        if not os.path.exists(subs_path):
            log('[-] results/subdomains.txt not found. Run subdomain scan first.', 'red')
            return

        with open(subs_path, encoding='utf-8', errors='ignore') as handle:
            subdomains = [line.strip() for line in handle if line.strip()]

        if not subdomains:
            log('[!] subdomains.txt is empty.', 'red')
            return

        if not os.path.exists(templates):
            log(f'[-] Nuclei templates not found: {templates}', 'red')
            log('[*] git clone https://github.com/projectdiscovery/nuclei-templates.git', 'default')
            return

        url_list = os.path.join(out_dir, '.urls.txt')
        with open(url_list, 'w', encoding='utf-8') as handle:
            for host in subdomains:
                handle.write(host if host.startswith(('http://', 'https://')) else 'https://' + host)
                handle.write('\n')

        log(f'[*] Nuclei scan on {len(subdomains)} subdomains (this can take a while)...', 'default')
        cmd = (
            f"nuclei -l {shlex.quote(url_list)} "
            f"-t {shlex.quote(templates)} "
            f"-severity low,medium,high,critical "
            f"-rate-limit 150 -timeout 8 -retries 1 -silent -nc"
        )

        proc = subprocess.Popen(
            cmd,
            shell=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            preexec_fn=os.setsid,
        )

        findings = 0
        with open(out_file, 'w', encoding='utf-8') as outf:
            outf.write(f'# Nuclei scan: {domain}\n')
            outf.write(f'# Total targets: {len(subdomains)}\n\n')
            try:
                while True:
                    if stop_event and stop_event.is_set():
                        _kill(proc)
                        log('[-] Nuclei scan stopped.', 'red')
                        return
                    line = proc.stdout.readline()
                    if not line and proc.poll() is not None:
                        break
                    if line:
                        cleaned = _clean(line)
                        if cleaned:
                            outf.write(cleaned + '\n')
                            log(cleaned, 'default')
                            findings += 1
            finally:
                proc.wait()

        try:
            os.remove(url_list)
        except OSError:
            pass

        if findings:
            log(f'[+] Nuclei complete: {findings} findings → {out_file}', 'light_green')
        else:
            log('[!] Nuclei found nothing (templates may need updating).', 'default')
    except Exception as exc:
        log(f'[-] Nuclei error: {exc}', 'red')
