import json
import os
import queue
import re
import shlex
import signal
import subprocess
import tempfile
import threading
import time
import tkinter as tk
from dataclasses import dataclass
from datetime import datetime
from tkinter import filedialog, messagebox, scrolledtext
from urllib.parse import urlparse

from PIL import Image, ImageTk

import xss
from nuclei import run_nuclei_scan

_ANSI_RE = re.compile(r'(?:\x1B[@-_]|[\x80-\x9F][@-_])[0-?]*[ -/]*[@-~]')
_MULTI_NL = re.compile(r'\n+')
_DOMAIN_RE = re.compile(r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$')
_URL_RE = re.compile(r'^https?://', re.IGNORECASE)
_HOST_RE = re.compile(
    r'^[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?'
    r'(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*'
    r'\.[a-zA-Z]{2,}$'
)
_NOISE_RE = re.compile(
    r'^(?:url\d+|em\d+|e\.em\d+|click\d*|track\d*|bounce\d*|pm-bounces|mail\d+|smtp\d+|mta\d+|link\d+|img\d+|rs\d+)\.',
    re.IGNORECASE,
)
_ALLOWED_HTTP_CODES = {200, 204, 301, 302, 307, 308, 401, 403}
_FINDINGS_CODES = {200, 204, 401, 403}
_REDIRECT_CODES = {301, 302, 307, 308}

_GOBIN = os.path.join(os.path.expanduser('~'), 'go', 'bin')
if _GOBIN not in os.environ.get('PATH', ''):
    os.environ['PATH'] = _GOBIN + os.pathsep + os.environ.get('PATH', '')

_HTTPX = os.path.join(_GOBIN, 'httpx')
if not os.path.exists(_HTTPX):
    _HTTPX = 'httpx'

_output_queue = queue.Queue()


@dataclass(frozen=True)
class HostProbeResult:
    host: str
    url: str
    codes: tuple
    title: str = ''

    @property
    def primary_code(self):
        return self.codes[0] if self.codes else None

    @property
    def is_live(self):
        return any(code in _ALLOWED_HTTP_CODES for code in self.codes)


def _drain_queue(output_widget, root):
    try:
        while True:
            text, tag = _output_queue.get_nowait()
            output_widget.insert(tk.END, text, tag)
            output_widget.yview(tk.END)
    except queue.Empty:
        pass
    root.after(100, _drain_queue, output_widget, root)


def _log(text, tag='default'):
    _output_queue.put((text + '\n', tag))


def sanitize_filename(name):
    return re.sub(r'[^\w\-.]', '_', name)


def clean_output(text):
    return _MULTI_NL.sub('\n', _ANSI_RE.sub('', text)).strip()


def validate_domain(domain):
    return bool(_DOMAIN_RE.match((domain or '').strip()))


def ensure_results_dirs():
    paths = [
        'results',
        os.path.join('results', 'directory'),
        os.path.join('results', 'paramspider'),
        os.path.join('results', 'xss'),
        os.path.join('results', 'nuclei'),
        os.path.join('results', 'meta'),
    ]
    for path in paths:
        os.makedirs(path, exist_ok=True)


def read_lines(path):
    if not os.path.exists(path):
        return []
    with open(path, encoding='utf-8', errors='ignore') as handle:
        return [line.strip() for line in handle if line.strip()]


def write_lines(path, lines):
    with open(path, 'w', encoding='utf-8') as handle:
        for line in lines:
            handle.write(str(line).rstrip() + '\n')


def _is_subdomain(host, domain):
    host = host.strip().lower().rstrip('.')
    domain = domain.strip().lower().rstrip('.')
    return host == domain or host.endswith('.' + domain)


def _is_noise(host):
    return bool(_NOISE_RE.match(host))


def _extract_host(value):
    value = (value or '').strip().lower().rstrip('.')
    if not value:
        return ''
    if _URL_RE.match(value):
        try:
            return (urlparse(value).hostname or '').lower().rstrip('.')
        except Exception:
            pass
        value = re.sub(r'^https?://', '', value, flags=re.IGNORECASE)
    return value.split('/')[0].split(':')[0].strip().lower().rstrip('.')


def _kill_process(process):
    try:
        os.killpg(os.getpgid(process.pid), signal.SIGTERM)
    except (ProcessLookupError, PermissionError):
        try:
            process.terminate()
        except Exception:
            pass


def run_command(command, stop_event=None, show_cmd=True, command_tag='terminal_red', output_tag='default', cwd=None, timeout=None):
    if show_cmd:
        _log(f'Running Command: {command}', command_tag)
    try:
        process = subprocess.Popen(
            command,
            shell=True,
            text=True,
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            preexec_fn=os.setsid,
        )
        output = []
        start = time.time()
        for line in iter(process.stdout.readline, ''):
            if stop_event and stop_event.is_set():
                _kill_process(process)
                break
            if timeout and (time.time() - start) > timeout:
                _kill_process(process)
                _log(f'[-] Command timeout after {timeout}s: {command}', 'red')
                break
            if not line:
                break
            clean_line = clean_output(line)
            if clean_line:
                output.append(clean_line)
                _log(clean_line, output_tag)
        process.wait()
        return output
    except Exception as exc:
        _log(f'[-] Command error: {exc}', 'red')
        return []


def detect_tool(binary):
    if os.path.isabs(binary) and os.path.exists(binary):
        return binary
    path = shutil_which(binary)
    return path or binary


def shutil_which(binary):
    for part in os.environ.get('PATH', '').split(os.pathsep):
        candidate = os.path.join(part, binary)
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None


def tool_exists(binary):
    resolved = detect_tool(binary)
    return bool(os.path.isabs(resolved) and os.path.exists(resolved) or shutil_which(binary))


def write_runtime_metadata(domain):
    ensure_results_dirs()
    metadata = {
        'target': domain,
        'timestamp_utc': datetime.utcnow().isoformat() + 'Z',
        'httpx_path': _HTTPX,
        'available_tools': {
            'subfinder': tool_exists('subfinder'),
            'findomain': tool_exists('findomain'),
            'amass': tool_exists('amass'),
            'httpx': tool_exists('httpx') or os.path.exists(_HTTPX),
            'ffuf': tool_exists('ffuf'),
            'paramspider': tool_exists('paramspider'),
            'waybackurls': tool_exists('waybackurls'),
            'kxss': tool_exists('kxss'),
            'qsreplace': tool_exists('qsreplace'),
            'nuclei': tool_exists('nuclei'),
        },
    }
    meta_path = os.path.join('results', 'meta', 'runtime.json')
    with open(meta_path, 'w', encoding='utf-8') as handle:
        json.dump(metadata, handle, indent=2)
    return meta_path


def fetch_subdomains(domain, stop_event=None):
    ensure_results_dirs()
    domain = domain.strip().lower().rstrip('.')
    safe = shlex.quote(domain)
    esc = re.escape(domain)

    meta_path = write_runtime_metadata(domain)
    _log(f'[*] Runtime metadata saved → {meta_path}', 'default')

    sources = [
        ('subfinder', f'timeout 25 subfinder -d {safe} -silent 2>/dev/null'),
        ('findomain', f'timeout 25 findomain -t {safe} -q 2>/dev/null'),
        ('crt.sh', f"curl -s --max-time 15 'https://crt.sh/?q=%25.{domain}&output=json' | jq -r '.[].name_value' 2>/dev/null | sed 's/\\*\\.//g' | sort -u"),
        ('certspotter', f"curl -s --max-time 15 'https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names' | jq -r '.[] | .dns_names[]' 2>/dev/null | grep -Po '([a-zA-Z0-9.-]+\\.{esc})' | sort -u"),
        ('hackertarget', f"curl -s --max-time 15 'https://api.hackertarget.com/hostsearch/?q={domain}' | awk -F',' '{{print $1}}'"),
        ('otx', f"curl -s --max-time 15 'https://otx.alienvault.com/api/v1/indicators/domain/{domain}/url_list?limit=250&page=1' | jq -r '.url_list[].hostname' 2>/dev/null | sort -u"),
        ('subdomain.center', f"curl -s --max-time 15 'https://api.subdomain.center/?domain={domain}' | jq -r '.[]' 2>/dev/null | sort -u"),
        ('rapiddns', f"curl -s --max-time 15 'https://rapiddns.io/subdomain/{domain}?full=1' | grep -oP '(?<=<td>)[^<]+' | grep -E '\\.{esc}$' | sort -u"),
        ('amass', f'timeout 45 amass enum -passive -d {safe} 2>/dev/null'),
    ]

    raw_hosts = set()
    lock = threading.Lock()
    total = len(sources)

    def _run_source(idx, name, cmd):
        if stop_event and stop_event.is_set():
            return
        _log(f'[{idx}/{total}] {name}...', 'terminal_red')
        lines = run_command(cmd, stop_event=stop_event, show_cmd=False)
        found = []
        with lock:
            for line in lines:
                host = _extract_host(line)
                if not host:
                    continue
                if _HOST_RE.match(host) and _is_subdomain(host, domain) and not _is_noise(host):
                    if host not in raw_hosts:
                        raw_hosts.add(host)
                        found.append(host)
        if found:
            _log(f'  [{name}] +{len(found)} ({len(raw_hosts)} total)', 'light_green')

    threads = [threading.Thread(target=_run_source, args=(i, name, cmd), daemon=True) for i, (name, cmd) in enumerate(sources, 1)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    all_hosts = sorted(raw_hosts)
    write_lines(os.path.join('results', 'all_subdomains.txt'), all_hosts)
    _log(f'[+] Saved {len(all_hosts)} total discovered subdomains → results/all_subdomains.txt', 'light_green')

    live_path = os.path.join('results', 'live_subdomains.txt')
    final_path = os.path.join('results', 'subdomains.txt')
    probe_json = os.path.join('results', 'meta', 'probe_results.json')
    report_path = os.path.join('results', 'subdomain_report.txt')

    if not all_hosts:
        write_lines(live_path, [])
        write_lines(final_path, [])
        write_lines(report_path, ['No subdomains were collected.'])
        _log('[-] No subdomains collected. Check installed tools and network access.', 'red')
        return

    _log(f'[*] Probing {len(all_hosts)} hosts with httpx...', 'default')

    tmp = tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False)
    try:
        for host in all_hosts:
            tmp.write(host + '\n')
        tmp.close()
        live_lines = run_command(
            f"{_HTTPX} -l {shlex.quote(tmp.name)} -status-code -title -follow-redirects -tech-detect -no-color -silent",
            stop_event=stop_event,
            show_cmd=False,
        )
    finally:
        if os.path.exists(tmp.name):
            os.unlink(tmp.name)

    results = {}
    for line in live_lines:
        line = line.strip()
        if not line:
            continue
        url_match = re.search(r'https?://\S+', line, re.IGNORECASE)
        if not url_match:
            continue
        url = url_match.group(0)
        host = _extract_host(url)
        if not (_HOST_RE.match(host) and _is_subdomain(host, domain) and not _is_noise(host)):
            continue
        codes = tuple(sorted({int(code) for code in re.findall(r'\b(\d{3})\b', line)}))
        if not set(codes).intersection(_ALLOWED_HTTP_CODES):
            continue
        title_match = re.search(r'\[([^\]]{1,200})\]\s*$', line)
        title = title_match.group(1).strip() if title_match else ''
        results[host] = HostProbeResult(host=host, url=url, codes=codes, title=title)

    live_hosts = sorted(results.keys())
    write_lines(live_path, live_hosts)
    write_lines(final_path, live_hosts)

    with open(probe_json, 'w', encoding='utf-8') as handle:
        json.dump(
            [
                {
                    'host': item.host,
                    'url': item.url,
                    'codes': list(item.codes),
                    'title': item.title,
                }
                for item in sorted(results.values(), key=lambda x: x.host)
            ],
            handle,
            indent=2,
        )

    report_lines = [
        f'Target: {domain}',
        f'Discovered hosts: {len(all_hosts)}',
        f'Live hosts: {len(live_hosts)}',
        '',
        'Live host details:',
    ]
    for host in live_hosts:
        item = results[host]
        codes = ','.join(str(code) for code in item.codes)
        title_part = f' | title={item.title}' if item.title else ''
        report_lines.append(f'{host} | codes={codes} | url={item.url}{title_part}')
    write_lines(report_path, report_lines)

    if live_hosts:
        _log(f'[+] {len(live_hosts)} live subdomains saved → {live_path}', 'light_green')
        _log(f'[+] Structured probe data saved → {probe_json}', 'light_green')
    else:
        _log('[-] No live subdomains found for the allowed HTTP codes.', 'red')


def read_subdomains():
    return read_lines(os.path.join('results', 'subdomains.txt'))


def to_url(host):
    if host.startswith(('http://', 'https://')):
        return host
    return f'https://{host}'


def directory_scan_ffuf(host, wordlist='common.txt', stop_event=None):
    ensure_results_dirs()
    try:
        url = to_url(host)
        sanitized = sanitize_filename(_extract_host(host))
        out_dir = os.path.join('results', 'directory')
        tmp_file = os.path.join(out_dir, f'{sanitized}_tmp.json')
        final_file = os.path.join(out_dir, f'{sanitized}.txt')

        if not os.path.exists(wordlist):
            _log(f"[-] Wordlist '{wordlist}' not found.", 'red')
            return

        _log(f'[*] ffuf → {url}', 'default')
        cmd = (
            f"ffuf -w {shlex.quote(wordlist)} -u {shlex.quote(url.rstrip('/'))}/FUZZ "
            f"-mc 200,204,301,302,307,308,401,403 -fc 404 -t 40 -timeout 8 "
            f"-o {shlex.quote(tmp_file)} -of json -s"
        )
        run_command(cmd, stop_event=stop_event, show_cmd=False)

        if not os.path.exists(tmp_file):
            _log(f'[!] No ffuf output for {url}', 'red')
            return

        with open(tmp_file, encoding='utf-8', errors='ignore') as handle:
            data = json.load(handle)
        os.remove(tmp_file)

        results = data.get('results', [])
        if not results:
            _log(f'[!] No interesting paths on {url}', 'default')
            return

        with open(final_file, 'w', encoding='utf-8') as handle:
            handle.write(f'# FFUF Report: {url}\n\n')
            for item in results:
                handle.write(f"Status: {item.get('status')}\n")
                handle.write(f"URL: {item.get('url')}\n")
                handle.write(f"Length: {item.get('length')}\n")
                handle.write(f"Words: {item.get('words')}\n")
                handle.write(f"Lines: {item.get('lines')}\n")
                handle.write(f"Content-Type: {item.get('content-type', '')}\n\n")
        _log(f'[+] {len(results)} directory hits → {final_file}', 'light_green')
    except Exception as exc:
        _log(f'[-] Directory scan error for {host}: {exc}', 'red')


def process_subdomains_for_scan(wordlist='common.txt', stop_event=None):
    subdomains = read_subdomains()
    if not subdomains:
        _log('[-] No subdomains in results/subdomains.txt. Run subdomain scan first.', 'red')
        return
    _log(f'[*] Directory scan on {len(subdomains)} subdomains...', 'default')
    for idx, host in enumerate(subdomains, 1):
        if stop_event and stop_event.is_set():
            _log('[-] Scan stopped.', 'red')
            break
        _log(f'--- [{idx}/{len(subdomains)}] ---', 'terminal_red')
        directory_scan_ffuf(host, wordlist, stop_event)


def run_paramspider(stop_event=None):
    ensure_results_dirs()
    subdomains = read_subdomains()
    if not subdomains:
        _log('[-] No subdomains in results/subdomains.txt. Run subdomain scan first.', 'red')
        return

    out_dir = os.path.join('results', 'paramspider')
    total_params = 0

    for idx, host in enumerate(subdomains, 1):
        if stop_event and stop_event.is_set():
            _log('[-] Scan stopped.', 'red')
            break

        domain = _extract_host(host)
        _log(f'[{idx}/{len(subdomains)}] ParamSpider → {domain}', 'default')
        process = subprocess.Popen(
            f'paramspider -d {shlex.quote(domain)}',
            shell=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            preexec_fn=os.setsid,
        )
        try:
            stdout, _ = process.communicate(timeout=150)
        except subprocess.TimeoutExpired:
            _kill_process(process)
            _log(f'[!] ParamSpider timeout for {domain}', 'red')
            continue

        stdout = stdout or ''
        if stdout.strip():
            _log(clean_output(stdout), 'default')

        hits = []
        default_result = os.path.join('results', f'{domain}.txt')
        if os.path.exists(default_result):
            hits = read_lines(default_result)
            try:
                os.remove(default_result)
            except OSError:
                pass
        if not hits:
            hits = [line.strip() for line in stdout.splitlines() if line.strip().startswith(('http://', 'https://')) and '=' in line]

        hits = sorted(set(hits))
        if hits:
            total_params += len(hits)
            out_file = os.path.join(out_dir, f'{sanitize_filename(domain)}.txt')
            write_lines(out_file, hits)
            _log(f'[+] {len(hits)} params → {out_file}', 'light_green')
        else:
            _log(f'[!] No params for {domain}', 'default')

    _log(f'[+] ParamSpider completed. Total params: {total_params}', 'light_green')


def generate_final_report(domain):
    ensure_results_dirs()
    report_path = os.path.join('results', 'FINAL_REPORT.txt')
    sections = [
        'Bug Hunter Final Report',
        '=' * 60,
        f'Target: {domain}',
        f'Generated: {datetime.utcnow().isoformat()}Z',
        '',
    ]

    subs = read_subdomains()
    sections += ['Subdomains', '-' * 60, *subs, ''] if subs else ['Subdomains', '-' * 60, 'No live subdomains found.', '']

    dir_dir = os.path.join('results', 'directory')
    if os.path.isdir(dir_dir):
        sections += ['Directory Findings', '-' * 60]
        files = sorted(f for f in os.listdir(dir_dir) if f.endswith('.txt'))
        if files:
            for name in files:
                sections += [f'## {name}'] + read_lines(os.path.join(dir_dir, name)) + ['']
        else:
            sections += ['No directory findings.', '']

    ps_dir = os.path.join('results', 'paramspider')
    if os.path.isdir(ps_dir):
        sections += ['Parameters', '-' * 60]
        files = sorted(f for f in os.listdir(ps_dir) if f.endswith('.txt'))
        if files:
            for name in files:
                lines = read_lines(os.path.join(ps_dir, name))
                sections.append(f'{name}: {len(lines)} parameters')
                sections.extend(lines[:50])
                if len(lines) > 50:
                    sections.append(f'... and {len(lines) - 50} more')
                sections.append('')
        else:
            sections += ['No parameter results.', '']

    for label, path in [
        ('XSS - KXSS', os.path.join('results', 'xss', 'kxss.txt')),
        ('XSS - QSReplace', os.path.join('results', 'xss', 'qsreplace.txt')),
        ('Nuclei', os.path.join('results', 'nuclei', 'nuclei.txt')),
    ]:
        sections += [label, '-' * 60]
        lines = read_lines(path)
        sections += lines if lines else ['No findings.']
        sections.append('')

    write_lines(report_path, sections)
    _log(f'[+] Final report generated → {report_path}', 'light_green')


def _run_threaded(fn, stop_event, status_var, all_btns, start_btn, stop_btn, label, root, *args):
    stop_event.clear()
    for button in all_btns:
        button.config(state='disabled')
    stop_btn.config(state='normal')
    status_var.set(label)

    def _restore():
        for button in all_btns:
            button.config(state='normal')
        stop_btn.config(state='disabled')
        status_var.set('Ready')

    def _run():
        try:
            fn(*args, stop_event=stop_event)
        except Exception as exc:
            root.after(0, lambda: status_var.set(f'Error: {exc}'))
        finally:
            root.after(0, _restore)

    threading.Thread(target=_run, daemon=True).start()


def start_full_scan(domain, wordlist, stop_event, status_var, all_btns, start_btn, stop_btn, root):
    if not validate_domain(domain):
        messagebox.showerror('Invalid Domain', f"'{domain}' is not a valid domain.\nExample: example.com")
        return

    def run_all(stop_event):
        _log('=' * 60, 'terminal_red')
        _log(f'[>] Full scan started: {domain}', 'light_green')
        _log('=' * 60, 'terminal_red')
        _log('[1/5] Subdomain enumeration', 'light_green')
        fetch_subdomains(domain, stop_event)
        if stop_event.is_set():
            return
        _log('[2/5] Parameter discovery', 'light_green')
        run_paramspider(stop_event)
        if stop_event.is_set():
            return
        _log('[3/5] Content discovery', 'light_green')
        process_subdomains_for_scan(wordlist, stop_event)
        if stop_event.is_set():
            return
        _log('[4/5] XSS workflow', 'light_green')
        xss.run_xss_scan(domain, _log, stop_event)
        if stop_event.is_set():
            return
        _log('[5/5] Nuclei workflow', 'light_green')
        run_nuclei_scan(domain, _log, stop_event)
        if stop_event.is_set():
            return
        generate_final_report(domain)
        _log('[✓] Full scan complete.', 'light_green')

    _run_threaded(run_all, stop_event, status_var, all_btns, start_btn, stop_btn, f'Full scan: {domain}', root)


def start_subdomain_scan(domain, stop_event, status_var, all_btns, start_btn, stop_btn, root):
    if not validate_domain(domain):
        messagebox.showerror('Invalid Domain', f"'{domain}' is not a valid domain.\nExample: example.com")
        return
    _run_threaded(fetch_subdomains, stop_event, status_var, all_btns, start_btn, stop_btn, f'Subdomain scan: {domain}', root, domain)


def start_directory_scan(wordlist, stop_event, status_var, all_btns, start_btn, stop_btn, root):
    _run_threaded(process_subdomains_for_scan, stop_event, status_var, all_btns, start_btn, stop_btn, 'Directory scan...', root, wordlist)


def start_paramspider(stop_event, status_var, all_btns, start_btn, stop_btn, root):
    _run_threaded(run_paramspider, stop_event, status_var, all_btns, start_btn, stop_btn, 'ParamSpider...', root)


def start_xss_scan(domain, stop_event, status_var, all_btns, start_btn, stop_btn, root):
    if not validate_domain(domain):
        messagebox.showerror('Invalid Domain', f"'{domain}' is not a valid domain.\nExample: example.com")
        return

    def _xss(stop_event):
        xss.run_xss_scan(domain, _log, stop_event)

    _run_threaded(_xss, stop_event, status_var, all_btns, start_btn, stop_btn, f'XSS scan: {domain}', root)


def start_nuclei_scan(domain, stop_event, status_var, all_btns, start_btn, stop_btn, root):
    if not validate_domain(domain):
        messagebox.showerror('Invalid Domain', f"'{domain}' is not a valid domain.\nExample: example.com")
        return

    def _nuclei(stop_event):
        run_nuclei_scan(domain, _log, stop_event)

    _run_threaded(_nuclei, stop_event, status_var, all_btns, start_btn, stop_btn, f'Nuclei scan: {domain}', root)


def main():
    root = tk.Tk()
    root.title('Bug Hunter GUI')
    root.geometry('1000x1000')
    root.configure(bg='#1E1E2E')
    root.minsize(800, 700)

    stop_event = threading.Event()
    wordlist_var = tk.StringVar(value='common.txt')
    status_var = tk.StringVar(value='Ready')

    header_frame = tk.Frame(root, bg='#1E1E2E')
    header_frame.pack(pady=(20, 10))

    try:
        logo_image = Image.open('13.png')
        logo_image = logo_image.resize((80, 80), Image.LANCZOS)
        logo_photo = ImageTk.PhotoImage(logo_image)
        logo_label = tk.Label(header_frame, image=logo_photo, bg='#1E1E2E')
        logo_label.image = logo_photo
        logo_label.pack(side=tk.LEFT, padx=(0, 20))
    except Exception:
        pass

    tk.Label(
        header_frame,
        text='Bug Hunter - Full Scanner',
        font=('Helvetica', 26, 'bold'),
        bg='#1E1E2E',
        fg='#A6E3A1',
    ).pack(side=tk.LEFT)

    domain_frame = tk.Frame(root, bg='#1E1E2E')
    domain_frame.pack(pady=(20, 5))

    tk.Label(
        domain_frame,
        text='Enter Domain:',
        font=('Helvetica', 16, 'bold'),
        bg='#1E1E2E',
        fg='#C9CBFF',
    ).grid(row=0, column=0, padx=5)

    domain_entry = tk.Entry(
        domain_frame,
        width=40,
        bg='#2B2B35',
        fg='#FFFFFF',
        font=('Helvetica', 14),
        insertbackground='white',
        relief='flat',
        bd=5,
    )
    domain_entry.grid(row=0, column=1, padx=10, pady=5)
    domain_entry.config(highlightbackground='#1E1E2E', highlightthickness=1)

    wl_frame = tk.Frame(root, bg='#1E1E2E')
    wl_frame.pack(pady=(0, 5))

    tk.Label(
        wl_frame,
        text='Wordlist:',
        font=('Helvetica', 12),
        bg='#1E1E2E',
        fg='#C9CBFF',
    ).grid(row=0, column=0, padx=5)

    tk.Entry(
        wl_frame,
        textvariable=wordlist_var,
        width=36,
        bg='#2B2B35',
        fg='#FFFFFF',
        font=('Helvetica', 12),
        insertbackground='white',
        relief='flat',
        bd=4,
    ).grid(row=0, column=1, padx=5)

    tk.Button(
        wl_frame,
        text='Browse',
        command=lambda: wordlist_var.set(
            filedialog.askopenfilename(
                title='Select Wordlist',
                filetypes=[('Text files', '*.txt'), ('All files', '*.*')],
            ) or wordlist_var.get()
        ),
        font=('Helvetica', 11),
        bg='#2B2B35',
        fg='#C9CBFF',
        relief='flat',
        cursor='hand2',
        padx=8,
    ).grid(row=0, column=2, padx=5)

    output_text = scrolledtext.ScrolledText(
        root,
        wrap=tk.WORD,
        width=90,
        height=20,
        bg='#2B2B35',
        fg='#00FF00',
        insertbackground='white',
        font=('Courier', 14),
        relief='flat',
        bd=5,
    )
    output_text.pack(pady=15, padx=20)
    output_text.tag_configure('terminal_red', foreground='#00FF00')
    output_text.tag_configure('default', foreground='#FFFFFF')
    output_text.tag_configure('light_green', foreground='#00FF00')
    output_text.tag_configure('red', foreground='#FF0000')

    root.after(100, _drain_queue, output_text, root)

    main_btn_frame = tk.Frame(root, bg='#1E1E2E')
    main_btn_frame.pack(pady=(0, 8))

    start_btn = tk.Button(
        main_btn_frame,
        text='Start Full Scan',
        font=('Helvetica', 14, 'bold'),
        bg='#FFA500',
        fg='#FFFFFF',
        relief='flat',
        width=20,
        height=2,
        cursor='hand2',
    )
    start_btn.grid(row=0, column=0, padx=8)

    stop_btn = tk.Button(
        main_btn_frame,
        text='Stop Scan',
        command=lambda: stop_event.set(),
        font=('Helvetica', 14, 'bold'),
        bg='#FF4444',
        fg='#FFFFFF',
        relief='flat',
        width=14,
        height=2,
        state='disabled',
        cursor='hand2',
    )
    stop_btn.grid(row=0, column=1, padx=8)

    scan_btn_frame = tk.Frame(root, bg='#1E1E2E')
    scan_btn_frame.pack(pady=(0, 8))

    small = dict(font=('Helvetica', 11, 'bold'), fg='#FFFFFF', relief='flat', width=13, height=1, cursor='hand2')
    btn_sub = tk.Button(scan_btn_frame, text='Subdomains', bg='#4A90D9', **small)
    btn_dir = tk.Button(scan_btn_frame, text='Directory', bg='#7E57C2', **small)
    btn_para = tk.Button(scan_btn_frame, text='ParamSpider', bg='#26A69A', **small)
    btn_xss = tk.Button(scan_btn_frame, text='XSS', bg='#EF5350', **small)
    btn_nuc = tk.Button(scan_btn_frame, text='Nuclei', bg='#8D6E63', **small)

    for col, button in enumerate([btn_sub, btn_dir, btn_para, btn_xss, btn_nuc]):
        button.grid(row=0, column=col, padx=5)

    all_btns = [start_btn, btn_sub, btn_dir, btn_para, btn_xss, btn_nuc]

    def _d():
        return domain_entry.get().strip()

    def _wl():
        return wordlist_var.get()

    def _args(**kw):
        return dict(stop_event=stop_event, status_var=status_var, all_btns=all_btns, start_btn=start_btn, stop_btn=stop_btn, root=root, **kw)

    start_btn.config(command=lambda: start_full_scan(_d(), _wl(), **_args()))
    btn_sub.config(command=lambda: start_subdomain_scan(_d(), **_args()))
    btn_dir.config(command=lambda: start_directory_scan(_wl(), **_args()))
    btn_para.config(command=lambda: start_paramspider(**_args()))
    btn_xss.config(command=lambda: start_xss_scan(_d(), **_args()))
    btn_nuc.config(command=lambda: start_nuclei_scan(_d(), **_args()))

    util_frame = tk.Frame(root, bg='#1E1E2E')
    util_frame.pack(pady=(0, 8))

    tk.Button(
        util_frame,
        text='Clear Output',
        command=lambda: output_text.delete('1.0', tk.END),
        font=('Helvetica', 11),
        bg='#2B2B35',
        fg='#C9CBFF',
        relief='flat',
        width=14,
        cursor='hand2',
    ).grid(row=0, column=0, padx=8)

    tk.Button(
        util_frame,
        text='Open Results',
        command=lambda: (ensure_results_dirs(), subprocess.Popen(['xdg-open', 'results'])),
        font=('Helvetica', 11),
        bg='#2B2B35',
        fg='#C9CBFF',
        relief='flat',
        width=14,
        cursor='hand2',
    ).grid(row=0, column=1, padx=8)

    tk.Label(
        root,
        textvariable=status_var,
        font=('Helvetica', 11),
        bg='#2B2B35',
        fg='#A6E3A1',
        anchor='w',
        padx=10,
        pady=4,
    ).pack(fill=tk.X, padx=20, pady=(0, 5))

    tk.Label(
        root,
        text='Coded By Tmrswrr',
        font=('Kristen ITC', 12, 'italic'),
        bg='#1E1E2E',
        fg='#C9CBFF',
    ).place(relx=0.85, rely=0.97, anchor='center')

    root.mainloop()


if __name__ == '__main__':
    main()
