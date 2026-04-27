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


def _stream(command, log, stop_event=None):
    proc = subprocess.Popen(
        command,
        shell=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        preexec_fn=os.setsid,
    )
    try:
        for line in iter(proc.stdout.readline, ''):
            if stop_event and stop_event.is_set():
                _kill(proc)
                return False
            if not line:
                break
            cleaned = _clean(line)
            if cleaned:
                log(cleaned, 'default')
        proc.wait()
        return proc.returncode == 0
    finally:
        try:
            proc.wait(timeout=1)
        except Exception:
            pass


def run_xss_scan(domain, log, stop_event=None):
    xss_dir = os.path.join('results', 'xss')
    os.makedirs(xss_dir, exist_ok=True)

    target = domain.strip()
    base_url = target if target.startswith(('http://', 'https://')) else f'https://{target}'

    kxss_out = os.path.join(xss_dir, 'kxss.txt')
    qsr_out = os.path.join(xss_dir, 'qsreplace.txt')

    try:
        log('[*] Running KXSS scan...', 'terminal_red')
        kxss_cmd = f"echo {shlex.quote(base_url)} | waybackurls | sort -u | kxss > {shlex.quote(kxss_out)}"
        if not _stream(kxss_cmd, log, stop_event):
            if stop_event and stop_event.is_set():
                log('[-] XSS scan stopped.', 'red')
                return
        log(f'[+] KXSS done → {kxss_out}', 'light_green')

        if stop_event and stop_event.is_set():
            return

        log('[*] Running QSReplace reflection workflow...', 'terminal_red')
        payload = shlex.quote('xsstest987654321')
        qsr_cmd = (
            f"echo {shlex.quote(base_url)} | waybackurls | grep '=' | sort -u | qsreplace {payload} "
            f"| while read url; do body=$(curl -ks --max-time 10 \"$url\"); "
            f"if printf '%s' \"$body\" | grep -q xsstest987654321; then echo \"$url\"; fi; done "
            f"| tee {shlex.quote(qsr_out)}"
        )
        if not _stream(qsr_cmd, log, stop_event):
            if stop_event and stop_event.is_set():
                log('[-] XSS scan stopped.', 'red')
                return
        log(f'[+] Reflection scan done → {qsr_out}', 'light_green')
    except Exception as exc:
        log(f'[-] XSS error: {exc}', 'red')
