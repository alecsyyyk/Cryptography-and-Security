"""Laboratorul 5: infrastructura cu chei publice (PKI) si semnatura digitala.

Programul foloseste utilitarul OpenSSL pentru a crea o autoritate de certificare
(CA) interna, a emite si a revoca certificatele utilizatorilor, a semna fisiere
si a verifica semnaturile.
"""

import getpass
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path


OPENSSL = os.environ.get("OPENSSL", "openssl")
PKI_DIR = Path(__file__).resolve().parent / "pki"

CA_KEY_BITS = 4096
CA_DAYS = 3650
USER_KEY_BITS = (2048, 3072, 4096)
USER_DAYS = 365
CRL_DAYS = 30
DIGEST = "sha256"
CA_SUBJECT = "/C=MD/L=Chisinau/O=UTM/OU=FCIM FAF-241/CN=FAF-241 Root CA"
USER_SUBJECT = "/C=MD/L=Chisinau/O=UTM/OU=FCIM FAF-241/CN={name}"
FIRST_SERIAL = "1000"
NAME_PATTERN = re.compile(r"^[A-Za-z0-9_-]{2,32}$")

# Fisierele CA, relative la folderul pki/ (OpenSSL ruleaza din acest folder).
CONFIG = "openssl.cnf"
CA_KEY = "private/ca.key"
CA_CERT = "certs/ca.crt"
CA_CRL = "crl/ca.crl"
INDEX = "index.txt"

# Motivele de revocare acceptate de "openssl ca -crl_reason" (RFC 5280).
REVOKE_REASONS = (
    ("keyCompromise", "cheia privata a fost compromisa"),
    ("affiliationChanged", "utilizatorul a parasit organizatia"),
    ("superseded", "certificatul a fost inlocuit"),
    ("cessationOfOperation", "certificatul nu mai este necesar"),
)

OPENSSL_CONFIG = f"""\
# Configuratia CA interne (generata de pki.py).
[ ca ]
default_ca = CA_default

[ CA_default ]
dir              = .
certs            = $dir/certs
crl_dir          = $dir/crl
new_certs_dir    = $dir/newcerts
database         = $dir/{INDEX}
serial           = $dir/serial
crlnumber        = $dir/crlnumber
private_key      = $dir/{CA_KEY}
certificate      = $dir/{CA_CERT}
crl              = $dir/{CA_CRL}
crl_extensions   = crl_ext
default_md       = {DIGEST}
default_days     = {USER_DAYS}
default_crl_days = {CRL_DAYS}
policy           = policy_user
unique_subject   = no
copy_extensions  = none
preserve         = no

[ policy_user ]
countryName            = optional
stateOrProvinceName    = optional
localityName           = optional
organizationName       = optional
organizationalUnitName = optional
commonName             = supplied
emailAddress           = optional

[ req ]
distinguished_name = req_distinguished_name
string_mask        = utf8only
default_md         = {DIGEST}

[ req_distinguished_name ]

[ v3_ca ]
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints       = critical, CA:true
keyUsage               = critical, keyCertSign, cRLSign, digitalSignature

[ usr_cert ]
basicConstraints       = critical, CA:false
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid,issuer
keyUsage               = critical, digitalSignature, nonRepudiation

[ crl_ext ]
authorityKeyIdentifier = keyid:always
"""


class PkiError(Exception):
    """An OpenSSL command failed or the PKI is in the wrong state."""


def run_openssl(*args, password=None, quiet=False, check=True):
    """Run an OpenSSL command inside PKI_DIR.

    The CA password is passed through the CA_PASS environment variable
    ("-passin env:CA_PASS"), so it never appears in the command line.
    With check=True the standard output is returned and a failure raises
    PkiError; with check=False the CompletedProcess is returned.
    """
    command = [OPENSSL, *args]
    if not quiet:
        print("  $ openssl " + " ".join(_quote(arg) for arg in args))
    PKI_DIR.mkdir(exist_ok=True)
    environment = dict(os.environ)
    if password is not None:
        environment["CA_PASS"] = password
    result = subprocess.run(
        command, cwd=PKI_DIR, env=environment,
        stdin=subprocess.DEVNULL, capture_output=True, text=True,
    )
    if not check:
        return result
    if result.returncode != 0:
        message = (result.stderr or result.stdout).strip()
        if "bad decrypt" in message or "maybe wrong password" in message:
            raise PkiError("Parola cheii CA este gresita.")
        raise PkiError(message or f"openssl a terminat cu codul {result.returncode}")
    return result.stdout


def _quote(argument):
    return f'"{argument}"' if " " in argument else argument


def _arg_path(path):
    """Path of a user file as seen from PKI_DIR (relative when possible)."""
    try:
        return os.path.relpath(path, PKI_DIR)
    except ValueError:  # Windows: alt disc decat folderul pki/
        return str(path)


def ca_exists():
    return (PKI_DIR / CA_CERT).exists() and (PKI_DIR / CA_KEY).exists()


def user_paths(name):
    """Return the key, CSR and certificate paths of a user (relative to PKI_DIR)."""
    folder = f"users/{name}"
    return f"{folder}/{name}.key", f"{folder}/{name}.csr", f"{folder}/{name}.crt"


def validate_name(raw):
    """Return (name, error_message) for a user name."""
    name = raw.strip()
    if not NAME_PATTERN.match(name):
        return None, ("Numele trebuie sa aiba 2-32 de caractere: litere latine, "
                      "cifre, '_' sau '-'.")
    return name, None


def init_ca(password):
    """Create the folder structure, the 4096-bit root key and the self-signed CA."""
    if PKI_DIR.exists():
        shutil.rmtree(PKI_DIR)
    for folder in ("certs", "crl", "newcerts", "private", "users"):
        (PKI_DIR / folder).mkdir(parents=True)
    (PKI_DIR / CONFIG).write_text(OPENSSL_CONFIG, encoding="utf-8")
    (PKI_DIR / INDEX).write_text("", encoding="utf-8")
    (PKI_DIR / "serial").write_text(FIRST_SERIAL + "\n", encoding="utf-8")
    (PKI_DIR / "crlnumber").write_text(FIRST_SERIAL + "\n", encoding="utf-8")

    print(f"\n[1/3] Cheia privata root (RSA {CA_KEY_BITS} biti, criptata AES-256):")
    run_openssl("genpkey", "-algorithm", "RSA",
                "-pkeyopt", f"rsa_keygen_bits:{CA_KEY_BITS}",
                "-aes-256-cbc", "-pass", "env:CA_PASS",
                "-out", CA_KEY, password=password)
    _restrict(PKI_DIR / CA_KEY)

    print(f"\n[2/3] Certificatul autosemnat al CA ({CA_DAYS} de zile):")
    run_openssl("req", "-config", CONFIG, "-new", "-x509",
                "-key", CA_KEY, "-passin", "env:CA_PASS",
                "-days", str(CA_DAYS), f"-{DIGEST}",
                "-extensions", "v3_ca", "-subj", CA_SUBJECT,
                "-out", CA_CERT, password=password)

    print("\n[3/3] Lista certificatelor revocate (CRL), deocamdata goala:")
    generate_crl(password)


def check_ca_password(password):
    """Decrypt the CA key once, so a wrong password stops before any change."""
    run_openssl("pkey", "-in", CA_KEY, "-passin", "env:CA_PASS", "-noout",
                password=password, quiet=True)


def generate_crl(password):
    run_openssl("ca", "-config", CONFIG, "-gencrl",
                "-passin", "env:CA_PASS", "-out", CA_CRL, password=password)


def certificate_status(certificate):
    """Check a certificate against the CA and the CRL.

    Returns (is_valid, openssl_message).
    """
    try:
        output = run_openssl("verify", "-CAfile", CA_CERT,
                             "-CRLfile", CA_CRL, "-crl_check",
                             str(certificate), quiet=True)
        return True, output.strip()
    except PkiError as error:
        return False, str(error)


def ensure_no_valid_certificate(name):
    """Refuse a new certificate while the user still holds a valid one."""
    certificate = user_paths(name)[2]
    if (PKI_DIR / certificate).exists() and certificate_status(certificate)[0]:
        raise PkiError(f"Utilizatorul {name} are deja un certificat valid. "
                       "Revocati-l inainte de a emite unul nou.")


def issue_user(name, bits, password):
    """Generate the user's RSA key and a CA-signed certificate valid USER_DAYS."""
    key, csr, certificate = user_paths(name)
    ensure_no_valid_certificate(name)
    check_ca_password(password)
    (PKI_DIR / "users" / name).mkdir(parents=True, exist_ok=True)

    print(f"\n[1/3] Cheia privata a utilizatorului (RSA {bits} biti):")
    run_openssl("genpkey", "-algorithm", "RSA",
                "-pkeyopt", f"rsa_keygen_bits:{bits}", "-out", key)
    _restrict(PKI_DIR / key)

    print("\n[2/3] Cererea de certificat (CSR):")
    run_openssl("req", "-config", CONFIG, "-new", "-key", key,
                "-subj", USER_SUBJECT.format(name=name), "-out", csr)

    print(f"\n[3/3] CA semneaza cererea ({USER_DAYS} de zile):")
    run_openssl("ca", "-config", CONFIG, "-batch", "-notext",
                "-extensions", "usr_cert", "-days", str(USER_DAYS),
                "-passin", "env:CA_PASS", "-in", csr, "-out", certificate,
                password=password)
    return certificate


def revoke_user(name, reason, password):
    """Revoke the user's certificate and publish a new CRL."""
    _, _, certificate = user_paths(name)
    if not (PKI_DIR / certificate).exists():
        raise PkiError(f"Utilizatorul {name} nu are certificat.")
    check_ca_password(password)
    print("\n[1/2] Revocarea certificatului in baza de date a CA:")
    run_openssl("ca", "-config", CONFIG, "-revoke", certificate,
                "-crl_reason", reason, "-passin", "env:CA_PASS",
                password=password)
    print("\n[2/2] Publicarea noii liste CRL:")
    generate_crl(password)


def sign_file(name, path):
    """Sign a file with the user's private key (RSA + SHA-256).

    The signature is written next to the file as <file>.<name>.sig.
    """
    key, _, certificate = user_paths(name)
    if not (PKI_DIR / key).exists():
        raise PkiError(f"Utilizatorul {name} nu are cheie privata.")
    valid, message = certificate_status(certificate)
    if not valid:
        raise PkiError(f"Certificatul lui {name} nu este valid, semnarea este "
                       f"interzisa.\n{message}")
    signature = path.with_name(f"{path.name}.{name}.sig")
    run_openssl("dgst", f"-{DIGEST}", "-sign", key,
                "-out", _arg_path(signature), _arg_path(path))
    return signature


def verify_signature(name, path, signature):
    """Verify the signer's certificate, then the signature of the file.

    Returns (certificate_ok, certificate_message, signature_ok, signature_message).
    """
    _, _, certificate = user_paths(name)
    if not (PKI_DIR / certificate).exists():
        raise PkiError(f"Utilizatorul {name} nu are certificat.")

    print("\n[1/3] Verificarea certificatului semnatarului (CA + CRL):")
    print(f"  $ openssl verify -CAfile {CA_CERT} -CRLfile {CA_CRL} "
          f"-crl_check {certificate}")
    certificate_ok, certificate_message = certificate_status(certificate)
    print("  " + certificate_message.replace("\n", "\n  "))

    print("\n[2/3] Extragerea cheii publice din certificat:")
    public_key = f"users/{name}/{name}.pub"
    run_openssl("x509", "-in", certificate, "-pubkey", "-noout", "-out", public_key)

    print("\n[3/3] Verificarea semnaturii:")
    result = run_openssl("dgst", f"-{DIGEST}", "-verify", public_key,
                         "-signature", _arg_path(signature), _arg_path(path),
                         check=False)
    signature_ok = result.returncode == 0
    signature_message = (result.stdout.strip() or "Verification failure")
    print("  " + signature_message.splitlines()[0])
    return certificate_ok, certificate_message, signature_ok, signature_message


def list_certificates():
    """Parse the CA database (index.txt) into (status, expires, revoked, serial, subject)."""
    rows = []
    for line in (PKI_DIR / INDEX).read_text(encoding="utf-8").splitlines():
        fields = line.split("\t")
        if len(fields) >= 6:
            status, expires, revoked, serial, _, subject = fields[:6]
            rows.append((status, expires, revoked, serial, subject))
    return rows


def _restrict(path):
    """Make a private key readable only by its owner (where the OS supports it)."""
    try:
        path.chmod(0o600)
    except OSError:
        pass


# ---------------------------------------------------------------- interfata

STATUS_NAMES = {"V": "valid", "R": "revocat", "E": "expirat"}


def _ask_new_password():
    while True:
        password = getpass.getpass("Parola noua pentru cheia CA (min. 4 caractere): ")
        if len(password) < 4:
            print("Parola este prea scurta.")
            continue
        if password != getpass.getpass("Repetati parola: "):
            print("Parolele nu coincid.")
            continue
        return password


def _ask_ca_password():
    return getpass.getpass("Parola cheii CA: ")


def _ask_name(prompt="Numele utilizatorului: "):
    while True:
        name, error = validate_name(input(prompt))
        if error is None:
            return name
        print(error)


def _ask_existing_user():
    users = sorted(folder.name for folder in (PKI_DIR / "users").iterdir()
                   if (PKI_DIR / user_paths(folder.name)[2]).exists())
    if not users:
        raise PkiError("Nu exista utilizatori. Emiteti mai intai un certificat (2).")
    print("Utilizatori:", ", ".join(users))
    while True:
        name = _ask_name()
        if name in users:
            return name
        print(f"Utilizatorul {name} nu exista.")


def _ask_file(prompt):
    while True:
        raw = input(prompt).strip().strip('"').strip("'")
        path = Path(raw).expanduser().resolve()
        if raw and path.is_file():
            return path
        print("Fisierul nu exista.")


def _ask_choice(prompt, options):
    while True:
        choice = input(prompt).strip()
        if choice in options:
            return choice
        print("Optiune invalida.")


def _show_certificate(certificate):
    output = run_openssl("x509", "-in", str(certificate), "-noout",
                         "-subject", "-issuer", "-serial", "-dates",
                         "-ext", "basicConstraints,keyUsage", quiet=True)
    key_info = run_openssl("x509", "-in", str(certificate), "-noout", "-text",
                           quiet=True)
    bits = re.search(r"Public-Key: \((\d+) bit\)", key_info)
    print("  " + output.strip().replace("\n", "\n  "))
    if bits:
        print(f"  Cheia publica: RSA {bits.group(1)} biti")


def _menu_init():
    if ca_exists():
        print("ATENTIE: CA exista deja. Reinitializarea sterge toate cheile, "
              "certificatele si lista CRL.")
        if input("Scrieti 'da' pentru a continua: ").strip().lower() != "da":
            return
    password = _ask_new_password()
    init_ca(password)
    print("\nCA a fost creata. Certificatul autosemnat:")
    _show_certificate(PKI_DIR / CA_CERT)


def _menu_issue():
    name = _ask_name()
    ensure_no_valid_certificate(name)
    print("Dimensiunea cheii: " + ", ".join(
        f"{number}. {bits} biti" for number, bits in enumerate(USER_KEY_BITS, 1)))
    choice = _ask_choice("Alege (1-3): ", {"1", "2", "3"})
    bits = USER_KEY_BITS[int(choice) - 1]
    certificate = issue_user(name, bits, _ask_ca_password())
    print(f"\nCheia privata:  pki/{user_paths(name)[0]}")
    print(f"Certificatul:   pki/{certificate}")
    _show_certificate(PKI_DIR / certificate)


def _menu_revoke():
    name = _ask_existing_user()
    for number, (_, description) in enumerate(REVOKE_REASONS, 1):
        print(f"{number}. {description}")
    choice = _ask_choice(f"Motivul revocarii (1-{len(REVOKE_REASONS)}): ",
                         {str(number) for number in range(1, len(REVOKE_REASONS) + 1)})
    reason = REVOKE_REASONS[int(choice) - 1][0]
    revoke_user(name, reason, _ask_ca_password())
    print(f"\nCertificatul lui {name} a fost revocat ({reason}).")


def _menu_sign():
    name = _ask_existing_user()
    path = _ask_file("Fisierul de semnat: ")
    signature = sign_file(name, path)
    try:
        shown = os.path.relpath(signature)
    except ValueError:
        shown = str(signature)
    print(f"\nSemnatura ({signature.stat().st_size} octeti) a fost salvata in: {shown}")


def _menu_verify():
    name = _ask_existing_user()
    path = _ask_file("Fisierul semnat: ")
    default = path.with_name(f"{path.name}.{name}.sig")
    raw = input(f"Fisierul semnaturii [{default.name}]: ").strip().strip('"')
    signature = Path(raw).expanduser().resolve() if raw else default
    if not signature.is_file():
        raise PkiError(f"Semnatura {signature} nu exista.")
    certificate_ok, _, signature_ok, _ = verify_signature(name, path, signature)
    print()
    if certificate_ok and signature_ok:
        print(f"REZULTAT: semnatura este VALIDA. Fisierul a fost semnat de {name} "
              "si nu a fost modificat.")
    elif not signature_ok:
        print("REZULTAT: semnatura este INVALIDA (fisierul a fost modificat sau "
              "semnatura nu apartine acestui utilizator).")
    else:
        print("REZULTAT: semnatura corespunde fisierului, dar NU este de incredere: "
              f"certificatul lui {name} nu este valid (revocat sau expirat).")


def _menu_list():
    print("\nCertificatul CA:")
    _show_certificate(PKI_DIR / CA_CERT)
    rows = list_certificates()
    print("\nCertificatele emise (baza de date index.txt):")
    if not rows:
        print("  nu exista certificate emise")
    for status, expires, revoked, serial, subject in rows:
        line = (f"  {serial}  {STATUS_NAMES.get(status, status):8} "
                f"expira {_format_date(expires)}  {subject}")
        if revoked:
            date, _, reason = revoked.partition(",")
            line += f"  (revocat {_format_date(date)}, {reason})"
        print(line)
    print("\nLista CRL (crl/ca.crl):")
    output = run_openssl("crl", "-in", CA_CRL, "-noout", "-lastupdate",
                         "-nextupdate", "-crlnumber", quiet=True)
    print("  " + output.strip().replace("\n", "\n  "))
    text = run_openssl("crl", "-in", CA_CRL, "-noout", "-text", quiet=True)
    serials = re.findall(r"Serial Number: (\w+)", text)
    print("  Certificate revocate: " + (", ".join(serials) if serials else "niciunul"))


def _format_date(value):
    """Turn an ASN.1 time such as 271122103000Z into 2027-11-22 10:30."""
    digits = value.rstrip("Z")
    if len(digits) == 12:
        digits = "20" + digits
    if len(digits) != 14:
        return value
    return f"{digits[:4]}-{digits[4:6]}-{digits[6:8]} {digits[8:10]}:{digits[10:12]}"


MENU = (
    ("1", "Initializarea CA (cheia root + certificatul autosemnat)", _menu_init, False),
    ("2", "Emiterea cheii si a certificatului pentru un utilizator", _menu_issue, True),
    ("3", "Revocarea certificatului unui utilizator", _menu_revoke, True),
    ("4", "Semnarea unui fisier", _menu_sign, True),
    ("5", "Verificarea unei semnaturi", _menu_verify, True),
    ("6", "Afisarea certificatelor si a listei CRL", _menu_list, True),
)


def main():
    sys.stdout.reconfigure(encoding="utf-8")
    if shutil.which(OPENSSL) is None:
        print(f"Nu am gasit '{OPENSSL}'. Instalati OpenSSL sau setati variabila "
              "de mediu OPENSSL cu calea spre openssl.exe.")
        return
    print(run_openssl("version", quiet=True).strip())
    actions = {key: (action, needs_ca) for key, _, action, needs_ca in MENU}
    while True:
        print("\n=== PKI interna si semnatura digitala ===")
        for key, title, _, _ in MENU:
            print(f"{key}. {title}")
        print("0. Iesire")
        choice = input(f"Alege (0-{len(MENU)}): ").strip()
        if choice == "0":
            return
        if choice not in actions:
            print(f"Optiune invalida. Alegeti un numar intre 0 si {len(MENU)}.")
            continue
        action, needs_ca = actions[choice]
        if needs_ca and not ca_exists():
            print("CA nu este initializata. Alegeti mai intai optiunea 1.")
            continue
        try:
            action()
        except PkiError as error:
            print(f"\nEROARE: {error}")
        except (KeyboardInterrupt, EOFError):
            print("\nOperatia a fost anulata.")


if __name__ == "__main__":
    main()
