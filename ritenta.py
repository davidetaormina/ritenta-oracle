"""Ritentatore Oracle: crea i server gratuiti Ampere (A1) appena Oracle libera un posto.

Prova a creare i server indicati in ritentatore.ini ogni ~2 minuti, giorno e notte.
Quando ci riesce avvisa (suono + finestra) e salva l'indirizzo IP in IP-server-X.txt.
Non crea mai doppioni: prima di ogni tentativo controlla se il server esiste già.

Serve:
  oci-config.txt   il testo che Oracle mostra dopo "Add API key"
  un file .pem      la chiave API scaricata da Oracle (nella stessa cartella)

Su GitHub Actions ("nuvola") gli stessi dati arrivano dai Secrets ORACLE_CONFIG e ORACLE_CHIAVE,
le chiavi SSH pubbliche da chiavi/chiave-X.pub e gli avvisi vanno su Telegram
(TELEGRAM_TOKEN + TELEGRAM_CHAT_ID). I log lì sono pubblici: niente IP né dati dell'account.
"""

import configparser
import contextlib
import ctypes
import json
import logging
import os
import random
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import urllib.request
from pathlib import Path

import oci
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from oci.core import models as m

BASE = Path(__file__).resolve().parent
CONFIG_ORACLE = BASE / "oci-config.txt"
IMPOSTAZIONI = BASE / "ritentatore.ini"

SHAPE = "VM.Standard.A1.Flex"
STATI_VIVI = {"PROVISIONING", "STARTING", "RUNNING", "STOPPING", "STOPPED", "CREATING_IMAGE", "MOVING"}

log = logging.getLogger("ritentatore")


def in_nuvola():
    return os.environ.get("GITHUB_ACTIONS") == "true" or bool(os.environ.get("ORACLE_CONFIG"))


class Fatale(Exception):
    """Problema che nessun nuovo tentativo può risolvere: va sistemato a mano."""


# ---------------------------------------------------------------- Telegram (avvisi)

def telegram(testo):
    """Manda un messaggio sul bot Telegram, se configurato. Non blocca mai il programma."""
    token, chat = os.environ.get("TELEGRAM_TOKEN", "").strip(), os.environ.get("TELEGRAM_CHAT_ID", "").strip()
    if not token or not chat:
        return False
    dati = urllib.parse.urlencode({"chat_id": chat, "text": testo}).encode()
    try:
        with urllib.request.urlopen(f"https://api.telegram.org/bot{token}/sendMessage", dati, timeout=20) as r:
            return bool(json.load(r).get("ok"))
    except Exception as e:
        log.warning("Messaggio Telegram non inviato (%s)", type(e).__name__)
        return False


# ---------------------------------------------------------------- configurazione

def trova_chiave_api():
    """La chiave API (.pem): dal Secret ORACLE_CHIAVE (nuvola) o dal file nella cartella (PC)."""
    testo = os.environ.get("ORACLE_CHIAVE", "").strip()
    if testo:
        if "PRIVATE KEY" not in testo:
            raise Fatale("il Secret ORACLE_CHIAVE non contiene la chiave privata: incolla TUTTO il file .pem")
        percorso = Path(tempfile.gettempdir()) / "oracle-api-chiave.pem"
        percorso.write_text(testo + "\n", encoding="ascii")
        os.chmod(percorso, 0o600)
        return percorso
    pem = [p for p in BASE.glob("*.pem") if "public" not in p.name.lower()]
    if not pem:
        raise Fatale("manca la chiave API: metti nella cartella il file .pem scaricato da Oracle "
                     "(quello della chiave PRIVATA)")
    if len(pem) > 1:
        raise Fatale("nella cartella ci sono più file .pem: lascia solo quello della chiave API privata "
                     f"({', '.join(p.name for p in pem)})")
    return pem[0]


def carica_oracle():
    testo = os.environ.get("ORACLE_CONFIG", "")
    if not testo.strip() and not CONFIG_ORACLE.exists():
        raise Fatale("manca oci-config.txt: incollaci il testo che Oracle mostra dopo 'Add API key'")
    fonte = "il Secret ORACLE_CONFIG" if testo.strip() else "oci-config.txt"
    cp = configparser.ConfigParser(interpolation=None, inline_comment_prefixes=("#", ";"))
    try:
        if not testo.strip():
            with open(CONFIG_ORACLE, encoding="utf-8-sig") as f:
                testo = f.read()
        if "[" not in testo.split("user", 1)[0]:
            testo = "[DEFAULT]\n" + testo  # incollato senza la riga [DEFAULT]
        cp.read_string(testo)
    except (configparser.Error, OSError, UnicodeDecodeError) as e:
        raise Fatale(f"{fonte} illeggibile: {e}") from None
    valori = dict(cp.defaults())
    for sezione in cp.sections():  # se qualcuno ha incollato sotto un nome diverso da DEFAULT
        valori.update(cp[sezione])
    mancanti = [k for k in ("user", "fingerprint", "tenancy", "region") if not valori.get(k, "").strip()]
    if mancanti:
        raise Fatale(f"in {fonte} mancano: {', '.join(mancanti)} (ricopia tutto il testo di Oracle)")
    config = {k: valori[k].strip() for k in ("user", "fingerprint", "tenancy", "region")}
    config["key_file"] = str(trova_chiave_api())  # la riga key_file di Oracle è un segnaposto: si ignora
    try:
        oci.config.validate_config(config)
    except oci.exceptions.InvalidConfig as e:
        raise Fatale(f"{fonte} non valido: {e}") from None
    return config


def carica_impostazioni():
    cp = configparser.ConfigParser(interpolation=None, inline_comment_prefixes=("#", ";"))
    if IMPOSTAZIONI.exists():
        with open(IMPOSTAZIONI, encoding="utf-8-sig") as f:
            cp.read_file(f)
    s = cp["ritentatore"] if cp.has_section("ritentatore") else {}
    nomi = [n.strip() for n in s.get("server", "server-A, server-B").split(",") if n.strip()]
    try:
        ocpu = float(s.get("ocpu", "1"))
        memoria = float(s.get("memoria_gb", "6"))
        ogni = max(60, int(s.get("ogni_secondi", "120")))
    except ValueError as e:
        raise Fatale(f"ritentatore.ini: numero non valido ({e})") from None
    if not nomi:
        raise Fatale("ritentatore.ini: nessun server da creare")
    return nomi, ocpu, memoria, ogni


# ---------------------------------------------------------------- chiavi SSH (per entrare nei server)

def file_chiave(nome):
    return BASE / f"chiave-{nome.split('-', 1)[-1]}.key"  # server-A -> chiave-A.key


def proteggi_chiave(percorso):
    """ssh rifiuta le chiavi leggibili da altri utenti del PC (es. "ospite"): la si rende solo tua."""
    if os.name != "nt":
        os.chmod(percorso, 0o600)
        return
    utente = os.environ.get("USERNAME")
    if utente:
        subprocess.run(["icacls", str(percorso), "/inheritance:r", "/grant:r", f"{utente}:F"],
                       capture_output=True, check=False)


def chiave_ssh_pubblica(nome):
    """Usa chiave-X.key se c'è, altrimenti la crea. Restituisce la parte pubblica da dare a Oracle.
    Nella nuvola non si creano mai chiavi: si usa chiavi/chiave-X.pub preparata da PREPARA.bat."""
    if in_nuvola():
        pub = BASE / "chiavi" / file_chiave(nome).with_suffix(".pub").name
        testo = pub.read_text(encoding="utf-8-sig").strip() if pub.exists() else ""
        if not testo.startswith("ssh-"):
            raise Fatale(f"manca chiavi/{pub.name} nel repository: lancia PREPARA.bat e ricarica la cartella")
        return testo
    percorso = file_chiave(nome)
    if percorso.exists():
        try:
            privata = serialization.load_pem_private_key(percorso.read_bytes(), password=None)
        except (ValueError, TypeError) as e:
            raise Fatale(f"{percorso.name} non è una chiave valida ({e}): cancellalo e verrà rifatto") from None
    else:
        privata = rsa.generate_private_key(public_exponent=65537, key_size=4096)
        percorso.write_bytes(privata.private_bytes(serialization.Encoding.PEM,
                                                   serialization.PrivateFormat.TraditionalOpenSSL,
                                                   serialization.NoEncryption()))
        log.info("Creata la chiave per entrare in %s: %s (conservala!)", nome, percorso.name)
    proteggi_chiave(percorso)
    pubblica = privata.public_key().public_bytes(serialization.Encoding.OpenSSH,
                                                 serialization.PublicFormat.OpenSSH).decode()
    percorso.with_suffix(".pub").write_text(pubblica + "\n", encoding="ascii")
    return pubblica


# ---------------------------------------------------------------- Oracle: rete, immagine, server

def tutti(funzione, *args, **kwargs):
    return oci.pagination.list_call_get_all_results(funzione, *args, **kwargs).data


def aspetta_stato(leggi, stato, massimo=600):
    fine = time.monotonic() + massimo
    while time.monotonic() < fine:
        oggetto = leggi()
        if oggetto.lifecycle_state == stato:
            return oggetto
        time.sleep(5)
    raise TimeoutError(f"non è diventato {stato} entro {massimo}s")


def assicura_ssh(rete, security_list_ids):
    """La porta 22 (SSH) deve essere aperta, altrimenti non si può installare il programma."""
    for sl_id in security_list_ids:
        sl = rete.get_security_list(sl_id).data
        for r in sl.ingress_security_rules or []:
            porte = r.tcp_options.destination_port_range if r.tcp_options else None
            if r.protocol in ("6", "all") and r.source == "0.0.0.0/0" and (
                    porte is None or porte.min <= 22 <= porte.max):
                return
    sl = rete.get_security_list(security_list_ids[0]).data
    regole = list(sl.ingress_security_rules or []) + [m.IngressSecurityRule(
        protocol="6", source="0.0.0.0/0", tcp_options=m.TcpOptions(destination_port_range=m.PortRange(min=22, max=22)))]
    rete.update_security_list(sl.id, m.UpdateSecurityListDetails(ingress_security_rules=regole))
    log.info("Aperta la porta SSH (22) nella rete")


def trova_o_crea_rete(rete, comp):
    """Usa una sottorete pubblica già esistente (es. quella creata dal pannello), oppure ne crea una."""
    for vcn in tutti(rete.list_vcns, comp):
        if vcn.lifecycle_state != "AVAILABLE":
            continue
        gateway = [g for g in tutti(rete.list_internet_gateways, comp, vcn_id=vcn.id)
                   if g.lifecycle_state == "AVAILABLE" and g.is_enabled]
        for sn in tutti(rete.list_subnets, comp, vcn_id=vcn.id):
            if sn.lifecycle_state != "AVAILABLE" or sn.prohibit_public_ip_on_vnic:
                continue
            if not gateway:
                g = rete.create_internet_gateway(m.CreateInternetGatewayDetails(
                    compartment_id=comp, vcn_id=vcn.id, is_enabled=True, display_name="internet-inoltro")).data
                gateway = [aspetta_stato(lambda: rete.get_internet_gateway(g.id).data, "AVAILABLE")]
            ids = {g.id for g in gateway}
            rt = rete.get_route_table(sn.route_table_id).data
            if not any(r.destination == "0.0.0.0/0" and r.network_entity_id in ids for r in rt.route_rules or []):
                regole = [r for r in rt.route_rules or [] if r.destination != "0.0.0.0/0"]
                regole.append(m.RouteRule(destination="0.0.0.0/0", destination_type="CIDR_BLOCK",
                                          network_entity_id=gateway[0].id))
                rete.update_route_table(rt.id, m.UpdateRouteTableDetails(route_rules=regole))
            assicura_ssh(rete, sn.security_list_ids)
            log.info("Uso la rete esistente: %s / %s", vcn.display_name, sn.display_name)
            return sn.id

    log.info("Nessuna rete pubblica trovata: la creo")
    vcn = rete.create_vcn(m.CreateVcnDetails(compartment_id=comp, cidr_blocks=["10.0.0.0/16"],
                                             display_name="rete-inoltro", dns_label="inoltro")).data
    vcn = aspetta_stato(lambda: rete.get_vcn(vcn.id).data, "AVAILABLE")
    g = rete.create_internet_gateway(m.CreateInternetGatewayDetails(
        compartment_id=comp, vcn_id=vcn.id, is_enabled=True, display_name="internet-inoltro")).data
    aspetta_stato(lambda: rete.get_internet_gateway(g.id).data, "AVAILABLE")
    rete.update_route_table(vcn.default_route_table_id, m.UpdateRouteTableDetails(route_rules=[
        m.RouteRule(destination="0.0.0.0/0", destination_type="CIDR_BLOCK", network_entity_id=g.id)]))
    sn = rete.create_subnet(m.CreateSubnetDetails(
        compartment_id=comp, vcn_id=vcn.id, cidr_block="10.0.0.0/24", display_name="subnet-inoltro",
        dns_label="pubblica", prohibit_public_ip_on_vnic=False, route_table_id=vcn.default_route_table_id,
        security_list_ids=[vcn.default_security_list_id])).data
    sn = aspetta_stato(lambda: rete.get_subnet(sn.id).data, "AVAILABLE")
    assicura_ssh(rete, sn.security_list_ids)
    return sn.id


def trova_immagine(compute, comp):
    for versione in ("22.04", "24.04"):
        immagini = [i for i in tutti(compute.list_images, comp, operating_system="Canonical Ubuntu",
                                     operating_system_version=versione, shape=SHAPE,
                                     sort_by="TIMECREATED", sort_order="DESC")
                    if "minimal" not in (i.display_name or "").lower() and i.lifecycle_state == "AVAILABLE"]
        if immagini:
            log.info("Immagine: %s", immagini[0].display_name)
            return immagini[0].id
    raise Fatale("non trovo un'immagine Ubuntu per l'Ampere A1")


def server_esistente(compute, comp, nome):
    for i in tutti(compute.list_instances, comp, display_name=nome):
        if i.lifecycle_state in STATI_VIVI:
            return i
    return None


def ip_pubblico(compute, rete, comp, istanza_id):
    for a in tutti(compute.list_vnic_attachments, comp, instance_id=istanza_id):
        if a.lifecycle_state == "ATTACHED":
            ip = rete.get_vnic(a.vnic_id).data.public_ip
            if ip:
                return ip
    return None


# ---------------------------------------------------------------- un tentativo

def prova_a_creare(compute, comp, ad, subnet_id, immagine_id, nome, chiave_pub, ocpu, memoria):
    """-> istanza creata, oppure None se Oracle non ha posto (si riprova). Fatale se è da sistemare a mano."""
    dettagli = m.LaunchInstanceDetails(
        compartment_id=comp, availability_domain=ad, display_name=nome, shape=SHAPE,
        shape_config=m.LaunchInstanceShapeConfigDetails(ocpus=ocpu, memory_in_gbs=memoria),
        source_details=m.InstanceSourceViaImageDetails(image_id=immagine_id),
        create_vnic_details=m.CreateVnicDetails(subnet_id=subnet_id, assign_public_ip=True),
        metadata={"ssh_authorized_keys": chiave_pub},
        # se Oracle fa manutenzione, il server si riaccende da solo
        availability_config=m.LaunchInstanceAvailabilityConfigDetails(recovery_action="RESTORE_INSTANCE"),
    )
    try:
        return compute.launch_instance(dettagli).data
    except oci.exceptions.ServiceError as e:
        messaggio = (e.message or "").lower()
        if "capacity" in messaggio:
            return None  # posti esauriti: il caso normale
        if e.status == 429:
            log.warning("Oracle chiede di rallentare: aspetto 5 minuti")
            time.sleep(300)
            return None
        if e.status >= 500:
            log.warning("Oracle ha un problema temporaneo (%s): riprovo", e.code)
            return None
        if e.code == "LimitExceeded" or "limit" in messaggio:
            raise Fatale(f"{nome}: superato il limite gratuito ({e.message}). Hai già altri server Ampere? "
                         "Il totale gratuito è 2 OCPU e 12 GB.") from None
        if e.status in (401, 403, 404):
            raise Fatale(f"Oracle rifiuta l'accesso ({e.code}): controlla oci-config.txt e la chiave .pem") from None
        raise Fatale(f"{nome}: Oracle ha rifiutato la richiesta ({e.status} {e.code}: {e.message})") from None


def avvisa(nome, ip):
    chiave = file_chiave(nome).name
    righe = [f"{nome} CREATO!", f"Indirizzo IP: {ip}", f"Chiave: {chiave}",
             f"In CARICA-SUL-SERVER.bat scrivi: ubuntu@{ip}"]
    inviato = telegram("✅ " + "\n".join(righe))
    if in_nuvola():  # i log di GitHub possono essere pubblici: l'IP va solo su Telegram
        log.info("%s CREATO! %s", nome, "IP inviato su Telegram" if inviato
                 else "IP non inviato: guardalo nel pannello Oracle (Compute -> Instances)")
        return
    (BASE / f"IP-{nome}.txt").write_text(f"{ip}\n", encoding="utf-8")
    log.info("=" * 60)
    for r in righe:
        log.info("  %s", r)
    log.info("=" * 60)
    if os.name == "nt":
        with contextlib.suppress(Exception):
            import winsound
            for _ in range(3):
                winsound.Beep(1000, 300)
        threading.Thread(target=lambda: ctypes.windll.user32.MessageBoxW(
            0, "\n".join(righe), "Ritentatore Oracle", 0x40 | 0x40000), daemon=True).start()


def tieni_sveglio_il_pc():
    """Finché il programma è aperto, Windows non va in sospensione (altrimenti i tentativi si fermano)."""
    if os.name == "nt":
        with contextlib.suppress(Exception):
            ctypes.windll.kernel32.SetThreadExecutionState(0x80000000 | 0x00000001)


# ---------------------------------------------------------------- programma

def esegui(config, nomi, ocpu, memoria, ogni, scadenza=None):
    """-> True se tutti i server esistono, False se è finito il tempo di questo giro (nuvola)."""
    compute = oci.core.ComputeClient(config)
    rete = oci.core.VirtualNetworkClient(config)
    identita = oci.identity.IdentityClient(config)
    comp = config["tenancy"]
    try:
        ad = identita.list_availability_domains(comp).data[0].name
    except oci.exceptions.ServiceError as e:
        raise Fatale(f"Oracle rifiuta l'accesso ({e.code}): controlla la configurazione e la chiave .pem") from None
    nuvola = in_nuvola()
    if nuvola:  # il nome dell'availability domain contiene un pezzo legato all'account: non nei log pubblici
        log.info("Collegato a Oracle (%s)", config["region"])
    else:
        log.info("Collegato a Oracle (%s, %s)", config["region"], ad)
    subnet_id = trova_o_crea_rete(rete, comp)
    immagine_id = trova_immagine(compute, comp)

    da_fare = {}
    for nome in nomi:
        esistente = server_esistente(compute, comp, nome)
        if esistente:
            ip = "" if nuvola else f", IP {ip_pubblico(compute, rete, comp, esistente.id) or '?'}"
            log.info("%s esiste già (%s%s): non lo ricreo", nome, esistente.lifecycle_state, ip)
            continue
        da_fare[nome] = chiave_ssh_pubblica(nome)
    if not da_fare:
        log.info("Tutti i server esistono già. Niente da fare.")
        return True

    log.info("Cerco posto per: %s (Ampere A1, %g OCPU, %g GB) ogni ~%ds",
             ", ".join(da_fare), ocpu, memoria, ogni)
    if nuvola and os.environ.get("GITHUB_EVENT_NAME") == "workflow_dispatch":
        telegram(f"🔎 Ritentatore avviato su GitHub: collegato a Oracle, cerco posto per {', '.join(da_fare)}. "
                 "Ti scrivo qui appena li trovo.")
    inizio, tentativo, creati = time.monotonic(), 0, []
    while da_fare:
        tentativo += 1
        for nome in list(da_fare):
            if server_esistente(compute, comp, nome):  # mai doppioni, anche se una risposta si era persa
                log.info("%s risulta già creato", nome)
                da_fare.pop(nome)
                continue
            istanza = prova_a_creare(compute, comp, ad, subnet_id, immagine_id, nome, da_fare[nome], ocpu, memoria)
            if istanza is None:
                continue
            log.info("%s: posto trovato! Lo sto accendendo...", nome)
            try:
                aspetta_stato(lambda: compute.get_instance(istanza.id).data, "RUNNING", massimo=900)
            except TimeoutError:
                stato = compute.get_instance(istanza.id).data.lifecycle_state
                if stato in ("TERMINATING", "TERMINATED"):
                    log.warning("%s è stato annullato da Oracle: riprovo", nome)
                    continue
            ip = None
            for _ in range(24):
                ip = ip_pubblico(compute, rete, comp, istanza.id)
                if ip:
                    break
                time.sleep(5)
            da_fare.pop(nome)
            creati.append(nome)
            avvisa(nome, ip or "(non ancora assegnato: guardalo nel pannello Oracle)")
        if da_fare:
            ore = (time.monotonic() - inizio) / 3600
            log.info("Tentativo %d: nessun posto per %s (in cerca da %.1f ore)", tentativo, ", ".join(da_fare), ore)
            if scadenza and time.monotonic() + ogni > scadenza:
                log.info("Fine di questo giro: il prossimo riparte da solo tra poco.")
                return False
            time.sleep(ogni + random.uniform(0, 30))
    if creati and nuvola:
        telegram("🏁 Tutti i server sono stati creati: il ritentatore su GitHub si spegne da solo.")
    log.info("Fatto: tutti i server sono stati creati.%s", "" if nuvola else " Puoi chiudere questa finestra.")
    return True


def segnala_a_github(fatto):
    """Dice al workflow se spegnersi (tutti i server creati)."""
    uscita = os.environ.get("GITHUB_OUTPUT")
    if uscita:
        with open(uscita, "a", encoding="utf-8") as f:
            f.write(f"fatto={'true' if fatto else 'false'}\n")


def main():
    nuvola = in_nuvola()
    gestori = [logging.StreamHandler()]
    if not nuvola:
        gestori.append(logging.FileHandler(BASE / "ritentatore.log", encoding="utf-8"))
    logging.basicConfig(level=logging.INFO, format="%(asctime)s  %(message)s", datefmt="%d/%m %H:%M:%S",
                        handlers=gestori)
    logging.getLogger("oci").setLevel(logging.CRITICAL)
    for flusso in (sys.stdout, sys.stderr):
        with contextlib.suppress(AttributeError, ValueError):
            flusso.reconfigure(errors="replace")
    tieni_sveglio_il_pc()
    # nella nuvola ogni giro dura al massimo DURATA_MINUTI, poi GitHub ne fa partire un altro
    minuti = float(os.environ.get("DURATA_MINUTI", "0") or 0) if nuvola else 0
    scadenza = time.monotonic() + minuti * 60 if minuti > 0 else None
    while True:
        try:
            config = carica_oracle()
            fatto = esegui(config, *carica_impostazioni(), scadenza=scadenza)
            segnala_a_github(fatto)
            return 0
        except Fatale as e:
            log.error("PROBLEMA: %s", e)
            if nuvola:
                telegram(f"⚠️ Ritentatore su GitHub fermo. PROBLEMA: {e}")
            return 1
        except KeyboardInterrupt:
            log.info("Fermato.")
            return 0
        except Exception as e:  # rete caduta, Oracle irraggiungibile...: si riparte da capo
            log.warning("Errore (%s): riprovo tra 2 minuti", type(e).__name__ if nuvola else f"{type(e).__name__}: {e}")
            if scadenza and time.monotonic() + 120 > scadenza:
                segnala_a_github(False)
                return 0
            time.sleep(120)


if __name__ == "__main__":
    sys.exit(main())
