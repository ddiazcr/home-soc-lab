"""
Automated triage pipeline for the Home SOC Lab.

SIMULATED MODE (MODE = "SIMULADO", default): does not call the Claude API and
uses a canned analysis instead, so the whole flow (dedup, case file,
notification) can be tested without active API credit.

REAL MODE: once the Claude API is available, set MODE to "REAL" below.
Requires the ANTHROPIC_API_KEY environment variable and system_prompt.txt in
the same folder.

Telegram notification: if TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID are set as
environment variables, the real message is sent. If they are not set, the
message is printed to the console as a fallback (the script keeps running).
"""

import os
import re
import sqlite3
import json
import hashlib
import time
import uuid
from datetime import datetime, timedelta, timezone

DB_PATH = "expedientes.db"
DEDUP_WINDOW_MINUTES = 10
MODE = "SIMULADO"  # set to "REAL" once the API is available


def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS casos (
            id TEXT PRIMARY KEY,
            hash_dedup TEXT,
            huella_contenido TEXT,
            regla TEXT,
            origen TEXT,
            destino TEXT,
            primera_deteccion TEXT,
            ultima_deteccion TEXT,
            conteo INTEGER,
            evidencia TEXT,
            analisis_ia TEXT,
            prioridad TEXT,
            confianza TEXT,
            estado TEXT
        )
    """)
    # Databases created before the content fingerprint existed lack the column.
    columnas = {fila[1] for fila in conn.execute("PRAGMA table_info(casos)")}
    if "huella_contenido" not in columnas:
        conn.execute("ALTER TABLE casos ADD COLUMN huella_contenido TEXT")
    conn.commit()
    return conn


def calcular_hash(regla, origen, destino):
    base = f"{regla}-{origen}-{destino}"
    return hashlib.sha256(base.encode()).hexdigest()[:16]


# Fields that are expected to change between repeats of the same event
# (timestamps, ephemeral source ports) are stripped before fingerprinting, so a
# beacon firing every 2 minutes still collapses into one case.
CAMPOS_VOLATILES = re.compile(
    r"\b(timestamp|time|srcport|src_port|spt)=\S+"
    r"|\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:?\d{2})?",
    re.IGNORECASE,
)


def calcular_huella_contenido(alerta):
    """Fingerprint of the alert content that an attacker can influence.

    Dedup used to group only by (rule + src IP + dest IP), so a new alert that
    reused a recent rule/IP pair was merged into the old case without being
    analyzed, whatever its description or raw log said. Hashing the content
    too means any change in those fields opens a new case and a new analysis.
    """
    raw_log = CAMPOS_VOLATILES.sub("", str(alerta.get("raw_log", "")))
    base = json.dumps(
        {
            "level": alerta.get("level"),
            "dest_port": alerta.get("dest_port"),
            "protocol": alerta.get("protocol"),
            "description": alerta.get("description"),
            "raw_log": " ".join(raw_log.split()),
        },
        sort_keys=True,
        ensure_ascii=False,
    )
    return hashlib.sha256(base.encode()).hexdigest()[:16]


def buscar_caso_reciente(conn, hash_dedup, huella_contenido):
    limite = (datetime.now(timezone.utc) - timedelta(minutes=DEDUP_WINDOW_MINUTES)).isoformat()
    cur = conn.execute(
        "SELECT id, conteo, huella_contenido FROM casos "
        "WHERE hash_dedup = ? AND ultima_deteccion > ? "
        "ORDER BY ultima_deteccion DESC",
        (hash_dedup, limite),
    )
    filas = cur.fetchall()
    for caso_id, conteo, huella in filas:
        if huella == huella_contenido:
            return (caso_id, conteo), None
    # Same rule and IPs as a recent case but different content: never merge it.
    return None, (filas[0][0] if filas else None)


def cargar_system_prompt():
    with open("system_prompt.txt", "r", encoding="utf-8") as f:
        return f.read()


def analizar_con_ia(alerta):
    if MODE == "SIMULADO":
        return {
            "resumen": f"[SIMULADO] Actividad sospechosa detectada en regla {alerta['rule_id']}",
            "prioridad": "high",
            "confianza": "medium",
            "campos_sustento": ["rule_id", "src_ip", "dest_port"],
            "verificaciones_sugeridas": ["Confirmar proceso asociado en el host origen"],
            "possible_prompt_injection": False,
        }

    import anthropic

    client = anthropic.Anthropic()
    system_prompt = cargar_system_prompt()
    msg = client.messages.create(
        model="claude-haiku-4-5-20251001",
        max_tokens=500,
        system=system_prompt,
        messages=[{"role": "user", "content": json.dumps(alerta, ensure_ascii=False)}],
    )
    return parsear_json_ia(msg.content[0].text)


def parsear_json_ia(texto):
    """Strip markdown fences (```json ... ```) in case the model adds them,
    and fall back to extracting the first {...} object if it comes wrapped
    in extra text."""
    texto = texto.strip()
    if texto.startswith("```"):
        texto = re.sub(r"^```(json)?", "", texto).strip()
        texto = re.sub(r"```$", "", texto).strip()
    try:
        return json.loads(texto)
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", texto, re.DOTALL)
        if match:
            return json.loads(match.group(0))
        raise


def procesar_alerta(conn, alerta, forzar_nuevo=False):
    hash_dedup = calcular_hash(alerta["rule_id"], alerta["src_ip"], alerta["dest_ip"])
    huella_contenido = calcular_huella_contenido(alerta)
    existente, caso_relacionado = (
        (None, None) if forzar_nuevo else buscar_caso_reciente(conn, hash_dedup, huella_contenido)
    )
    ahora = datetime.now(timezone.utc).isoformat()

    if existente:
        caso_id, conteo = existente
        conn.execute(
            "UPDATE casos SET ultima_deteccion = ?, conteo = ? WHERE id = ?",
            (ahora, conteo + 1, caso_id),
        )
        conn.commit()
        print(f"[DEDUP] Caso {caso_id} actualizado (conteo={conteo + 1})")
        return caso_id

    if caso_relacionado:
        print(
            f"[DEDUP] Mismo rule/IPs que el caso {caso_relacionado} pero contenido distinto: "
            "se abre un caso nuevo y se analiza"
        )

    # Unique ID per incident (not derived from rule+IPs alone, so it never
    # collides with an older case outside the dedup window, even when it is
    # the same rule/source/destination from another day).
    caso_id = f"{hash_dedup}-{uuid.uuid4().hex[:8]}"
    try:
        analisis = analizar_con_ia(alerta)
        estado = "analizado"
    except Exception as e:
        analisis = None
        estado = "sin_analisis"
        print(f"[ERROR] Falló el análisis de IA: {e}")

    conn.execute(
        "INSERT INTO casos (id, hash_dedup, huella_contenido, regla, origen, destino, "
        "primera_deteccion, ultima_deteccion, conteo, evidencia, analisis_ia, "
        "prioridad, confianza, estado) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            caso_id,
            hash_dedup,
            huella_contenido,
            alerta["rule_id"],
            alerta["src_ip"],
            alerta["dest_ip"],
            ahora,
            ahora,
            1,
            json.dumps(alerta, ensure_ascii=False),
            json.dumps(analisis, ensure_ascii=False) if analisis else None,
            analisis["prioridad"] if analisis else "desconocida",
            analisis["confianza"] if analisis else "n/a",
            estado,
        ),
    )
    conn.commit()
    notificar(caso_id, alerta, analisis, estado, caso_relacionado)
    return caso_id


def enviar_telegram(mensaje):
    token = os.environ.get("TELEGRAM_BOT_TOKEN")
    chat_id = os.environ.get("TELEGRAM_CHAT_ID")

    if not token or not chat_id:
        print("--- NOTIFICACIÓN (Telegram no configurado, mostrando en consola) ---")
        print(mensaje)
        print("---------------------------------------------------------------")
        return

    import requests

    url = f"https://api.telegram.org/bot{token}/sendMessage"
    try:
        resp = requests.post(url, data={"chat_id": chat_id, "text": mensaje}, timeout=10)
        resp.raise_for_status()
    except Exception as e:
        print(f"[ERROR] No se pudo enviar el mensaje a Telegram: {e}")
        print("--- Mensaje que no se pudo enviar ---")
        print(mensaje)


def notificar(caso_id, alerta, analisis, estado, caso_relacionado=None):
    if estado == "analizado":
        flag_injection = " ⚠️ POSIBLE INYECCIÓN DETECTADA EN EL LOG" if analisis.get("possible_prompt_injection") else ""
        mensaje = (
            f"Caso {caso_id}{flag_injection}\n"
            f"Regla: {alerta['rule_id']}\n"
            f"Prioridad: {analisis['prioridad']} (confianza: {analisis['confianza']})\n"
            f"Resumen: {analisis['resumen']}"
        )
    else:
        mensaje = (
            f"Caso {caso_id} — análisis de IA NO disponible\n"
            f"Regla: {alerta['rule_id']}\n"
            f"Origen: {alerta['src_ip']} -> Destino: {alerta['dest_ip']}\n"
            f"Revisar manualmente."
        )
    if caso_relacionado:
        mensaje += (
            f"\nNota: mismo rule/IPs que el caso {caso_relacionado} pero con contenido "
            "distinto. Revisar si alguien intenta esconder una alerta nueva."
        )
    enviar_telegram(mensaje)


def main():
    import sys

    args = sys.argv[1:]
    forzar_nuevo = "--no-dedup" in args
    args = [a for a in args if a != "--no-dedup"]
    archivo_alertas = args[0] if args else "simulated_alerts.json"

    conn = init_db()
    with open(archivo_alertas, "r", encoding="utf-8") as f:
        alertas = json.load(f)

    modo_txt = " (dedup desactivado)" if forzar_nuevo else ""
    print(f"Procesando {len(alertas)} alertas desde {archivo_alertas}{modo_txt}...\n")
    for alerta in alertas:
        procesar_alerta(conn, alerta, forzar_nuevo=forzar_nuevo)
        time.sleep(1)

    conn.close()
    print(f"\nListo. Revisá {DB_PATH} para ver los casos guardados.")


if __name__ == "__main__":
    main()
