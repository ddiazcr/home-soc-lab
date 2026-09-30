"""
Pipeline de triage automatizado para el Home SOC Lab.

MODO SIMULADO (por defecto): no llama a la API de Claude, usa un análisis
de prueba, para poder probar toda la lógica (dedup, expediente, notificación)
sin necesitar crédito activo.

MODO REAL: cuando tengas la API de Claude activa, cambiá MODE a "REAL"
más abajo. Necesita la variable de entorno ANTHROPIC_API_KEY y el archivo
system_prompt.txt en la misma carpeta.

Notificación por Telegram: si TELEGRAM_BOT_TOKEN y TELEGRAM_CHAT_ID están
configurados como variables de entorno, se envía el mensaje real. Si no
están configurados, se imprime en consola como respaldo (no rompe el script).
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
MODE = "SIMULADO"  # cambiar a "REAL" cuando tengas la API activa


def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS casos (
            id TEXT PRIMARY KEY,
            hash_dedup TEXT,
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
    conn.commit()
    return conn


def calcular_hash(regla, origen, destino):
    base = f"{regla}-{origen}-{destino}"
    return hashlib.sha256(base.encode()).hexdigest()[:16]


def buscar_caso_reciente(conn, hash_dedup):
    limite = (datetime.now(timezone.utc) - timedelta(minutes=DEDUP_WINDOW_MINUTES)).isoformat()
    cur = conn.execute(
        "SELECT id, conteo FROM casos WHERE hash_dedup = ? AND ultima_deteccion > ?",
        (hash_dedup, limite),
    )
    return cur.fetchone()


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
    """Limpia fences de markdown (```json ... ```) por si el modelo los agrega,
    y extrae el primer objeto {...} como respaldo si viene con texto alrededor."""
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
    existente = None if forzar_nuevo else buscar_caso_reciente(conn, hash_dedup)
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

    # ID único por incidente (no depende solo de regla+IPs, para no chocar
    # con un caso viejo de fuera de la ventana de dedup, aunque sea la misma
    # regla/origen/destino de otro día).
    caso_id = f"{hash_dedup}-{uuid.uuid4().hex[:8]}"
    try:
        analisis = analizar_con_ia(alerta)
        estado = "analizado"
    except Exception as e:
        analisis = None
        estado = "sin_analisis"
        print(f"[ERROR] Falló el análisis de IA: {e}")

    conn.execute(
        "INSERT INTO casos VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            caso_id,
            hash_dedup,
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
    notificar(caso_id, alerta, analisis, estado)
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


def notificar(caso_id, alerta, analisis, estado):
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
