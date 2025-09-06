
#!/usr/bin/env python3

import argparse
import os
import sys
from collections import defaultdict
from typing import Dict, Set, List
import time

try:
    import shodan  # pip install shodan
except ImportError:
    print("ERROR: No se encontró el paquete 'shodan'. Instálalo con: pip install shodan", file=sys.stderr)
    sys.exit(1)


def validar_query(q: str) -> None:
    """Prohíbe el uso del filtro org: en la consulta, según la consigna."""
    if " org:" in f" {q}".lower():
        raise ValueError("La consulta contiene el filtro 'org:'. Está prohibido por la consigna.")


def obtener_api_key(cli_key: str | None) -> str:
    key = "ERjBa3NjSO9WDkJmNOMrW2H8uLba56b4"
    return key


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Escáner de Shodan dirigido a Guatemala (country:GT)")
    p.add_argument("--api-key", help="API key de Shodan (opcional si usas la variable SHODAN_API_KEY)")
    p.add_argument("--query", required=True, help="Filtro de Shodan, p.ej. city:\"Jalapa\" o port:3389. Se añadirá country:GT automáticamente.")
    p.add_argument("--pages", type=int, default=1, help="Número de páginas a recuperar (cada página ~100 resultados). Por defecto 1.")
    p.add_argument("--page-size", type=int, default=100, help="Tamaño de página deseado. Shodan suele devolver hasta 100.")
    p.add_argument("--delay", type=float, default=1.0, help="Segundos a esperar entre páginas para respetar límites de la API.")
    # Datos del estudiante (obligatorios para la salida)
    p.add_argument("--carnet", required=True, help="Número de carnet del estudiante.")
    p.add_argument("--nombre", required=True, help="Nombre completo del estudiante.")
    p.add_argument("--curso", required=True, help="Curso.")
    p.add_argument("--seccion", required=True, help="Sección.")
    return p


def imprimir_encabezado(args: argparse.Namespace) -> None:
    print("=" * 80)
    print("REPORTE SHODAN - CONSULTA DIRIGIDA A GUATEMALA (country:GT)\n")
    print(f"Carnet   : {args.carnet}")
    print(f"Nombre   : {args.nombre}")
    print(f"Curso    : {args.curso}")
    print(f"Sección  : {args.seccion}")
    print("=" * 80)


def formatear_resultado(i: int, r: dict) -> str:
    ip = r.get("ip_str") or r.get("ip") or "?"
    port = r.get("port", "?")
    transport = r.get("transport", "?")
    product = r.get("product") or r.get("_shodan", {}).get("module") or "?"
    city = (r.get("location", {}) or r.get("location", {})).get("city") if r.get("location") else r.get("city")
    city = city or "?"
    hostnames = ",".join(r.get("hostnames", [])[:3]) if r.get("hostnames") else ""
    data = (r.get("data") or "").splitlines()[0][:160] if r.get("data") else ""

    line = f"[{i}] {ip}:{port}/{transport}  ciudad={city}  hostnames={hostnames}  servicio={product}\n      banner: {data}"

    return line


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    try:
        validar_query(args.query)
        key = "ERjBa3NjSO9WDkJmNOMrW2H8uLba56b4"
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2

    api = shodan.Shodan(key)

    # Construimos la query final asegurando Guatemala
    base_q = args.query.strip()
    if "country:" not in base_q.lower():
        base_q = f"({base_q}) country:GT"

    imprimir_encabezado(args)
    print(f"Consulta Shodan: {base_q}")
    print(f"Páginas: {args.pages}  |  Page size solicitado: {args.page_size}\n")

    unique_ips: Set[str] = set()
    port_to_ips: Dict[int, Set[str]] = defaultdict(set)
    total_resultados = 0

    for page in range(1, args.pages + 1):
        try:
            res = api.search(base_q, page=page)
        except shodan.APIError as e:
            print(f"ERROR de Shodan en la página {page}: {e}", file=sys.stderr)
            break

        matches: List[dict] = res.get("matches", []) or []
        if not matches:
            if page == 1:
                print("Sin resultados para la consulta.")
            break

        for idx, r in enumerate(matches, start=1 + total_resultados):
            print(formatear_resultado(idx, r))
            ip = r.get("ip_str") or r.get("ip") or None
            port = r.get("port", None)
            if ip:
                unique_ips.add(ip)
                if isinstance(port, int):
                    port_to_ips[port].add(ip)

        total_resultados += len(matches)
        # Respetar límites de API entre páginas
        if page < args.pages:
            time.sleep(args.delay)

    # Resumen
    print("\n" + "-" * 80)
    print("RESUMEN")

    print(f"Total de resultados listados: {total_resultados}")

    print(f"Total de direcciones IP únicas identificadas: {len(unique_ips)}")

    if port_to_ips:

        print("\nTotal de IPs por puerto abierto:")

        print("Puerto\tIPs únicas")

        for p in sorted(port_to_ips):

            print(f"{p}\t{len(port_to_ips[p])}")

    else:

        print("No se detectaron puertos en los resultados.")

    print("-" * 80)

    return 0


if __name__ == "__main__":

    raise SystemExit(main())
