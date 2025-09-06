# Shodan GT – Script de Consola
Script en **Python** que utiliza la **API de Shodan** para consultar activos en **Guatemala** y generar un resumen con: **total de direcciones IP únicas identificadas**, **conteo de IPs por puerto abierto** y un **listado** con IP, puerto, transporte, ciudad, hostnames y la primera línea del banner. Puedes incluir metadatos opcionales con `--carnet`, `--nombre`, `--curso`, `--seccion`.

## Requisitos
- Cuenta en [Shodan](https://account.shodan.io/).
- **API Key** de Shodan (Settings → API Key).
- **Python 3.10+** instalado.
> Shodan impone límites según el plan; si vas a traer muchas páginas, usa `--delay` y ajusta `--pages`.

## Preparación del entorno
```bash
# (Opcional) crear entorno virtual
python -m venv .venv
# Activar
# Windows:
.venv\Scripts\activate
# macOS / Linux:
# source .venv/bin/activate
# Instalar dependencias
pip install --upgrade pip
pip install shodan


# Windows (PowerShell)
setx SHODAN_API_KEY "TU_API_KEY_AQUI"
# macOS / Linux (bash/zsh; solo para la sesión actual)
export SHODAN_API_KEY="TU_API_KEY_AQUI"
