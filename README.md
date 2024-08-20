# LFIProbeX

**LFIProbeX** es una herramienta diseñada para auditar vulnerabilidades de inclusión de archivos locales (LFI) en aplicaciones web. El script permite verificar si una URL es vulnerable a través de la inyección de payloads personalizados. Además, ofrece opciones de verbosidad y la capacidad de procesar múltiples URLs desde una lista.

## Características

- **Auditoría LFI**: Escanea URLs para detectar vulnerabilidades de inclusión de archivos locales (LFI).
- **Verbosidad Controlada**: Imprime el contenido completo de la respuesta si se detecta una vulnerabilidad (opcional).
- **Soporte para Múltiples URLs**: Puedes auditar una única URL o un conjunto de URLs desde un archivo.
- **Resultados en Color**: Los resultados se muestran en verde para vulnerabilidades detectadas y en rojo para intentos fallidos.

## Requisitos

- Python 3.x
- Librerías:
    - `requests`
    - `colorama`

Puedes instalar las dependencias utilizando `pip`:

`pip install requests colorama`

## Uso

### Ejecución básica

Para auditar una sola URL utilizando una lista de payloads:

`python LFIProbeX.py --url "https://example.com/vuln.php?param=" -w wordlist.txt`

![[Pasted image 20240819215156.png]](https://raw.githubusercontent.com/Mr-r00t11/LFIProbeX/main/img/Pasted%20image%2020240819215156.png)
### Auditar múltiples URLs

Para auditar múltiples URLs desde un archivo:

`python LFIProbeX.py -l urls.txt -w wordlist.txt`

![[Pasted image 20240819215230.png]](https://raw.githubusercontent.com/Mr-r00t11/LFIProbeX/main/img/Pasted%20image%2020240819215230.png)
### Verbosidad

Para habilitar la verbosidad y ver la respuesta completa cuando se detecta una vulnerabilidad:

`python LFIProbeX.py --url "https://example.com/vuln.php?param=" -w wordlist.txt -v`

![[Pasted image 20240819215306.png]](https://raw.githubusercontent.com/Mr-r00t11/LFIProbeX/main/img/Pasted%20image%2020240819215306.png)
## Parámetros

- `--url`: Especifica una única URL para auditar.
- `-l`, `--list`: Especifica un archivo que contiene una lista de URLs para auditar.
- `-w`, `--wordlist`: Ruta al archivo de wordlist que contiene los payloads.
- `-v`, `--verbose`: Habilita la salida detallada de la respuesta completa si se detecta una vulnerabilidad.
