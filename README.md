# SecretVars

[![Build](https://github.com/ElCyberCurioso/secretvars/actions/workflows/build.yml/badge.svg)](https://github.com/ElCyberCurioso/secretvars/actions/workflows/build.yml)
[![Release](https://img.shields.io/github/v/release/ElCyberCurioso/secretvars?label=release)](https://github.com/ElCyberCurioso/secretvars/releases/latest)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
![Java 17+](https://img.shields.io/badge/java-17%2B-orange)
![Burp Montoya API](https://img.shields.io/badge/Burp-Montoya%20API-ff6633)

**Variables secretas para Burp Suite.** Define tokens, API keys, contraseñas o cookies de sesión una sola
vez y referéncialos en cualquier petición con `{{secret:NOMBRE}}`. El valor real se inserta **en el momento
del envío**, así que:

- Las pestañas de Repeater (y de cualquier otro editor) **conservan el marcador**, nunca el valor.
- Si cambias el valor de un secreto, **el siguiente envío de cualquier pestaña usa el valor nuevo**, sin
  editar ni una sola petición guardada.

```http
GET /api/users/me HTTP/2
Host: target.local
Authorization: Bearer {{secret:jwt_admin}}
X-Api-Key: {{secret:api_key}}
```

## Índice

- [Características](#características)
- [Instalación](#instalación)
- [Uso rápido](#uso-rápido)
- [Sintaxis y modificadores](#sintaxis-y-modificadores)
- [Ámbitos](#ámbitos)
- [Menú contextual](#menú-contextual)
- [Comportamiento detallado](#comportamiento-detallado)
- [Seguridad](#seguridad)
- [Compilar desde el código fuente](#compilar-desde-el-código-fuente)
- [Contribuir](#contribuir)
- [Licencia](#licencia)

## Características

- Sustitución en el envío para **Repeater, Intruder, Scanner, Proxy, Sequencer, extensiones**... (configurable
  por herramienta).
- Marcadores en la línea de petición, cabeceras y cuerpo, con **modificadores** (`url`, `b64`, `b64url`,
  `hex`, `json`) encadenables.
- **Dos ámbitos**: secretos del proyecto (fichero `.burp`) y globales (preferencias de Burp); el de proyecto
  prevalece.
- **Menú contextual**: insertar variables, convertir una selección en secreto y **actualizar un secreto con
  el token seleccionado en una respuesta**.
- Pestaña **SecretVars** en el editor de peticiones con la vista resuelta (valores enmascarados por defecto).
- Recalcula `Content-Length` cuando procede y **respeta las manipulaciones deliberadas** (smuggling).
- HTTP/1.x reescrito byte a byte; HTTP/2 mediante la API estructurada.
- Los logs de la extensión **nunca** contienen valores, solo nombres de variable.

## Instalación

1. Descarga `SecretVars-x.y.z.jar` de la [última release](https://github.com/ElCyberCurioso/secretvars/releases/latest).
2. En Burp: `Extensions › Installed › Add`.
3. Extension type: **Java** y selecciona el JAR.
4. Aparece la pestaña **SecretVars** en la barra principal.

Requiere Burp Suite Professional o Community con soporte de la API Montoya (2023.x o posterior; compilado
contra la API 2026.7).

## Uso rápido

1. Pestaña **SecretVars › Añadir**: nombre `jwt`, valor `eyJhbGciOi...`.
2. En una pestaña de Repeater escribe `Authorization: Bearer {{secret:jwt}}` (o *clic derecho ›
   Extensions › SecretVars › Insertar variable*).
3. Envía. El servidor recibe el token; la pestaña sigue mostrando el marcador.
4. ¿Ha caducado el token? Selecciónalo en la respuesta del login › *clic derecho › SecretVars › Actualizar
   valor con la selección › jwt*. Todas las pestañas usarán el nuevo a partir del siguiente envío.

Ejemplo completo. Lo que guarda la pestaña de Repeater:

```http
POST /api/login?debug={{secret:password|url}} HTTP/1.1
Host: target.local
Authorization: Bearer {{secret:jwt}}
Content-Type: application/json
Content-Length: 45

{"user":"admin","pass":"{{secret:password}}"}
```

Lo que sale realmente hacia el servidor (`password` = `S3cr3t!`):

```http
POST /api/login?debug=S3cr3t%21 HTTP/1.1
Host: target.local
Authorization: Bearer eyJhbGciOi...
Content-Type: application/json
Content-Length: 33

{"user":"admin","pass":"S3cr3t!"}
```

## Sintaxis y modificadores

```
{{secret:NOMBRE}}
{{secret:NOMBRE|mod1|mod2}}
```

- `NOMBRE`: letras, dígitos, `_`, `-` y `.` (distingue mayúsculas).
- Válido en la línea de petición (ruta y query), nombres y valores de cabeceras, y cuerpo.
- No colisiona con payloads de SSTI tipo `{{7*7}}`: solo se reconoce el prefijo exacto `{{secret:`.

| Modificador | Efecto                                               | Ejemplo                                       |
|-------------|------------------------------------------------------|-----------------------------------------------|
| `url`       | Percent-encoding de todo salvo `A-Z a-z 0-9 - _ . ~` | `?pwd={{secret:pass\|url}}`                   |
| `b64`       | Base64 estándar                                      | `Authorization: Basic {{secret:creds\|b64}}`  |
| `b64url`    | Base64 URL-safe sin padding (estilo JWT)             | `{{secret:payload\|b64url}}`                  |
| `hex`       | Hexadecimal en minúsculas                            | `{{secret:key\|hex}}`                         |
| `json`      | Escapado para insertar dentro de una cadena JSON     | `{"p":"{{secret:pass\|json}}"}`               |

Se aplican de izquierda a derecha: `{{secret:creds|b64|url}}` codifica en Base64 y después en URL.

## Ámbitos

| Ámbito   | Dónde se guarda                 | Uso típico                                    |
|----------|---------------------------------|-----------------------------------------------|
| Proyecto | Fichero de proyecto `.burp`     | Credenciales y tokens de una auditoría        |
| Global   | Preferencias de usuario de Burp | Claves que reutilizas en todos los proyectos  |

Si existe el mismo nombre en ambos, **prevalece el de Proyecto** (el global aparece como "anulado"). Con un
proyecto temporal, los secretos de ámbito Proyecto solo duran la sesión.

## Menú contextual

`Clic derecho › Extensions › SecretVars` en cualquier editor de mensajes:

| Opción                               | Dónde                               | Qué hace                                                            |
|--------------------------------------|-------------------------------------|---------------------------------------------------------------------|
| Insertar variable ▸                  | Petición editable (Repeater, Intercept) | Inserta el marcador en el cursor o sustituye la selección       |
| Convertir selección en secreto…      | Petición editable                   | Crea el secreto con lo seleccionado y lo reemplaza por el marcador  |
| Crear secreto con la selección…      | Visores de solo lectura y respuestas | Crea el secreto con lo seleccionado                                |
| Actualizar valor con la selección ▸  | Cualquier editor, incluidas respuestas | Asigna lo seleccionado a un secreto existente                    |

Además, cuando una petición contiene marcadores aparece una pestaña **SecretVars** junto a *Pretty / Raw /
Hex* que muestra la petición resuelta, las variables resueltas y las no definidas. Los valores van
enmascarados salvo que marques **Mostrar valores reales**.

## Comportamiento detallado

- **Variable no definida o modificador desconocido**: el marcador se envía literal y se registra un aviso
  (una sola vez por variable) en la pestaña *Output* de la extensión.
- **Content-Length**: si el cuerpo cambia de tamaño y hay una única cabecera `Content-Length` cuyo valor
  coincidía con el cuerpo original, se recalcula. Si no coincidía (manipulación deliberada, pruebas de
  request smuggling) o hay varias, **no se toca**.
- **Transfer-Encoding: chunked**: los tamaños de chunk **no** se recalculan si el marcador está en el
  cuerpo; se registra un aviso.
- **HTTP/1.x**: todo lo que no sea un marcador se conserva byte a byte (orden y formato de cabeceras,
  duplicados, bytes no ASCII).
- **HTTP/2**: se usa la API estructurada (ruta, cabeceras, cuerpo) para conservar el protocolo.
- **Valores**: se insertan en UTF-8. La sustitución no es recursiva.
- **Errores**: ante cualquier fallo interno la petición sale sin modificar; nunca se bloquea el tráfico.
- **Scanner / Intruder**: si un payload queda pegado a un marcador (`{{secret:token}}'`), el marcador se
  resuelve igualmente y el payload queda pegado al valor real.

## Seguridad

- Los valores se guardan **sin cifrar** en el fichero de proyecto (ámbito Proyecto) o en las preferencias
  de usuario de Burp (ámbito Global). Trata ambos como material sensible.
- Las peticiones realmente enviadas (Logger, historial del Proxy, resultados de Intruder/Scanner) sí
  contienen el valor: el servidor lo necesita. Lo que no lo contiene es el editor de Repeater.
- Para informar de una vulnerabilidad en la extensión, consulta [SECURITY.md](SECURITY.md).

## Compilar desde el código fuente

Requiere JDK 17 o superior. El wrapper descarga Gradle automáticamente.

```bash
./gradlew build                 # compila, ejecuta las pruebas y genera build/libs/SecretVars-<versión>.jar
./gradlew coreTests             # motor de sustitución, reescritura HTTP/1 y almacén
./gradlew handlerSimulation     # flujo Repeater -> HttpHandler con una API Montoya simulada
```

En Windows usa `gradlew.bat`.

### Estructura

```
.
├── .github/
│   ├── workflows/build.yml        CI: compila y prueba en cada push / PR
│   ├── workflows/release.yml      Publica el JAR en Releases al crear un tag vX.Y.Z
│   ├── ISSUE_TEMPLATE/            Formularios de bug y propuesta
│   ├── pull_request_template.md
│   └── dependabot.yml             Actualizaciones de Montoya API, Gradle y Actions
├── gradle/wrapper/                Gradle wrapper
├── src/main/java/secretvars/
│   ├── SecretVarsExtension.java   Punto de entrada (BurpExtension)
│   ├── core/                      Lógica sin dependencias de Burp (motor, reescritura, almacén)
│   ├── burp/                      HttpHandler, menú contextual, pestaña del editor, ajustes
│   └── ui/                        Pestaña de gestión y diálogo de edición
├── src/test/java/secretvars/      Pruebas autocontenidas y simulación de la API
├── build.gradle
├── CHANGELOG.md
├── CONTRIBUTING.md
├── SECURITY.md
└── LICENSE
```

### Publicar una versión

```bash
# 1. Añade la entrada en CHANGELOG.md con el formato "## [1.1.0] - AAAA-MM-DD"
git tag v1.1.0
git push origin v1.1.0
```

El workflow `release.yml` compila con esa versión, ejecuta las pruebas y crea la release con el JAR adjunto
y las notas de la sección correspondiente del CHANGELOG.

## Contribuir

Las propuestas y correcciones son bienvenidas. Lee [CONTRIBUTING.md](CONTRIBUTING.md) antes de abrir un PR.

## Licencia

[MIT](LICENSE) © ElCyberCurioso.

Burp Suite y la API Montoya son propiedad de PortSwigger Ltd. Este proyecto no está afiliado a PortSwigger.
