# Changelog

Todos los cambios relevantes de este proyecto se documentan en este fichero.

El formato sigue [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/) y el proyecto usa
[versionado semántico](https://semver.org/lang/es/). El workflow de release extrae automáticamente la
sección de cada versión como notas de la release.

## [Unreleased]

## [1.0.0] - 2026-11-18

### Añadido

- Marcadores `{{secret:NOMBRE}}` sustituidos en el momento del envío; los editores conservan el marcador.
- Modificadores encadenables `url`, `b64`, `b64url`, `hex` y `json`.
- Secretos de ámbito Proyecto (fichero `.burp`) y Global (preferencias de Burp); prevalece el de proyecto.
- Pestaña de gestión con valores enmascarados, contadores de uso y ajustes por herramienta.
- Menú contextual: insertar variable, convertir selección en secreto, crear secreto y actualizar valor con
  la selección (también desde respuestas).
- Pestaña de vista resuelta en el editor de peticiones.
- Recalculado de `Content-Length` que respeta manipulaciones deliberadas; aviso en cuerpos chunked.
- Soporte de HTTP/1.x (reescritura byte a byte) y HTTP/2 (API estructurada).

[Unreleased]: https://github.com/ElCyberCurioso/secretvars/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/ElCyberCurioso/secretvars/releases/tag/v1.0.0
