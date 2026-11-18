## Descripción

<!-- Qué cambia y por qué. Enlaza el issue si existe: "Closes #12" -->

## Tipo de cambio

- [ ] Corrección de error
- [ ] Nueva funcionalidad
- [ ] Refactorización / mantenimiento
- [ ] Documentación

## Comprobaciones

- [ ] `./gradlew build` pasa en local
- [ ] He añadido o actualizado pruebas en `CoreTests` / `HandlerSimulation`
- [ ] He probado la extensión en Burp (indica edición y versión abajo)
- [ ] He añadido la entrada en `[Unreleased]` de `CHANGELOG.md`
- [ ] Ningún log, excepción ni `toString()` expone valores de secretos
- [ ] No uso métodos de la API Montoya recientes sin protegerlos (ver CONTRIBUTING.md)

## Probado en

<!-- p. ej. Burp Professional 2026.10, Windows 11, HTTP/1.1 y HTTP/2 -->
