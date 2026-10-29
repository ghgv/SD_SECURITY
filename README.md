# Nubeware SD Security — Flutter + FastAPI + OpenWrt

## Arquitectura

Flutter (administrador) -> HTTPS -> FastAPI (AWS) -> JSON de políticas -> HTTPS -> agente C de OpenWrt -> UCI/dnsmasq/wifi.

La app **no** se conecta al router directamente ni sustituye al agente C. El router sigue consultando `GET /firewall/policy` con sus credenciales de dispositivo.

## Flutter

1. Tener Flutter instalado y Android SDK configurado.
2. Crear un proyecto Flutter con los archivos de plataforma:

```bash
flutter create --project-name nubeware_sd_security nubeware_sd_security
cd nubeware_sd_security
```

3. Reemplazar `pubspec.yaml` y `lib/main.dart` con los archivos de `mobile/`.
4. Asegurar permiso de Internet en `android/app/src/main/AndroidManifest.xml`:

```xml
<uses-permission android:name="android.permission.INTERNET" />
```

   Debe ir dentro de `<manifest>` y fuera de `<application>`.

5. Ejecutar:

```bash
flutter pub get
flutter run
```

Para generar un APK:

```bash
flutter build apk --release
```

La URL está fijada en `apiBase` al principio de `lib/main.dart`.

## Backend FastAPI

La app espera estas rutas, **ya definidas en el main.py del proyecto discutido**:

- `GET /admin/policy` (HTTP Basic de administrador): `revision`, `blocked_domains`, `wifi` (password enmascarada/vacía).
- `POST /admin/wifi`: `enabled`, `ssid`, `password` opcional, `channel`.
- `POST /admin/firewall/block`: `url`.
- `DELETE /admin/firewall/block/{domain}`.
- `GET /firewall/policy` (HTTP Basic diferente, solo para dispositivo): JSON completo que usa el agente C.

Configuración del backend en AWS (según la instalación existente):

```bash
sudo nano /home/ubuntu/sd_security/sd_security.env
sudo systemctl restart sd_security
```

Los usuarios y contraseñas se definen como `ADMIN_USER`, `ADMIN_PASSWORD`, `DEVICE_USER`, `DEVICE_PASSWORD`.

## Advertencias importantes

- No almacena credenciales de administrador en el dispositivo móvil: se conservan solamente en memoria durante la sesión.
- Es una primera versión de laboratorio; para producción considerar inicio de sesión con tokens limitados/expirables, control de sesiones, rate limiting y auditoría, en vez de HTTP Basic permanente.
- **Crítico:** el agente OpenWrt debe verificar correctamente la revisión, validar el JSON y aplicar solo cambios efectivos sin recargar Wi-Fi cada vez.
- El bloqueo de dominios es por DNS (`dnsmasq`): no bloquea URLs HTTPS individuales ni supera DNS-over-HTTPS/VPN.
- La contraseña Wi-Fi se entrega al agente C por el endpoint autenticado. Evitar registros sensibles.
- La app publica la política, pero no confirma por sí sola que el router la aplicó. Para ese estado real se necesita un endpoint de reporte del agente.

## Servidor Python incluido

El archivo `backend/main.py` implementa el backend de referencia. Para instalarlo sobre tu servicio actual, **haz copia de seguridad de `main.py` y de `policy.json`**. No reemplaces a ciegas si tienes otros endpoints activos.

```bash
cd /home/ubuntu/sd_security/src/backend
cp main.py main.py.backup
# copiar aquí el main.py de backend/
/home/ubuntu/sd_security/venv/bin/pip install -r requirements.txt
sudo systemctl restart sd_security
```

Las credenciales de `sd_security.env` se cargan con `EnvironmentFile` en systemd. Después de cambiar el servidor, la API de administración acepta únicamente las credenciales `ADMIN_*`; el agente del router mantiene las `DEVICE_*`.

**Nota:** no se incluyó HTML en esta variante, porque el administrador utilizará Flutter. Si deseas conservar `/admin` en el navegador, conserva o incorpora su ruta antes de reemplazar `main.py`.

## Compatibilidad de políticas antiguas

`load()` añade los campos `wifi` faltantes a las políticas viejas en memoria. Solo se persisten al guardar un cambio. Si `wifi.enabled=false` y la contraseña está vacía, el servidor puede entregar esta sección: el agente C debe aceptar el estado deshabilitado sin exigir contraseña WPA2. Si tu C actual exige siempre clave de 8 caracteres, corrígelo antes de poner esta versión en producción.
