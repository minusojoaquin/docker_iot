# Contexto del Proyecto: RECTITRACK

## 1. Propósito del Sistema
Sistema de software web diseñado para la gestión operativa y digitalización centralizada de un taller de rectificación de motores. Elimina la pérdida de información, automatiza notificaciones, gestiona el flujo de trabajo financiero y técnico, y garantiza la trazabilidad en tiempo real mediante identificadores físicos (QR).

## 2. Restricciones de Infraestructura y Despliegue
* **Entorno:** Servidor VPS con orquestación Docker y Docker Compose.
* **Restricción de Red:** Exposición estricta de un único puerto público (`10213`) en el host.
* **Enrutamiento:** SWAG (Nginx LinuxServer) operando como Proxy Inverso seguro (`10213`). Despacho interno mediante proxy inverso *strip-prefix*.
* **Topología `compose.yaml`:**
  * `mariadb`: Motor relacional (`rectitrack_db`).
  * `phpmyadmin`: Interfaz de administración de datos aislada.
  * `swag`: Capa de seguridad HTTPS y enrutamiento.
  * `crud`: Aplicación core (Python / Flask / Bootstrap 5).

## 3. Modelo de Datos Relacional (`rectitrack_db`)
* **Cliente:** Entidad de contacto. Credenciales autogeneradas (Usuario: apellido, Contraseña: DNI).
* **Motor:** Identificado criptográficamente por `codigo_qr`. Incluye columna `estado` (`PENDIENTE`, `EN_PROCESO`, `TERMINADO`) para exclusión lógica en vistas. **Prohibida la eliminación física (`DELETE`).**
* **OrdenTrabajo:** Control de fechas, montos totales, saldos y estado global del motor.
* **Pago_Orden:** Registro de transacciones parciales (`anticipos`).
* **Area:** Divisiones operativas (`Cilindros`, `Cigüeñal`, `Bujes`, `Plano`).
* **Operario:** Ejecutor técnico de tareas.
* **Tarea:** Registro transaccional inmutable de operaciones, mediciones, observaciones y prioridad.
* **Notificaciones:** Registro de alertas críticas (pausas por repuestos, inactividad prolongada).
* **TokenRecuperacion:** Gestión de tokens seguros temporales (30 min) para el restablecimiento de contraseñas de Gerentes.

## 4. Roles y Casos de Uso del Sistema
* **Rol Gerente (Administrador):**
  * Asignación de tareas y monitoreo de cuellos de botella.
  * Registro de motores y generación de QR.
  * Gestión de cobros, anticipos y saldos deudores.
  * Acceso exclusivo a recuperación de contraseña desde UI.
* **Rol Operario (Técnico):**
  * Resolución de QR para acceso a ficha técnica.
  * Ejecución de tareas ordenadas por prioridad.
  * Transición de estados de tarea (Inicio, Pausa, Finalización).
* **Rol Cliente (Solo Lectura):**
  * Consulta de estado de avance de motor.
  * Visualización de saldos adeudados y notificaciones.

## 5. Estado Actual del Desarrollo
* **Backend (`crud.py` / Flask):** Integración de SQLAlchemy/MySQLdb. Despacho SMTP seguro implementado.
* **Rutas Críticas Activas:**
  * `/login`: Control de acceso Role-Based (Gerente, Operario, Cliente). UI optimizada (alta legibilidad, sin credenciales expuestas, sin navegación redundante).
  * `/recuperar-password` y `/reset-password/<token>`: Flujo seguro de recuperación de contraseñas vía email para el rol Gerente.
  * `/panel-gerente`: Interfaz principal 2x2.
  * `/panel-gerente/asignar`: Lógica DML para inyección de tareas.
  * `/panel-gerente/pagos`: Tablero financiero. Recálculo dinámico de `saldo` vía POST modal (`/registrar_anticipo/<id>`).
  * `/panel-gerente/registro-motor`: Flujo de ingreso. Autogeneración de credenciales y despacho de email asíncrono SMTP post-commit.
  * `/scan/<codigo_qr>`: Endpoint de resolución técnica para operarios.

## 6. Resoluciones Estructurales (Sprint Actual)
* **Refactorización UI/UX (Mobile-First):** Escalado de logotipos, inyección de grillas 2x2 en paneles, corrección de contraste en formularios (texto blanco en fondos oscuros). Supresión de botones de retroceso y logotipos redundantes en `/login`.
* **Transmisión SMTP (Gateways):** Implementación de `smtplib` con TLS puerto 587. Uso obligatorio de App Passwords (2FA) para Google Workspace/Gmail. Bloques `try/except` con feedback asíncrono (Flask flash).
* **Máquina de Estados y Exclusión Lógica:** Intercepción de la finalización de tareas del operario. Confirmación UI para última tarea. Ejecución de `UPDATE Motor SET estado = 'TERMINADO'`. Modificación de consultas SQL (`WHERE estado != 'TERMINADO'`) para purgar colas operativas preservando el historial financiero.
* **Gestión Financiera:** Implementación de modales de anticipo con validación de tipo de dato numérico (`step="0.01"`). Implementación de endpoint `/registrar_anticipo/<int:motor_id>`.

## 7. Directivas Absolutas para Agentes de IA
* **Integridad de Datos:** Bajo ningún concepto ejecutar sentencias `DROP` o `DELETE` sobre registros operativos (Motores, Clientes, Tareas). Utilizar estrictamente mutaciones de estado (`UPDATE`) para exclusión lógica.
* **Preservación de Autenticación:** No alterar la lógica de encriptación de contraseñas ni la generación automática de credenciales de cliente (Apellido/DNI).
* **Fidelidad UI:** Mantener estricto cumplimiento de la paleta (`#1A365D`, `#FF6B00`, `#FFF3E8`). Requerir el uso de Bootstrap 5 y variables Jinja2 para componentes dinámicos.
* **Gestión de Entorno:** Credenciales SMTP, tokens y variables de entorno deben permanecer fuera del código fuente, referenciadas vía `os.environ` o `.env`.