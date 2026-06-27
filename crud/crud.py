import os
import io
import base64
import logging
import qrcode
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import secrets
import random
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_mysqldb import MySQL
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash

# Configuración del Logger
logging.basicConfig(format='%(asctime)s - RECTITRACK - %(levelname)s - %(message)s', level=logging.INFO)

# RF14: WhatsApp API Stub
def send_whatsapp_alert(phone, message):
    # Stub function for Twilio/Meta API integration
    logging.info(f"WhatsApp API [STUB] - Mensaje enviado a {phone}: {message}")

app = Flask(__name__)

# Middleware para Proxy Inverso (Nginx/SWAG)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

# Parámetros estáticos de Base de Datos y Sesión
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "rectitrack_secure_key_2026")
app.config["MYSQL_USER"] = "root"
app.config["MYSQL_PASSWORD"] = os.environ.get("MARIADB_ROOT_PASSWORD", "IoTJoa")
app.config["MYSQL_DB"] = "rectitrack_db"
app.config["MYSQL_HOST"] = "mariadb"
app.config['PERMANENT_SESSION_LIFETIME'] = 1800

mysql = MySQL(app)

_db_seeded = False

@app.before_request
def setup_db():
    global _db_seeded
    if not _db_seeded:
        try:
            cur = mysql.connection.cursor()
            # 0. Crear tabla TokenRecuperacion si no existe
            cur.execute("""
                CREATE TABLE IF NOT EXISTS TokenRecuperacion (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    usuario_id VARCHAR(255) NOT NULL,
                    token_hash VARCHAR(255) NOT NULL,
                    fecha_expiracion DATETIME NOT NULL,
                    usado BOOLEAN DEFAULT 0
                )
            """)
            # 0b. Agregar columna email a Usuarios_Gerencia si no existe
            cur.execute("""
                ALTER TABLE Usuarios_Gerencia
                ADD COLUMN IF NOT EXISTS email VARCHAR(255) DEFAULT NULL
            """)
            mysql.connection.commit()
            
            # 1. Check/Insert Gerente admin
            cur.execute("SELECT usuario FROM Usuarios_Gerencia WHERE usuario = 'admin'")
            if not cur.fetchone():
                admin_hash = generate_password_hash("admin", method='scrypt', salt_length=16)
                cur.execute("INSERT INTO Usuarios_Gerencia (usuario, hash_password) VALUES ('admin', %s)", (admin_hash,))
                mysql.connection.commit()
                logging.info("Seeded default Manager credentials (admin/admin).")
            
            # 2. Check/Insert Operario operario
            cur.execute("SELECT id_operario FROM Operario WHERE login = 'operario'")
            if not cur.fetchone():
                operario_hash = generate_password_hash("operario", method='scrypt', salt_length=16)
                cur.execute("""
                    INSERT INTO Operario (nombre, apellido, login, password) 
                    VALUES ('Operario', 'Default', 'operario', %s)
                """, (operario_hash,))
                mysql.connection.commit()
                logging.info("Seeded default Operario credentials (operario/operario).")
            cur.close()
            _db_seeded = True
        except Exception as e:
            logging.error(f"Error during database seeding: {e}")

# Decoradores de Autorización
def require_gerente(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("role") != "gerente":
            flash("Acceso denegado. Se requieren credenciales de Gerente.")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def require_operario(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("role") != "operario":
            flash("Acceso denegado. Se requieren credenciales de Operario.")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def require_cliente(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("role") != "cliente":
            flash("Acceso denegado. Se requieren credenciales de Cliente.")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# ==========================================
# RUTAS DE AUTENTICACIÓN
# ==========================================
@app.route('/')
def index():
    role = session.get("role")
    if role == "gerente":
        return redirect(url_for('panel_gerente'))
    elif role == "operario":
        return redirect(url_for('panel_operario'))
    elif role == "cliente":
        return redirect(url_for('panel_cliente'))
    return redirect(url_for('login'))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        usuario = request.form.get("usuario")
        password = request.form.get("password")
        rol = request.form.get("rol")

        if not usuario or not password:
            flash("Todos los campos son obligatorios.")
            return redirect(url_for('login'))

        cur = mysql.connection.cursor()
        
        if rol == "gerente":
            cur.execute("SELECT id, hash_password FROM Usuarios_Gerencia WHERE usuario = %s", (usuario,))
            row = cur.fetchone()
            cur.close()

            if row and check_password_hash(row[1], password):
                session.permanent = True
                session["user_id"] = usuario
                session["role"] = "gerente"
                logging.info(f"Autenticación exitosa - Gerente: {usuario}")
                return redirect(url_for('panel_gerente'))
            else:
                flash("Credenciales de Gerente incorrectas.")
        
        elif rol == "operario":
            cur.execute("SELECT id_operario, password, nombre, apellido FROM Operario WHERE login = %s", (usuario,))
            row = cur.fetchone()
            cur.close()

            if row and check_password_hash(row[1], password):
                session.permanent = True
                session["user_id"] = usuario
                session["role"] = "operario"
                session["operario_id"] = row[0]
                logging.info(f"Autenticación exitosa - Operario: {row[2]} {row[3]}")
                return redirect(url_for('panel_operario'))
            else:
                flash("Credenciales de Operario incorrectas.")
                
        elif rol == "cliente":
            cur.execute("SELECT dni, password, nombre, apellido FROM Cliente WHERE login = %s", (usuario,))
            row = cur.fetchone()
            cur.close()
            
            if row and check_password_hash(row[1], password):
                session.permanent = True
                session["user_id"] = usuario
                session["role"] = "cliente"
                session["cliente_dni"] = row[0]
                logging.info(f"Autenticación exitosa - Cliente: {row[2]} {row[3]}")
                return redirect(url_for('panel_cliente'))
            else:
                flash("Credenciales de Cliente incorrectas.")
        else:
            cur.close()
            flash("Rol no válido.")

    return render_template('login.html')

@app.route("/registrar", methods=["GET", "POST"])
def registrar():
    if request.method == "POST":
        usuario = request.form.get("usuario")
        password = request.form.get("password")
        rol = request.form.get("rol")

        if not usuario or not password:
            flash("Todos los campos son obligatorios.")
            return redirect(url_for('registrar'))

        passhash = generate_password_hash(password, method='scrypt', salt_length=16)
        cur = mysql.connection.cursor()

        try:
            if rol == "gerente":
                cur.execute("INSERT INTO Usuarios_Gerencia (usuario, hash_password) VALUES (%s, %s)", (usuario, passhash))
            elif rol == "operario":
                cur.execute("INSERT INTO Operario (nombre, apellido, login, password) VALUES ('Nuevo', 'Operario', %s, %s)", (usuario, passhash))
            
            mysql.connection.commit()
            flash("Usuario registrado exitosamente.")
            return redirect(url_for('login'))
        except Exception as e:
            logging.error(f"Falla de persistencia en registro: {e}")
            flash("El nombre de usuario ya existe en la base de datos.")
        finally:
            cur.close()

    return render_template('registrar.html')

@app.route("/logout")
def logout():
    logging.info(f"Sesión cerrada - Usuario: {session.get('user_id')}")
    session.clear()
    return redirect(url_for('login'))

# ==========================================
# RUTAS DE RECUPERACIÓN DE CONTRASEÑA
# ==========================================
@app.route("/recuperar-password", methods=["GET", "POST"])
def recuperar_password():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()

        cur = mysql.connection.cursor()
        # Dual-factor: match username AND email in Usuarios_Gerencia
        cur.execute(
            "SELECT usuario, email FROM Usuarios_Gerencia WHERE usuario = %s AND email = %s",
            (username, email)
        )
        row = cur.fetchone()

        if row:
            usuario_id = row[0]
            dest_email = row[1]
            # Generate 6-digit OTP — no URL required, bypasses proxy routing entirely
            pin = random.randint(100000, 999999)
            fecha_expiracion = datetime.now() + timedelta(minutes=30)

            cur.execute("""
                INSERT INTO TokenRecuperacion (usuario_id, token_hash, fecha_expiracion, usado)
                VALUES (%s, %s, %s, 0)
            """, (usuario_id, str(pin), fecha_expiracion))
            mysql.connection.commit()

            try:
                smtp_server = os.environ.get("SMTP_SERVER", "smtp.gmail.com")
                smtp_port = int(os.environ.get("SMTP_PORT", 587))
                remitente = os.environ.get("MAIL_USERNAME", "")
                password = os.environ.get("MAIL_PASSWORD", "")  # 16-char Google App Password

                html_body = (
                    f"<p>Su código de recuperación de 6 dígitos es: <strong>{pin}</strong></p>"
                    f"<p>Ingrese este código en el sistema para restablecer su contraseña.</p>"
                )

                msg = MIMEMultipart()
                msg['Subject'] = 'RectiTrack - Código de Recuperación'
                msg['From'] = remitente
                msg['To'] = dest_email
                msg.attach(MIMEText(html_body, 'html'))

                server = smtplib.SMTP(smtp_server, smtp_port, timeout=10)
                server.ehlo()
                server.starttls()
                server.ehlo()
                server.login(remitente, password)
                server.send_message(msg)
                server.quit()
                logging.info(f"OTP de recuperación enviado con éxito a {dest_email}")
            except Exception as smtp_err:
                logging.error(f"Error al enviar OTP de recuperación: {smtp_err}")

        cur.close()
        flash('Si los datos coinciden, se ha enviado un correo.', 'info')
        return redirect(url_for('resetear_password'))

    return render_template('recuperar_password.html')

@app.route("/reset-password", methods=["GET", "POST"])
def resetear_password():
    if request.method == "POST":
        otp = request.form.get("otp", "").strip()
        nueva_password = request.form.get("nueva_password", "")

        if not otp or not nueva_password:
            flash("Debe completar todos los campos.", "warning")
            return render_template('resetear_password.html')

        cur = mysql.connection.cursor()
        cur.execute("""
            SELECT id, usuario_id FROM TokenRecuperacion
            WHERE token_hash = %s AND usado = 0 AND fecha_expiracion > NOW()
        """, (otp,))
        row = cur.fetchone()

        if not row:
            cur.close()
            flash("El código OTP es inválido o ha expirado.", "danger")
            return render_template('resetear_password.html')

        usuario_id = row[1]
        passhash = generate_password_hash(nueva_password, method='scrypt', salt_length=16)
        cur.execute(
            "UPDATE Usuarios_Gerencia SET hash_password = %s WHERE usuario = %s",
            (passhash, usuario_id)
        )
        cur.execute(
            "UPDATE TokenRecuperacion SET usado = 1 WHERE token_hash = %s",
            (otp,)
        )
        mysql.connection.commit()
        cur.close()
        flash('Contraseña modificada con éxito. Ya puede ingresar.', 'success')
        return redirect(url_for('login'))

    return render_template('resetear_password.html')

# ==========================================
# RUTAS DE MÓDULOS GERENCIALES
# ==========================================
@app.route('/panel-gerente')
@require_gerente
def panel_gerente():
    cur = mysql.connection.cursor()
    # Fetch unread notifications
    cur.execute("""
        SELECT id_notificacion, mensaje, tipo, fecha_creacion, id_orden, id_tarea 
        FROM Notificaciones 
        WHERE leida = FALSE 
        ORDER BY fecha_creacion DESC
    """)
    notificaciones = cur.fetchall()
    
    # Check for engines > 30 days completed
    cur.execute("""
        SELECT ot.id_orden, m.codigo_qr, ot.fecha_terminado 
        FROM OrdenTrabajo ot
        JOIN Motor m ON ot.id_motor = m.id_motor
        WHERE ot.estado_general IN ('HECHO', 'TERMINADO') 
        AND ot.fecha_terminado IS NOT NULL
        AND DATEDIFF(NOW(), ot.fecha_terminado) > 30
    """)
    motores_antiguos = cur.fetchall()
    
    cur.close()
    return render_template('panel_gerente.html', notificaciones=notificaciones, motores_antiguos=motores_antiguos)

@app.route('/panel-gerente/registro-cliente', methods=['GET', 'POST'])
@require_gerente
def registro_cliente():
    if request.method == 'POST':
        dni = request.form.get('dni')
        es_nuevo = request.form.get('es_nuevo') == 'true'
        
        if not dni:
            flash("El DNI es obligatorio.")
            return render_template('registro_cliente.html')
        try:
            dni_val = int(dni)
            if dni_val < 100000:
                flash("El DNI debe tener al menos 6 dígitos.")
                return render_template('registro_cliente.html')
        except ValueError:
            flash("El DNI debe ser numérico.")
            return render_template('registro_cliente.html')

        cur = mysql.connection.cursor()
        
        if es_nuevo:
            nombre = request.form.get('nombre')
            apellido = request.form.get('apellido')
            telefono = request.form.get('telefono')
            email = request.form.get('email')
            
            # Credential Automation: Automatically map form data to generate credentials
            login_usr = request.form['apellido']
            password_usr = request.form['dni']
            
            if not nombre or not apellido or not telefono:
                flash("Para un nuevo cliente, todos los campos son obligatorios.")
                cur.close()
                return render_template('registro_cliente.html')
            
            cur.execute("SELECT dni FROM Cliente WHERE dni = %s", (dni,))
            if cur.fetchone():
                flash("Ya existe un cliente registrado con ese DNI.")
                cur.close()
                return render_template('registro_cliente.html')
                
            cur.execute("SELECT dni FROM Cliente WHERE login = %s", (login_usr,))
            if cur.fetchone():
                flash("El nombre de usuario para el cliente ya existe.")
                cur.close()
                return render_template('registro_cliente.html')
                
            try:
                passhash = generate_password_hash(password_usr, method='scrypt', salt_length=16)
                cur.execute("""
                    INSERT INTO Cliente (dni, nombre, apellido, telefono, email, login, password)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                """, (dni, nombre, apellido, telefono, email or None, login_usr, passhash))
                mysql.connection.commit()
                flash("Cliente registrado exitosamente.")
                
                # SMTP Integration: Dispatch email
                if email:
                    try:
                        remitente = os.environ.get("MAIL_USERNAME")
                        password = os.environ.get("MAIL_PASSWORD")

                        msg = MIMEMultipart()
                        msg['From'] = remitente
                        msg['To'] = email
                        msg['Subject'] = "Credenciales de Acceso - RectiTrack"
                        msg.attach(MIMEText(f"Bienvenido a RectiTrack.\n\nSus credenciales de acceso son:\nUsuario: {login_usr}\nContraseña: {password_usr}", 'plain'))

                        server = smtplib.SMTP('smtp.gmail.com', 587)
                        server.ehlo()
                        server.starttls()
                        server.ehlo()
                        server.login(remitente, password)
                        server.send_message(msg)
                        server.quit()
                        logging.info(f"Email de credenciales enviado con éxito a {email}")
                        flash("Se ha enviado un correo con las credenciales de acceso.", "success")
                    except Exception as smtp_err:
                        import traceback
                        traceback.print_exc()
                        logging.error(f"Error al enviar email de credenciales: {smtp_err}")
                        flash("Cliente guardado, pero falló el envío de correo.", "warning")
            except Exception as e:
                mysql.connection.rollback()
                logging.error(f"Error registering new client: {e}")
                flash(f"Error al registrar cliente: {e}")
                cur.close()
                return render_template('registro_cliente.html')
        else:
            cur.execute("SELECT dni FROM Cliente WHERE dni = %s", (dni,))
            if not cur.fetchone():
                flash("El cliente con el DNI ingresado no existe. Regístrelo como Nuevo Cliente.")
                cur.close()
                return render_template('registro_cliente.html')
        
        cur.close()
        return redirect(url_for('registro_motor', dni=dni))

    return render_template('registro_cliente.html')


@app.route('/panel-gerente/registro-motor', methods=['GET', 'POST'])
@require_gerente
def registro_motor():
    dni = request.args.get('dni')
    if not dni:
        flash("Debe identificar un cliente primero.", "warning")
        return redirect(url_for('registro_cliente'))
        
    cur = mysql.connection.cursor()
    cur.execute("SELECT dni, nombre, apellido, email, login FROM Cliente WHERE dni = %s", (dni,))
    cliente = cur.fetchone()
    if not cliente:
        cur.close()
        flash("Cliente no encontrado.", "danger")
        return redirect(url_for('registro_cliente'))
        
    qr_code_base64 = None
    codigo_qr_text = None
    qr_cliente_nombre = None
    qr_motor_marca_modelo = None
    qr_tipo_trabajo = None
    qr_fecha = None
    active_motor_id = None
    
    if request.method == 'POST':
        marca = request.form.get('marca')
        modelo = request.form.get('modelo')
        nro_serie_bloque = request.form.get('nro_serie_bloque')
        tipo_trabajo = request.form.get('tipo_trabajo')
        fecha_entrega_estimada = request.form.get('fecha_entrega_estimada')
        monto_total_str = request.form.get('monto_total')
        origen_repuestos = request.form.get('origen_repuestos')
        
        errors = []
        if not marca or len(marca.strip()) < 2:
            errors.append("La marca del motor debe tener al menos 2 caracteres.")
        if not modelo or len(modelo.strip()) < 2:
            errors.append("El modelo del motor debe tener al menos 2 caracteres.")
        if not nro_serie_bloque or len(nro_serie_bloque.strip()) < 3:
            errors.append("El número de serie del bloque es obligatorio.")
        if not tipo_trabajo or len(tipo_trabajo.strip()) < 3:
            errors.append("El tipo de trabajo es obligatorio.")
        if not fecha_entrega_estimada:
            errors.append("La fecha de entrega estimada es obligatoria.")
        else:
            try:
                datetime.strptime(fecha_entrega_estimada, '%Y-%m-%d')
            except ValueError:
                errors.append("Formato de fecha de entrega estimada inválido.")
        if not monto_total_str:
            errors.append("El presupuesto total es obligatorio.")
        else:
            try:
                monto_total = float(monto_total_str)
                if monto_total < 0:
                    errors.append("El presupuesto debe ser mayor o igual a 0.")
            except ValueError:
                errors.append("El presupuesto debe ser un número válido.")
        if not origen_repuestos or origen_repuestos not in ['TALLER', 'CLIENTE']:
            errors.append("El origen de repuestos no es válido.")
            
        if nro_serie_bloque:
            cur.execute("SELECT id_motor FROM Motor WHERE nro_serie_bloque = %s", (nro_serie_bloque.strip(),))
            if cur.fetchone():
                errors.append("Ya existe un motor registrado con ese número de serie.")
                
        if errors:
            for err in errors:
                flash(err)
        else:
            try:
                timestamp_str = datetime.now().strftime("%Y%m%d%H%M%S")
                codigo_qr_text = f"RT-{dni}-{nro_serie_bloque.strip()}-{timestamp_str}"
                
                cur.execute("""
                    INSERT INTO Motor (marca, modelo, nro_serie_bloque, dni_cliente, codigo_qr)
                    VALUES (%s, %s, %s, %s, %s)
                """, (marca.strip(), modelo.strip(), nro_serie_bloque.strip(), dni, codigo_qr_text))
                id_motor = cur.lastrowid
                active_motor_id = id_motor
                
                cur.execute("""
                    INSERT INTO OrdenTrabajo (fecha_ingreso, fecha_entrega_estimada, monto_total, saldo_pendiente, estado_general, origen_repuestos, id_motor)
                    VALUES (%s, %s, %s, %s, 'CREADO', %s, %s)
                """, (datetime.now(), fecha_entrega_estimada, monto_total, monto_total, origen_repuestos, id_motor))
                id_orden = cur.lastrowid
                
                cur.execute("SELECT id_operario FROM Operario LIMIT 1")
                op_row = cur.fetchone()
                cur.execute("SELECT id_area FROM Area LIMIT 1")
                area_row = cur.fetchone()
                if op_row and area_row:
                    cur.execute("""
                        INSERT INTO Tarea (descripcion_trabajo, estado_tarea, fecha_actualizacion, id_orden, id_operario, id_area)
                        VALUES (%s, 'PENDIENTE', %s, %s, %s, %s)
                    """, (tipo_trabajo.strip(), datetime.now(), id_orden, op_row[0], area_row[0]))
                
                mysql.connection.commit()
                
                qr = qrcode.QRCode(version=1, box_size=10, border=4)
                qr.add_data(codigo_qr_text)
                qr.make(fit=True)
                img = qr.make_image(fill_color="black", back_color="white")
                
                buf = io.BytesIO()
                img.save(buf, format="PNG")
                qr_bytes = buf.getvalue()
                qr_code_base64 = base64.b64encode(qr_bytes).decode('utf-8')
                
                qr_cliente_nombre = f"{cliente[1]} {cliente[2]}"
                qr_motor_marca_modelo = f"{marca.strip()} {modelo.strip()}"
                qr_tipo_trabajo = tipo_trabajo.strip()
                qr_fecha = datetime.now().strftime('%d/%m/%Y %H:%M')
                
                # SMTP Dispatch logic
                client_email = cliente[3]
                client_login = cliente[4]
                client_password = str(cliente[0]) # DNI is the password
                
                if client_email:
                    try:
                        remitente = os.environ.get("MAIL_USERNAME", "")
                        password = os.environ.get("MAIL_PASSWORD", "")

                        email_body = (
                            f"Hola {cliente[1]} {cliente[2]},\n\n"
                            f"Su motor {marca.strip()} {modelo.strip()} ha sido registrado exitosamente en RectiTrack.\n"
                            f"El número de orden es: {id_orden}.\n\n"
                            f"Puede realizar el seguimiento en tiempo real y consultar saldos ingresando al portal con sus credenciales:\n"
                            f"Usuario: {client_login}\n"
                            f"Contraseña: {client_password}\n\n"
                            f"Gracias por confiar en nuestros servicios.\nEquipo RectiTrack"
                        )

                        msg = MIMEText(email_body)
                        msg['Subject'] = 'RectiTrack - Motor Registrado y Credenciales'
                        msg['From'] = remitente
                        msg['To'] = client_email

                        server = smtplib.SMTP('smtp.gmail.com', 587, timeout=10)
                        server.ehlo()
                        server.starttls()
                        server.ehlo()
                        server.login(remitente, password)
                        server.send_message(msg)
                        server.quit()
                        logging.info(f"Email de registro de motor enviado con éxito a {client_email}")
                        flash("Motor registrado y credenciales enviadas al cliente.", "success")
                    except Exception as smtp_err:
                        import traceback
                        traceback.print_exc()
                        logging.error(f"Error al enviar email de registro de motor: {smtp_err}")
                        flash("Motor registrado, pero falló el envío del correo al cliente.", "warning")
                else:
                    flash("Motor registrado con éxito y QR generado. (El cliente no tiene email asociado)", "success")
                    
            except Exception as e:
                mysql.connection.rollback()
                logging.error(f"Error registering motor: {e}")
                flash(f"Error al registrar motor: {e}", "danger")
                
    cur.execute("""
        SELECT m.id_motor, m.marca, m.modelo, m.nro_serie_bloque, MAX(t.descripcion_trabajo)
        FROM Motor m
        JOIN OrdenTrabajo ot ON m.id_motor = ot.id_motor
        LEFT JOIN Tarea t ON ot.id_orden = t.id_orden
        WHERE m.dni_cliente = %s
        GROUP BY m.id_motor, m.marca, m.modelo, m.nro_serie_bloque
        ORDER BY m.id_motor DESC
    """, (dni,))
    motores = cur.fetchall()
    cur.close()
    
    return render_template(
        'registro_motor.html',
        cliente=cliente,
        motores=motores,
        active_motor_id=active_motor_id,
        qr_code_base64=qr_code_base64,
        codigo_qr_text=codigo_qr_text,
        qr_cliente_nombre=qr_cliente_nombre,
        qr_motor_marca_modelo=qr_motor_marca_modelo,
        qr_tipo_trabajo=qr_tipo_trabajo,
        qr_fecha=qr_fecha
    )

@app.route('/panel-gerente/asignar', methods=['GET', 'POST'])
@require_gerente
def asignar_tareas():
    cur = mysql.connection.cursor()
    
    if request.method == 'POST':
        id_orden = request.form.get('id_orden')
        id_operario = request.form.get('id_operario')
        id_area = request.form.get('id_area')
        descripcion = request.form.get('descripcion')

        try:
            cur.execute("""
                INSERT INTO Tarea (descripcion_trabajo, estado_tarea, fecha_actualizacion, id_orden, id_operario, id_area)
                VALUES (%s, 'PENDIENTE', %s, %s, %s, %s)
            """, (descripcion, datetime.now(), id_orden, id_operario, id_area))
            mysql.connection.commit()
            flash('Tarea asignada y registrada con Éxito.')
        except Exception as e:
            logging.error(f"Falla DML al insertar Tarea: {e}")
            flash('Error técnico al registrar la asignación.')
        finally:
            cur.close()
        return redirect(url_for('asignar_tareas'))

    cur.execute("SELECT id_area, nombre_area FROM Area")
    areas = cur.fetchall()
    
    cur.execute("SELECT id_operario, nombre, apellido FROM Operario")
    operarios = cur.fetchall()
    
    cur.execute("""
        SELECT ot.id_orden, m.codigo_qr, m.marca, m.modelo 
        FROM OrdenTrabajo ot 
        JOIN Motor m ON ot.id_motor = m.id_motor
        WHERE m.estado != 'TERMINADO'
    """)
    ordenes = cur.fetchall()
    cur.close()
    
    return render_template('asignar_tareas.html', areas=areas, operarios=operarios, ordenes=ordenes)

@app.route('/panel-gerente/stock')
@require_gerente
def gestionar_stock():
    return render_template('gestionar_stock.html')

@app.route('/panel-gerente/pagos')
@require_gerente
def gestionar_pagos():
    cur = mysql.connection.cursor()
    cur.execute("""
        SELECT ot.id_orden, m.codigo_qr, c.nombre, c.apellido, ot.monto_total, 
               COALESCE((SELECT SUM(monto) FROM Pago_Orden WHERE id_orden = ot.id_orden), 0) AS anticipo, 
               (ot.monto_total - COALESCE((SELECT SUM(monto) FROM Pago_Orden WHERE id_orden = ot.id_orden), 0)) AS saldo_pendiente
        FROM OrdenTrabajo ot 
        JOIN Motor m ON ot.id_motor = m.id_motor
        JOIN Cliente c ON m.dni_cliente = c.dni
    """)
    pagos = cur.fetchall()
    cur.close()
    return render_template('gestionar_pagos.html', pagos=pagos)

@app.route('/registrar_anticipo/<int:motor_id>', methods=['POST'])
@require_gerente
def registrar_anticipo(motor_id):
    monto_str = request.form.get('monto')
    if not monto_str:
        flash("Debe ingresar un monto válido.", "warning")
        return redirect(url_for('gestionar_pagos'))
        
    try:
        monto = float(monto_str)
        if monto <= 0:
            flash("El monto debe ser mayor a cero.", "warning")
            return redirect(url_for('gestionar_pagos'))
            
        cur = mysql.connection.cursor()
        cur.execute("INSERT INTO Pago_Orden (id_orden, monto, fecha_pago, metodo_pago) VALUES (%s, %s, NOW(), 'Efectivo')", (motor_id, monto))
        mysql.connection.commit()
        cur.close()
        flash("Anticipo registrado exitosamente. El saldo ha sido recalculado.", "success")
    except ValueError:
        flash("Monto inválido.", "danger")
    except Exception as e:
        mysql.connection.rollback()
        logging.error(f"Error registrando anticipo: {e}")
        flash("Error al registrar anticipo.", "danger")
        
    return redirect(url_for('gestionar_pagos'))

@app.route('/panel-gerente/progreso')
@require_gerente
def progreso_motores():
    cur = mysql.connection.cursor()
    cur.execute("""
        SELECT m.codigo_qr, o.nombre, o.apellido, 
               CASE 
                   WHEN ot.estado_general = 'HECHO' THEN 100 
                   WHEN ot.estado_general = 'EN_PROCESO' THEN 50 
                   ELSE 10 
               END AS porcentaje,
               ot.estado_general
        FROM OrdenTrabajo ot
        JOIN Motor m ON ot.id_motor = m.id_motor
        LEFT JOIN Tarea t ON ot.id_orden = t.id_orden
        LEFT JOIN Operario o ON t.id_operario = o.id_operario
        WHERE m.estado != 'TERMINADO'
        GROUP BY ot.id_orden
    """)
    progresos = cur.fetchall()
    cur.close()
    return render_template('progreso_motores.html', progresos=progresos)

@app.route('/api/status/gerente')
@require_gerente
def api_status_gerente():
    cur = mysql.connection.cursor()
    cur.execute("SELECT COUNT(*) FROM Notificaciones WHERE leida = FALSE")
    unread_notifications = cur.fetchone()[0]
    
    cur.execute("""
        SELECT COUNT(*)
        FROM OrdenTrabajo ot
        WHERE ot.estado_general IN ('HECHO', 'TERMINADO') 
        AND ot.fecha_terminado IS NOT NULL
        AND DATEDIFF(NOW(), ot.fecha_terminado) > 30
    """)
    old_engines = cur.fetchone()[0]
    cur.close()
    
    return {
        "unread_notifications": unread_notifications,
        "old_engines": old_engines
    }

@app.route('/api/notificaciones/<int:id_notificacion>/marcar-leida', methods=['POST'])
@require_gerente
def marcar_notificacion_leida(id_notificacion):
    cur = mysql.connection.cursor()
    cur.execute("UPDATE Notificaciones SET leida = TRUE WHERE id_notificacion = %s", (id_notificacion,))
    mysql.connection.commit()
    cur.close()
    return {"status": "ok"}

@app.route('/panel-operario')
@require_operario
def panel_operario():
    return render_template('panel_operario.html')

@app.route('/panel-operario/tareas')
@require_operario
def tareas_operario():
    cur = mysql.connection.cursor()
    cur.execute("""
        SELECT t.id_tarea, t.descripcion_trabajo, t.estado_tarea, t.fecha_actualizacion, 
               ot.id_orden, m.marca, m.modelo, m.codigo_qr, a.nombre_area, t.prioridad
        FROM Tarea t
        JOIN OrdenTrabajo ot ON t.id_orden = ot.id_orden
        JOIN Motor m ON ot.id_motor = m.id_motor
        JOIN Area a ON t.id_area = a.id_area
        WHERE t.id_operario = %s AND m.estado != 'TERMINADO'
        ORDER BY FIELD(t.prioridad, 'Alta', 'Media', 'Baja'), t.fecha_actualizacion DESC
    """, (session.get("operario_id"),))
    tareas = cur.fetchall()
    cur.close()
    return render_template('tareas_operario.html', tareas=tareas)

@app.route('/panel-operario/tareas/<int:id_tarea>', methods=['GET', 'POST'])
@require_operario
def detalle_tarea_operario(id_tarea):
    cur = mysql.connection.cursor()
    
    if request.method == 'POST':
        nuevo_estado = request.form.get('estado')
        observaciones = request.form.get('observaciones', '')
        is_final_task = request.form.get('is_final_task') == 'true'
        if nuevo_estado in ['PENDIENTE', 'EN_PROCESO', 'HECHO', 'FINALIZADA', 'PAUSADA']:
            try:
                cur.execute("""
                    UPDATE Tarea 
                    SET estado_tarea = %s, fecha_actualizacion = %s, observaciones = %s
                    WHERE id_tarea = %s AND id_operario = %s
                """, (nuevo_estado, datetime.now(), observaciones, id_tarea, session.get("operario_id")))
                
                cur.execute("SELECT id_orden FROM Tarea WHERE id_tarea = %s", (id_tarea,))
                order_row = cur.fetchone()
                if order_row:
                    id_orden = order_row[0]
                    ot_estado = 'EN_PROCESO' if nuevo_estado in ['EN_PROCESO', 'PAUSADA'] else ('HECHO' if nuevo_estado in ['HECHO', 'FINALIZADA'] else 'CREADO')
                    
                    if nuevo_estado in ['HECHO', 'FINALIZADA']:
                        cur.execute("UPDATE OrdenTrabajo SET estado_general = %s, fecha_terminado = NOW() WHERE id_orden = %s", (ot_estado, id_orden))
                        
                        # Trigger RF14: WhatsApp Alert
                        cur.execute("""
                            SELECT c.telefono, c.nombre, m.marca, m.modelo 
                            FROM Cliente c 
                            JOIN Motor m ON c.dni = m.dni_cliente 
                            WHERE m.id_motor = %s
                        """, (tarea[11],))
                        client_data = cur.fetchone()
                        if client_data:
                            msg = f"Hola {client_data[1]}, el trabajo en su motor {client_data[2]} {client_data[3]} ha sido finalizado. Puede pasar a retirarlo."
                            send_whatsapp_alert(client_data[0], msg)
                    else:
                        cur.execute("UPDATE OrdenTrabajo SET estado_general = %s WHERE id_orden = %s", (ot_estado, id_orden))
                    
                    if nuevo_estado == 'PAUSADA':
                        cur.execute("""
                            INSERT INTO Notificaciones (mensaje, tipo, id_orden, id_tarea) 
                            VALUES (%s, 'ALERTA', %s, %s)
                        """, (f"Tarea {id_tarea} pausada por operario. Obs: {observaciones}", id_orden, id_tarea))
                
                if is_final_task and nuevo_estado in ['HECHO', 'FINALIZADA']:
                    cur.execute("UPDATE Motor SET estado = 'TERMINADO' WHERE id_motor = (SELECT id_motor FROM OrdenTrabajo WHERE id_orden = %s)", (id_orden,))
                
                mysql.connection.commit()
                flash("Estado de la tarea y observaciones actualizados.")
            except Exception as e:
                mysql.connection.rollback()
                logging.error(f"Error updating task state: {e}")
                flash("Error al actualizar el estado de la tarea.")
        else:
            flash("Estado no válido.")
            
    cur.execute("""
        SELECT t.id_tarea, t.descripcion_trabajo, t.estado_tarea, t.fecha_actualizacion,
               ot.id_orden, m.marca, m.modelo, m.codigo_qr, a.nombre_area,
               c.nombre, c.apellido, m.id_motor, t.observaciones
        FROM Tarea t
        JOIN OrdenTrabajo ot ON t.id_orden = ot.id_orden
        JOIN Motor m ON ot.id_motor = m.id_motor
        JOIN Area a ON t.id_area = a.id_area
        JOIN Cliente c ON m.dni_cliente = c.dni
        WHERE t.id_tarea = %s AND t.id_operario = %s
    """, (id_tarea, session.get("operario_id")))
    tarea = cur.fetchone()
    cur.close()
    
    if not tarea:
        flash("Tarea no encontrada.")
        return redirect(url_for('tareas_operario'))
        
    return render_template('detalle_tarea_operario.html', tarea=tarea)

@app.route('/panel-operario/escanear', methods=['GET', 'POST'])
@require_operario
def escanear_operario():
    motor = None
    if request.method == 'POST':
        codigo_qr = request.form.get('codigo_qr')
        if codigo_qr:
            cur = mysql.connection.cursor()
            cur.execute("""
                SELECT m.codigo_qr
                FROM Motor m
                WHERE m.codigo_qr = %s OR m.nro_serie_bloque = %s
            """, (codigo_qr.strip(), codigo_qr.strip()))
            row = cur.fetchone()
            cur.close()
            if row:
                return redirect(url_for('escanear_motor', codigo_qr=row[0]))
            else:
                flash("No se encontró ningún motor con ese QR o Número de Serie.")
        else:
            flash("Debe ingresar un código QR.")
    return render_template('escanear_operario.html')

@app.route('/scan/<string:codigo_qr>', methods=['GET'])
@require_operario
def escanear_motor(codigo_qr):
    cur = mysql.connection.cursor()
    cur.execute("""
        SELECT m.id_motor, m.marca, m.modelo, m.codigo_qr, m.nro_serie_bloque, c.nombre, c.apellido, ot.estado_general, ot.fecha_ingreso, ot.origen_repuestos, ot.id_orden
        FROM Motor m
        JOIN Cliente c ON m.dni_cliente = c.dni
        LEFT JOIN OrdenTrabajo ot ON m.id_motor = ot.id_motor
        WHERE m.codigo_qr = %s
    """, (codigo_qr,))
    motor = cur.fetchone()
    
    if not motor:
        cur.close()
        flash("Motor no encontrado.")
        return redirect(url_for('escanear_operario'))
        
    cur.execute("""
        SELECT t.descripcion_trabajo, t.estado_tarea, t.fecha_actualizacion, a.nombre_area, o.nombre, o.apellido, t.observaciones
        FROM Tarea t
        JOIN Area a ON t.id_area = a.id_area
        JOIN Operario o ON t.id_operario = o.id_operario
        WHERE t.id_orden = %s
        ORDER BY t.fecha_actualizacion DESC
    """, (motor[10],))
    tareas = cur.fetchall()
    cur.close()
    
    return render_template('ficha_tecnica_motor.html', motor=motor, tareas=tareas)

@app.route('/api/status/operario')
@require_operario
def api_status_operario():
    cur = mysql.connection.cursor()
    cur.execute("SELECT COUNT(*) FROM Tarea WHERE id_operario = %s AND estado_tarea = 'PENDIENTE'", (session.get("operario_id"),))
    new_tasks = cur.fetchone()[0]
    cur.close()
    return {"new_tasks": new_tasks}

@app.route('/panel-cliente')
@require_cliente
def panel_cliente():
    cur = mysql.connection.cursor()
    cur.execute("""
        SELECT m.id_motor, m.marca, m.modelo, m.codigo_qr, 
               ot.id_orden, ot.fecha_ingreso, ot.fecha_entrega_estimada, 
               ot.monto_total, 
               (ot.monto_total - COALESCE((SELECT SUM(monto) FROM Pago_Orden WHERE id_orden = ot.id_orden), 0)) AS saldo_pendiente, 
               ot.estado_general
        FROM Motor m
        LEFT JOIN OrdenTrabajo ot ON m.id_motor = m.id_motor
        WHERE m.dni_cliente = %s
    """, (session.get("cliente_dni"),))
    motores = cur.fetchall()
    cur.close()
    return render_template('panel_cliente.html', motores=motores)

@app.route('/api/pagar/<int:id_orden>', methods=['POST'])
@require_cliente
def api_pagar_stub(id_orden):
    # RF15: Payment Integration Stub
    logging.info(f"Payment Gateway [STUB] - Generando preferencia de pago para orden {id_orden}")
    # In a real scenario, this would call MercadoPago API and return an init_point URL
    # Here we just mock a success URL or response
    return {"status": "success", "url": "#", "message": "Simulación de pago generada exitosamente."}

def send_whatsapp_alert(phone, message):
    # RF14: WhatsApp Integration Stub
    logging.info(f"WhatsApp Alert [STUB] - Sending to {phone}: {message}")

@app.route('/recuperar-contrasena', methods=['GET', 'POST'])
def recuperar_contrasena():
    if request.method == 'POST':
        email = request.form.get('email')
        if not email:
            flash("El correo electrónico es obligatorio.", "error")
            return redirect(url_for('recuperar_contrasena'))
            
        cur = mysql.connection.cursor()
        cur.execute("SELECT usuario FROM Usuarios_Gerencia WHERE email = %s", (email,))
        row = cur.fetchone()
        
        if row:
            usuario = row[0]
            # In a real system, generate a random password, hash it, update DB, and send email
            # For now, we simulate success
            flash(f"Se han enviado las instrucciones al correo: {email}", "success")
            logging.info(f"Recuperación de contraseña solicitada para gerente: {usuario}")
        else:
            flash("No se encontró ningún gerente con ese correo.", "error")
            
        cur.close()
        return redirect(url_for('login'))
        
    return render_template('recuperar_contrasena.html')

@app.route('/api/motor/<int:id_motor>/qr', methods=['GET'])
def get_motor_qr(id_motor):
    cur = mysql.connection.cursor()
    cur.execute("""
        SELECT m.codigo_qr, c.nombre, c.apellido, m.marca, m.modelo, ot.tipo_trabajo, ot.fecha_ingreso
        FROM Motor m
        JOIN Cliente c ON m.dni_cliente = c.dni
        LEFT JOIN OrdenTrabajo ot ON m.id_motor = ot.id_motor
        WHERE m.id_motor = %s
    """, (id_motor,))
    row = cur.fetchone()
    cur.close()
    
    if not row or not row[0]:
        return {"error": "QR no encontrado"}, 404
        
    qr_text = row[0]
    qr = qrcode.QRCode(version=1, box_size=10, border=4)
    qr.add_data(qr_text)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    qr_code_base64 = base64.b64encode(buf.getvalue()).decode('utf-8')
    
    fecha_str = row[6].strftime("%d/%m/%Y") if row[6] else "N/A"
    
    return {
        "qr_code_base64": qr_code_base64,
        "codigo_qr_text": qr_text,
        "qr_cliente_nombre": f"{row[1]} {row[2]}",
        "qr_motor_marca_modelo": f"{row[3]} {row[4]}",
        "qr_tipo_trabajo": row[5] or "Mantenimiento General",
        "qr_fecha": fecha_str
    }

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)