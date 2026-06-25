import os
import io
import base64
import logging
import qrcode
import smtplib
from email.mime.text import MIMEText
from datetime import datetime
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_mysqldb import MySQL
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash

# Configuración del Logger
logging.basicConfig(format='%(asctime)s - RECTITRACK - %(levelname)s - %(message)s', level=logging.INFO)

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
            cur.execute("SELECT hash_password FROM Usuarios_Gerencia WHERE usuario = %s", (usuario,))
            row = cur.fetchone()
            cur.close()
            
            if row and check_password_hash(row[0], password):
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
# RUTAS DE MÓDULOS GERENCIALES
# ==========================================
@app.route('/panel-gerente')
@require_gerente
def panel_gerente():
    return render_template('panel_gerente.html')

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
            login_usr = request.form.get('login')
            password_usr = request.form.get('password')
            
            if not nombre or not apellido or not telefono or not login_usr or not password_usr:
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
        flash("Debe identificar un cliente primero.")
        return redirect(url_for('registro_cliente'))
        
    cur = mysql.connection.cursor()
    cur.execute("SELECT dni, nombre, apellido FROM Cliente WHERE dni = %s", (dni,))
    cliente = cur.fetchone()
    if not cliente:
        cur.close()
        flash("Cliente no encontrado.")
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
                
                flash("Motor registrado con éxito y QR generado.")
            except Exception as e:
                mysql.connection.rollback()
                logging.error(f"Error registering motor: {e}")
                flash(f"Error al registrar motor: {e}")
                
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
               (ot.monto_total - ot.saldo_pendiente) AS anticipo, ot.saldo_pendiente
        FROM OrdenTrabajo ot 
        JOIN Motor m ON ot.id_motor = m.id_motor
        JOIN Cliente c ON m.dni_cliente = c.dni
    """)
    pagos = cur.fetchall()
    cur.close()
    return render_template('gestionar_pagos.html', pagos=pagos)

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
        GROUP BY ot.id_orden
    """)
    progresos = cur.fetchall()
    cur.close()
    return render_template('progreso_motores.html', progresos=progresos)

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
               ot.id_orden, m.marca, m.modelo, m.codigo_qr, a.nombre_area
        FROM Tarea t
        JOIN OrdenTrabajo ot ON t.id_orden = ot.id_orden
        JOIN Motor m ON ot.id_motor = m.id_motor
        JOIN Area a ON t.id_area = a.id_area
        WHERE t.id_operario = %s
        ORDER BY t.fecha_actualizacion DESC
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
        if nuevo_estado in ['PENDIENTE', 'EN_PROCESO', 'HECHO', 'FINALIZADA']:
            try:
                cur.execute("""
                    UPDATE Tarea 
                    SET estado_tarea = %s, fecha_actualizacion = %s 
                    WHERE id_tarea = %s AND id_operario = %s
                """, (nuevo_estado, datetime.now(), id_tarea, session.get("operario_id")))
                
                cur.execute("SELECT id_orden FROM Tarea WHERE id_tarea = %s", (id_tarea,))
                order_row = cur.fetchone()
                if order_row:
                    id_orden = order_row[0]
                    ot_estado = 'EN_PROCESO' if nuevo_estado == 'EN_PROCESO' else ('HECHO' if nuevo_estado in ['HECHO', 'FINALIZADA'] else 'CREADO')
                    cur.execute("""
                        UPDATE OrdenTrabajo 
                        SET estado_general = %s 
                        WHERE id_orden = %s
                    """, (ot_estado, id_orden))
                
                mysql.connection.commit()
                flash("Estado de la tarea actualizado.")
            except Exception as e:
                mysql.connection.rollback()
                logging.error(f"Error updating task state: {e}")
                flash("Error al actualizar el estado de la tarea.")
        else:
            flash("Estado no válido.")
            
    cur.execute("""
        SELECT t.id_tarea, t.descripcion_trabajo, t.estado_tarea, t.fecha_actualizacion,
               ot.id_orden, m.marca, m.modelo, m.codigo_qr, a.nombre_area,
               c.nombre, c.apellido, m.id_motor
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
                SELECT m.id_motor, m.marca, m.modelo, m.codigo_qr, c.nombre, c.apellido, ot.estado_general
                FROM Motor m
                JOIN Cliente c ON m.dni_cliente = c.dni
                LEFT JOIN OrdenTrabajo ot ON m.id_motor = ot.id_motor
                WHERE m.codigo_qr = %s OR m.nro_serie_bloque = %s
            """, (codigo_qr.strip(), codigo_qr.strip()))
            motor = cur.fetchone()
            cur.close()
            if motor:
                flash(f"Motor encontrado: {motor[1]} {motor[2]} de {motor[4]} {motor[5]}.")
            else:
                flash("No se encontró ningún motor con ese QR o Número de Serie.")
        else:
            flash("Debe ingresar un código QR.")
    return render_template('escanear_operario.html', motor=motor)

@app.route('/panel-cliente')
@require_cliente
def panel_cliente():
    cur = mysql.connection.cursor()
    cur.execute("""
        SELECT m.id_motor, m.marca, m.modelo, m.codigo_qr, 
               ot.id_orden, ot.fecha_ingreso, ot.fecha_entrega_estimada, 
               ot.monto_total, ot.saldo_pendiente, ot.estado_general
        FROM Motor m
        LEFT JOIN OrdenTrabajo ot ON m.id_motor = ot.id_motor
        WHERE m.dni_cliente = %s
    """, (session.get("cliente_dni"),))
    motores = cur.fetchall()
    cur.close()
    return render_template('panel_cliente.html', motores=motores)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)