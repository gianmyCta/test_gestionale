from flask import Flask, render_template, redirect, request, session, jsonify,flash, url_for,flash,render_template_string
import sqlite3
import hashlib
from datetime import datetime, date
import json
from functools import wraps
from flask import abort, session
from werkzeug.security import generate_password_hash, check_password_hash
import pandas as pd
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash
import os
import sys



db_path = '/home/MartiEngTesting/mysite/database2.db'



with sqlite3.connect(db_path) as conn:
    conn.execute('PRAGMA journal_mode=WAL;')



app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Cambia questa chiave segreta per una migliore sicurezza

#uso questa funzione pe verificare che l'utente sia admin e la applico dove serve
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        print("Controllo ruolo:", session.get('ruolo'))  # Debug
        if 'user_id' not in session or session.get('ruolo') != 'admin':
            abort(403)  # Accesso negato
        return f(*args, **kwargs)
    return decorated_function

@app.route('/setup_admin') #creata solo per resettare
@admin_required
def setup_admin():
    from werkzeug.security import generate_password_hash
    conn = sqlite3.connect(db_path)
    hashed = generate_password_hash('nuovapassword')
    conn.execute('INSERT OR REPLACE INTO utenti (id, username, password, ruolo) VALUES (?, ?, ?, ?)',
                 (1, 'admin', hashed, 'admin'))
    conn.commit()
    conn.close()
    return 'Admin aggiornato!'


@app.route('/check-session') #la uso in fase di sviluppo per visualizzare se il database acquisisce il ruolo giusto
def check_session():
    return jsonify(dict(session))

@app.route('/register', methods=['GET', 'POST'])
@admin_required
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Hash della password
        hashed_password = hashlib.sha256(password.encode()).hexdigest()

        # Inserisci nel DB con ruolo "user"
        connection = sqlite3.connect(db_path)
        cursor = connection.cursor()
        cursor.execute(
            'INSERT INTO utenti (username, password, ruolo) VALUES (?, ?, ?)',
            (username, hashed_password, 'user')
        )
        connection.commit()
        connection.close()

        return redirect('/login')

    return render_template('register.html')



# Funzione per verificare la password
def check_password(password, hashed_password):
    return hashlib.sha256(password.encode()).hexdigest() == hashed_password

# Funzione per ottenere il report mensile delle prenotazioni
def get_monthly_report():
    connection = sqlite3.connect(db_path)
    connection.row_factory = sqlite3.Row
    # Query per ottenere il numero di prenotazioni per mese
    query = '''
    SELECT strftime('%Y-%m', data_pr) AS month, COUNT(*) AS count
    FROM prenotazioni
    GROUP BY month
    ORDER BY month DESC
    '''
    result = connection.execute(query).fetchall()
    connection.close()
    return result

# Rotta per il login
from werkzeug.security import check_password_hash

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        connection = sqlite3.connect(db_path)
        connection.row_factory = sqlite3.Row
        user = connection.execute('SELECT * FROM utenti WHERE username = ?', (username,)).fetchone()
        connection.close()

        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['ruolo'] = user['ruolo']

            return redirect('/')
        else:
            return 'Username o password errati', 401

    return render_template('login.html')


# Rotta per il logout
@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')

from datetime import datetime, date

@app.route('/notifiche')
@admin_required
def notifiche():
    if 'user_id' not in session:
        return redirect('/login')

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row

    # Recupera tutte le prenotazioni recenti (es. ultime 10 o tutte)
    notifiche = conn.execute(
        "SELECT * FROM prenotazioni ORDER BY data_pr DESC LIMIT 20"
    ).fetchall()
    conn.close()

    # 🟢 Segna tutte le prenotazioni come "lette" aggiornando il timestamp
    session['notifiche_lette_at'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    return render_template('notifiche.html', notifiche=notifiche)



# Pagina principale



@app.route('/api/nuove_prenotazioni')
def nuove_prenotazioni_api():
    if 'user_id' not in session:
        return jsonify({'count': 0})

    # Ottieni timestamp dell'ultima visita notifiche
    ultima_visita = session.get('notifiche_lette_at', '1970-01-01 00:00:00')

    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM prenotazioni WHERE datetime(data_pr) > datetime(?)", (ultima_visita,))
    count = cur.fetchone()[0]
    conn.close()

    return jsonify({'count': count})



@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect('/login')

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row

    if session.get('ruolo') == 'admin':
        # Admin vede tutte le prenotazioni
        prenotazioni = conn.execute('SELECT * FROM prenotazioni').fetchall()

        ultime_viste = session.get('ultima_visita')
        if ultime_viste:
            nuove = conn.execute(
                "SELECT COUNT(*) FROM prenotazioni WHERE data_pr > ?",
                (ultime_viste,)
            ).fetchone()[0]
        else:
            nuove = 0

    else:
        # Utente normale vede solo le sue prenotazioni
        username = session['username']
        prenotazioni = conn.execute(
            'SELECT * FROM prenotazioni WHERE id_partner = ?',
            (username,)
        ).fetchall()

        ultime_viste = session.get('ultima_visita')
        if ultime_viste:
            nuove = conn.execute(
                "SELECT COUNT(*) FROM prenotazioni WHERE id_partner = ? AND data_pr > ?",
                (username, ultime_viste)
            ).fetchone()[0]
        else:
            nuove = 0

    # Aggiorna data/ora ultima visita
    session['ultima_visita'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    conn.close()
    return render_template('index.html', prenotazioni=prenotazioni, nuove_prenotazioni=nuove)


# Eliminazione di una prenotazione
@app.route('/<int:idx>/delete', methods=('POST',))
@admin_required
def delete(idx):
    if 'user_id' not in session:
        return redirect('/login')

    connection = sqlite3.connect(db_path)
    connection.row_factory = sqlite3.Row
    connection.execute('DELETE FROM prenotazioni WHERE id_prenotazione=?', (idx,))
    connection.commit()
    connection.close()
    return redirect('/')

# Creazione di una prenotazione


@app.route('/create', methods=('GET', 'POST'))
def create():
    if 'user_id' not in session:
        return redirect('/login')

    # Connessione al database per recuperare i servizi
    connection = sqlite3.connect(db_path)
    connection.row_factory = sqlite3.Row
    servizi = connection.execute('SELECT nome_servizio FROM servizio').fetchall()
    connection.close()

    if request.method == 'POST':
        partner = session['username']
        nome = request.form['nome_cliente']
        quantita = request.form['quantita']
        servizio = request.form['servizio']
        note = request.form['note']
        data_pr = request.form['data_pr']
        data_tour = request.form['data_tour']

        # Estrai il mese dalla data di prenotazione
        mese_prenotazione = datetime.strptime(data_pr, '%Y-%m-%d').strftime('%Y-%m')

        # Connessione al database per inserire la prenotazione
        connection = sqlite3.connect(db_path)
        connection.row_factory = sqlite3.Row
        connection.execute(
            'INSERT INTO prenotazioni (id_partner, nome_cliente, quantita, servizio, note, data_pr, data_tour, mese) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
            (partner, nome, quantita, servizio, note, data_pr, data_tour, mese_prenotazione)
        )
        connection.commit()
        connection.close()

        flash('Prenotazione creata con successo!', 'success')
        return redirect('/')  # Puoi cambiare questa rotta con la pagina che desideri

    return render_template('create.html', servizi=servizi)



@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    connection = sqlite3.connect(db_path)
    connection.row_factory = sqlite3.Row

    # Recupera i filtri selezionati
    partner_filter = request.args.get('partner', '')
    mese_filter = request.args.get('mese', '')
    servizio_filter = request.args.get('servizio', '')

    # Costruisci la query per recuperare le prenotazioni in base ai filtri
    query = 'SELECT * FROM prenotazioni WHERE 1=1'
    params = []

    if partner_filter:
        query += ' AND id_partner = ?'
        params.append(partner_filter)
    if mese_filter:
        query += ' AND mese = ?'
        params.append(mese_filter)
    if servizio_filter:
        query += ' AND servizio = ?'
        params.append(servizio_filter)

    # Esegui la query con i parametri
    prenotazioni = connection.execute(query, params).fetchall()

        # Calcola il riepilogo
    totale_prenotazioni = len(prenotazioni)
    totale_quantita = sum([int(pren['quantita']) for pren in prenotazioni])  # Assicurati che la quantità sia un intero


    # Recupera i dati dei filtri
    partner_ids = connection.execute('SELECT DISTINCT id_partner FROM prenotazioni').fetchall()
    mesi = connection.execute('SELECT DISTINCT mese FROM prenotazioni').fetchall()
    servizi = connection.execute('SELECT DISTINCT servizio FROM prenotazioni').fetchall()

    connection.close()

    return render_template('dashboard.html',
                           prenotazioni=prenotazioni,
                           partner_ids=partner_ids,
                           mesi=mesi,
                           servizi=servizi,
                           totale_prenotazioni=totale_prenotazioni,
                           totale_quantita=totale_quantita)


# Creazione di un servizio
@app.route('/pannello_servizi', methods=('GET', 'POST'))
@admin_required
def pannello_servizi():
    if 'user_id' not in session:
        return redirect('/login')

    if request.method == 'POST':
        nome_servizio = request.form['nome_servizio']
        commissione = request.form['commissione']



        connection = sqlite3.connect(db_path)
        connection.row_factory = sqlite3.Row
        connection.execute(
            'INSERT INTO servizio (nome_servizio, commissione) VALUES (?, ?)',
            (nome_servizio, commissione)
        )
        connection.commit()
        connection.close()
        return redirect('/')

    return render_template('pannello_servizi.html')

@app.route('/servizi')
@admin_required
def servizi():
    if 'user_id' not in session:
        return redirect('/login')

    # Connessione al database
    connection = sqlite3.connect(db_path)
    connection.row_factory = sqlite3.Row

    # Recupera tutti i servizi
    tutti_servizi = connection.execute('SELECT * FROM servizio').fetchall()

    # Recupera ID dei servizi unici (anche se non sembra utile senza contesto)
    servizi_id = connection.execute('SELECT DISTINCT id FROM servizio').fetchall()

    # Recupera i nomi dei servizi unici
    nomi_servizi = connection.execute('SELECT DISTINCT nome_servizio FROM servizio ORDER BY id DESC').fetchall()

    connection.close()

    # Passa i dati al template
    return render_template('servizi.html', tutti_servizi=tutti_servizi, servizi_id=servizi_id, nomi_servizi=nomi_servizi)


@app.route('/modifica_servizio/<int:id>', methods=['POST'])
@admin_required
def modifica_servizio(id):
    if 'user_id' not in session:
        return redirect('/login')

    nome_servizio = request.form['nome_servizio']
    commissione = request.form['commissione']

    connection = sqlite3.connect(db_path)
    connection.execute('''
        UPDATE servizio
        SET nome_servizio = ?, commissione = ?
        WHERE id = ?
    ''', (nome_servizio, commissione, id))
    connection.commit()
    connection.close()

    return redirect('/servizi')

@app.route('/aggiungi_servizio', methods=['POST'])
@admin_required
def aggiungi_servizio():
    if 'user_id' not in session:
        return redirect('/login')

    nome_servizio = request.form['nome_servizio']
    commissione = request.form['commissione']

    connection = sqlite3.connect(db_path)
    try:
        connection.execute('''
            INSERT INTO servizio (nome_servizio, commissione)
            VALUES (?, ?)
        ''', (nome_servizio, commissione))
        connection.commit()
        flash("Servizio aggiunto con successo!", "success")
    except sqlite3.IntegrityError:
        flash("Errore: Servizio già esistente!", "danger")
    connection.close()

    return redirect('/servizi')

@app.route('/elimina_servizio/<int:id>', methods=['POST'])
@admin_required
def elimina_servizio(id):
    if 'user_id' not in session:
        return redirect('/login')

    connection = sqlite3.connect(db_path)
    connection.execute('''
        DELETE FROM servizio
        WHERE id = ?
    ''', (id,))
    connection.commit()
    connection.close()

    flash("Servizio eliminato con successo!", "success")
    return redirect('/servizi')

@app.route('/form_servizio', methods=['GET', 'POST'])
@admin_required
def form_servizio():
    if 'user_id' not in session:
        return redirect('/login')

    # Connessione al database
    connection = sqlite3.connect(db_path)
    connection.row_factory = sqlite3.Row

    # Recupera i nomi dei servizi dalla tabella 'servizio'
    servizi = connection.execute('SELECT nome_servizio FROM servizio').fetchall()
    connection.close()

    # Gestisci il form di invio, se il metodo è POST
    if request.method == 'POST':
        # Logica per gestire l'invio del form
        servizio_selezionato = request.form['servizio']
        # Aggiungi qui la logica per il servizio selezionato
        flash(f"Servizio {servizio_selezionato} selezionato con successo!", "success")
        return redirect('/servizi')

    # Passa i servizi al template
    return render_template('servizi.html', servizi=servizi)

@app.route('/utenti')
def utenti():
    if 'user_id' not in session:
        return redirect('/login')

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    utenti = conn.execute('SELECT * FROM utenti').fetchall()
    conn.close()
    return render_template('pannello_utenti.html', utenti=utenti)


@app.route('/aggiungi_utente', methods=['POST'])
@admin_required
def aggiungi_utente():
    if 'user_id' not in session:
        return redirect('/login')

    username = request.form['username']
    password = request.form['password']
    hashed = generate_password_hash(password)

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row

    # Controlla se l'username esiste già
    existing_user = conn.execute('SELECT * FROM utenti WHERE username = ?', (username,)).fetchone()

    if existing_user:
        flash('Username già esistente. Scegli un altro.', 'danger')
        conn.close()
        return redirect('/utenti')

    # Altrimenti inserisce il nuovo utente
    conn.execute('INSERT INTO utenti (username, password) VALUES (?, ?)', (username, hashed))
    conn.commit()
    conn.close()
    flash('Utente creato con successo.', 'success')
    return redirect('/utenti')


@app.route('/elimina_utente/<int:id>', methods=['POST'])
def elimina_utente(id):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    user = conn.execute('SELECT * FROM utenti WHERE id = ?', (id,)).fetchone()

    if user and user['username'] == 'admin':
        flash("Non puoi eliminare l'utente admin!", 'danger')
    else:
        conn.execute('DELETE FROM utenti WHERE id = ?', (id,))
        conn.commit()
        flash("Utente eliminato con successo.", 'success')

    conn.close()
    return redirect('/utenti')

from flask import flash

@app.route('/modifica_utente/<int:id>', methods=['POST'])
@admin_required
def modifica_utente(id):
    if 'user_id' not in session:
        return redirect('/login')

    username = request.form['username']
    password = request.form['password']
    conn = sqlite3.connect(db_path)

    if password.strip():
        hashed = generate_password_hash(password)
        conn.execute('UPDATE utenti SET username = ?, password = ? WHERE id = ?', (username, hashed, id))
    else:
        conn.execute('UPDATE utenti SET username = ? WHERE id = ?', (username, id))

    conn.commit()
    conn.close()

    flash('✅ Utente modificato con successo!', 'success')
    return redirect('/utenti')



@app.route('/importa_utenti', methods=['POST'])
@admin_required
def importa_utenti():
    if 'user_id' not in session:
        return redirect('/login')

    file = request.files['file']

    if not file:
        flash("Nessun file selezionato.", "danger")
        return redirect('/utenti')

    filename = secure_filename(file.filename)
    ext = filename.split('.')[-1].lower()

    # Legge il file in base all'estensione
    try:
        if ext == 'csv':
            df = pd.read_csv(file)
        elif ext in ['xlsx', 'xls']:
            df = pd.read_excel(file)
        else:
            flash("Formato file non supportato. Usa .xlsx, .xls o .csv.", "danger")
            return redirect('/utenti')
    except Exception as e:
        flash(f"Errore durante la lettura del file: {e}", "danger")
        return redirect('/utenti')

    # Connessione al database
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    aggiunti = 0
    duplicati = 0

    for _, row in df.iterrows():
        username = str(row['username']).strip()
        password = str(row['password']).strip()

        if username and password:
            existing_user = cursor.execute('SELECT * FROM utenti WHERE username = ?', (username,)).fetchone()

            if not existing_user:
                hashed = generate_password_hash(password)
                cursor.execute('INSERT INTO utenti (username, password) VALUES (?, ?)', (username, hashed))
                aggiunti += 1
            else:
                duplicati += 1

    conn.commit()
    conn.close()

    flash(f"✅ {aggiunti} utenti importati. ⚠️ {duplicati} duplicati ignorati.", "success")
    return redirect('/utenti')


# Funzione per connettersi al database
def get_db_connection():
    conn = sqlite3.connect(db_path)  # Sostituisci con il percorso del tuo database SQLite
    conn.row_factory = sqlite3.Row  # Per ottenere un dizionario per ogni riga
    return conn

@app.route('/fatturazione', methods=['GET', 'POST'])
def fatturazione():
    conn = get_db_connection()

    # Variabili di filtro (default: tutti i partner e mese)
    partner_filter = request.args.get('partner', '')
    mese_filter = request.args.get('mese', '')

    # Query per ottenere i partner, mesi e commissioni raggruppati
    query = """
        SELECT strftime('%Y-%m', p.data_pr) AS mese,
               p.id_partner,
               SUM(p.quantita) AS totale_quantita,
               SUM(s.commissione * p.quantita) AS totale_commissioni
        FROM prenotazioni p
        JOIN servizio s ON p.Servizio = s.nome_servizio
        WHERE (p.id_partner = ? OR ? = '') AND
              (strftime('%Y-%m', p.data_pr) = ? OR ? = '')
        GROUP BY strftime('%Y-%m', p.data_pr), p.id_partner
        ORDER BY strftime('%Y-%m', p.data_pr) DESC;
    """

    # Esegui la query con i filtri
    result = conn.execute(query, (partner_filter, partner_filter, mese_filter, mese_filter)).fetchall()

    # Recupera i partner disponibili per il filtro
    partner_query = "SELECT DISTINCT id_partner FROM prenotazioni"
    partner_ids = conn.execute(partner_query).fetchall()

    # Recupera i mesi disponibili per il filtro
    mese_query = "SELECT DISTINCT strftime('%Y-%m', data_pr) AS mese FROM prenotazioni"
    mesi = conn.execute(mese_query).fetchall()

    # Chiudi la connessione al database
    conn.close()

    # Passa i dati al template
    return render_template('fatturazione.html',
                           risultati=result,
                           partner_ids=partner_ids,
                           mesi=mesi,
                           partner_filter=partner_filter,
                           mese_filter=mese_filter)

@app.route('/convalida/<int:id_prenotazione>', methods=['POST'])
@admin_required
def convalida_prenotazione(id_prenotazione):
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute("UPDATE prenotazioni SET stato = 'convalidato' WHERE id_prenotazione = ?", (id_prenotazione,))
    conn.commit()
    conn.close()
    flash("Prenotazione convalidata con successo!", "success")
    return redirect(request.referrer or url_for('visualizza_prenotazioni'))

@app.route('/api/convalida/<int:pren_id>', methods=['POST'])
@admin_required
def convalida_ajax(pren_id):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    try:
        cursor.execute("UPDATE prenotazioni SET stato = 'convalidato' WHERE id_prenotazione = ?", (pren_id,))
        conn.commit()
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})
    finally:
        conn.close()

from flask import jsonify

@app.route('/api/prenotazioni')
def api_prenotazioni():
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    cur.execute("SELECT * FROM prenotazioni ORDER BY data_pr DESC")
    rows = cur.fetchall()

    prenotazioni = []
    for row in rows:
        prenotazioni.append({
            "id_prenotazione": row["id_prenotazione"],
            "id_partner": row["id_partner"],
            "nome_cliente": row["nome_cliente"],
            "quantita": row["quantita"],
            "servizio": row["servizio"],
            "note": row["note"],
            "data_pr": row["data_pr"],
            "data_tour": row["data_tour"],
            "stato": row["stato"]
        })

    return jsonify(prenotazioni)


# Rotta API per ottenere il report mensile in formato JSON
@app.route('/api/monthly_report', methods=['GET'])
def api_monthly_report():
    monthly_report = get_monthly_report()
    return jsonify(monthly_report)






if __name__ == "__main__":
    app.run(debug=True)
