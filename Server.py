from flask import Flask, render_template, request, redirect, url_for, session
import os
import re
import sqlite3
import smtplib
import ssl
from email.message import EmailMessage
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired


def load_env_file(path=".env"):
    try:
        with open(path, "r", encoding="utf-8") as arquivo:
            for linha in arquivo:
                linha = linha.strip()
                if not linha or linha.startswith("#") or "=" not in linha:
                    continue
                chave, valor = linha.split("=", 1)
                os.environ.setdefault(chave.strip(), valor.strip().strip('"').strip("'"))
    except FileNotFoundError:
        pass


load_env_file()

app = Flask(__name__)

# Chave usada para proteger a sessão
app.secret_key = os.getenv("SECRET_KEY", "heitor e lindo")


def _get_bool_env(name, default):
    value = os.getenv(name, str(default)).strip().lower()
    return value in ["1", "true", "yes", "on"]


EMAIL_USER = os.getenv("EMAIL_USER", "").strip().lower()
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD", "").replace(" ", "").strip()
EMAIL_HOST = os.getenv("EMAIL_HOST", "smtp.gmail.com").strip()
EMAIL_PORT = int(os.getenv("EMAIL_PORT", "587"))
EMAIL_USE_TLS = _get_bool_env("EMAIL_USE_TLS", True)
EMAIL_FROM = os.getenv("EMAIL_FROM", EMAIL_USER).strip()

SERIALIZER_SALT = "email-confirmation-salt"
CONFIRMATION_TOKEN_EXPIRATION = 86400  # 24 horas
EMAIL_REGEX = re.compile(r"^[^@]+@[^@]+\.[^@]+$")


# =========================
# BANCO DE DADOS
# =========================


def conectar_banco():
    banco = sqlite3.connect("sistema.db")
    banco.row_factory = sqlite3.Row
    return banco


def criar_banco():
    banco = conectar_banco()
    cursor = banco.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS usuarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nome TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            senha TEXT NOT NULL,
            email_verificado INTEGER NOT NULL DEFAULT 0
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alunos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nome TEXT NOT NULL,
            idade INTEGER NOT NULL,
            nota REAL NOT NULL,
            usuario_id INTEGER NOT NULL,
            FOREIGN KEY (usuario_id) REFERENCES usuarios(id)
        )
    """)

    cursor.execute("PRAGMA table_info(usuarios)")
    columns = [row[1] for row in cursor.fetchall()]
    if "email_verificado" not in columns:
        cursor.execute("ALTER TABLE usuarios ADD COLUMN email_verificado INTEGER NOT NULL DEFAULT 0")

    banco.commit()
    banco.close()


def get_serializer():
    return URLSafeTimedSerializer(app.secret_key)


def send_confirmation_email(destino_email, token, nome):
    confirm_url = url_for("confirmar_email", token=token, _external=True)

    if not EMAIL_USER or not EMAIL_PASSWORD:
        mensagem = (
            "Configuração de e-mail não encontrada. "
            "Crie um arquivo .env com EMAIL_USER e EMAIL_PASSWORD "
            "ou defina as variáveis de ambiente antes de iniciar o app."
        )
        print(mensagem)
        return False, mensagem

    message = EmailMessage()
    message["Subject"] = "Confirme seu e-mail - Venda Online"
    message["From"] = EMAIL_FROM
    message["Reply-To"] = EMAIL_FROM
    message["To"] = destino_email

    body_text = f"""Olá {nome or ''},

Obrigado por criar sua conta em Venda Online.

Clique no link abaixo para confirmar seu e-mail:

{confirm_url}

Se você não criou essa conta, ignore esta mensagem.
"""

    body_html = f"""<html>
    <body style="font-family: Arial, sans-serif; color: #111; background: #f4f7f8; padding: 20px;">
      <div style="max-width:600px; margin: auto; background: #ffffff; border-radius: 14px; padding: 30px; box-shadow: 0 0 30px rgba(0,0,0,0.08);">
        <h2 style="color: #00a86b;">Olá {nome or ''},</h2>
        <p>Obrigado por criar sua conta em <strong>Venda Online</strong>.</p>
        <p>Clique no botão abaixo para confirmar seu e-mail:</p>
        <p style="text-align: center; margin: 35px 0;">
          <a href="{confirm_url}" style="display:inline-block; padding: 14px 28px; border-radius: 10px; background:#00a86b; color:#ffffff; text-decoration:none; font-weight:bold;">Confirmar meu e-mail</a>
        </p>
        <p>Se você não criou essa conta, apenas ignore esta mensagem.</p>
      </div>
    </body>
    </html>"""

    message.set_content(body_text)
    message.add_alternative(body_html, subtype="html")

    try:
        context = ssl.create_default_context()
        if EMAIL_USE_TLS:
            with smtplib.SMTP(EMAIL_HOST, EMAIL_PORT, timeout=30) as server:
                server.ehlo()
                server.starttls(context=context)
                server.ehlo()
                server.login(EMAIL_USER, EMAIL_PASSWORD)
                server.send_message(message)
        else:
            with smtplib.SMTP_SSL(EMAIL_HOST, EMAIL_PORT, context=context, timeout=30) as server:
                server.login(EMAIL_USER, EMAIL_PASSWORD)
                server.send_message(message)
        return True, None
    except smtplib.SMTPAuthenticationError:
        mensagem = (
            "Credenciais do Gmail rejeitadas. "
            "Use a senha de app do Google e não a senha normal da conta. "
            "Ative a verificação em duas etapas e gere a senha de app em myaccount.google.com/apppasswords."
        )
        print(mensagem)
        return False, mensagem
    except Exception as error:
        print("Erro ao enviar e-mail:", error)
        return False, str(error)


# =========================
# PÁGINA PRINCIPAL
# =========================

@app.route("/")
def inicio():
    return render_template("index.html")


# =========================
# CADASTRO
# =========================

@app.route("/cadastro", methods=["GET", "POST"])
def cadastro():
    if request.method == "POST":
        nome = request.form["nome"].strip()
        email = request.form["email"].strip().lower()
        senha = request.form["senha"]

        if not nome or not email or not senha:
            return render_template("cadastro.html", error="Todos os campos são obrigatórios.", nome=nome, email=email)

        if len(senha) < 6:
            return render_template("cadastro.html", error="A senha deve ter ao menos 6 caracteres.", nome=nome, email=email)

        if not EMAIL_REGEX.match(email):
            return render_template("cadastro.html", error="Informe um e-mail válido.", nome=nome, email=email)

        senha_hash = generate_password_hash(senha)
        banco = conectar_banco()

        try:
            banco.execute(
                """
                INSERT INTO usuarios (nome, email, senha, email_verificado)
                VALUES (?, ?, ?, 0)
                """,
                (nome, email, senha_hash)
            )
            banco.commit()
        except sqlite3.IntegrityError:
            banco.close()
            return render_template("cadastro.html", error="Esse e-mail já está cadastrado.", nome=nome, email=email)

        banco.close()
        token = get_serializer().dumps(email, salt=SERIALIZER_SALT)
        sent, error = send_confirmation_email(email, token, nome)

        if sent:
            return render_template("login.html", message="Conta criada! Verifique seu e-mail para ativar a conta.")

        return render_template(
            "login.html",
            error=f"Conta criada, mas não foi possível enviar o e-mail: {error}",
            email=email,
        )

    return render_template("cadastro.html")


# =========================
# LOGIN
# =========================

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"].strip().lower()
        senha = request.form["senha"]

        if not email or not senha:
            return render_template("login.html", error="Preencha e-mail e senha.", email=email)

        if not EMAIL_REGEX.match(email):
            return render_template("login.html", error="E-mail inválido.", email=email)

        banco = conectar_banco()
        usuario = banco.execute(
            """
            SELECT *
            FROM usuarios
            WHERE email = ?
            """,
            (email,)
        ).fetchone()
        banco.close()

        if not usuario or not check_password_hash(usuario["senha"], senha):
            return render_template("login.html", error="E-mail ou senha incorretos.", email=email)

        if not usuario["email_verificado"]:
            return render_template("login.html", error="Verifique seu e-mail antes de entrar.", show_resend=True, email=email)

        session["usuario_id"] = usuario["id"]
        session["usuario_nome"] = usuario["nome"]
        return redirect(url_for("inicio"))

    return render_template("login.html")


# =========================
# REENVIAR CONFIRMAÇÃO DE E-MAIL
# =========================

@app.route("/reenviar-confirmacao", methods=["GET", "POST"])
def reenviar_confirmacao():
    if request.method == "POST":
        email = request.form["email"].strip().lower()

        if not email or not EMAIL_REGEX.match(email):
            return render_template("reenviar_confirmacao.html", error="Informe um e-mail válido.", email=email)

        banco = conectar_banco()
        usuario = banco.execute(
            "SELECT * FROM usuarios WHERE email = ?",
            (email,)
        ).fetchone()
        banco.close()

        if usuario and not usuario["email_verificado"]:
            token = get_serializer().dumps(email, salt=SERIALIZER_SALT)
            sent, error = send_confirmation_email(email, token, usuario["nome"])
            if sent:
                return render_template("reenviar_confirmacao.html", message="E-mail de confirmação reenviado com sucesso. Verifique sua caixa de entrada.", email=email)
            return render_template("reenviar_confirmacao.html", error=f"Não foi possível enviar o e-mail de confirmação: {error}", email=email)

        return render_template("reenviar_confirmacao.html", message="Se esse e-mail estiver cadastrado e não confirmado, você receberá um novo link de confirmação.", email=email)

    return render_template("reenviar_confirmacao.html")


# =========================
# CONFIRMAÇÃO DE E-MAIL
# =========================

@app.route("/confirmar-email/<token>")
def confirmar_email(token):
    try:
        email = get_serializer().loads(token, salt=SERIALIZER_SALT, max_age=CONFIRMATION_TOKEN_EXPIRATION)
    except SignatureExpired:
        return render_template("confirmacao_expirada.html", expired=True)
    except BadSignature:
        return render_template("confirmacao_expirada.html", invalid=True)

    banco = conectar_banco()
    usuario = banco.execute(
        "SELECT * FROM usuarios WHERE email = ?",
        (email,)
    ).fetchone()

    if not usuario:
        banco.close()
        return render_template("confirmacao_expirada.html", invalid=True)

    if usuario["email_verificado"]:
        banco.close()
        return render_template("email_confirmado.html", already=True)

    banco.execute(
        "UPDATE usuarios SET email_verificado = 1 WHERE email = ?",
        (email,)
    )
    banco.commit()
    banco.close()

    return render_template("email_confirmado.html", success=True)


# =========================
# LOGOUT
# =========================

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# =========================
# PAINEL
# =========================

@app.route("/painel")
def painel():
    if "usuario_id" not in session:
        return redirect(url_for("login"))

    return f"""
        <h1>Login realizado!</h1>
        <p>Olá, {session["usuario_nome"]}!</p>
        <p>Você está logado.</p>
        <a href="{url_for("logout")}">Sair</a>
    """


# =========================
# ADICIONAR ALUNO
# =========================

@app.route("/aluno/adicionar", methods=["POST"])
def adicionar_aluno():
    if "usuario_id" not in session:
        return redirect(url_for("login"))

    try:
        nome = request.form["nome"]
        idade = int(request.form["idade"])
        nota = float(request.form["nota"])
    except (ValueError, KeyError):
        return "Dados inválidos."

    if idade < 0:
        return "A idade não pode ser negativa."

    if nota < 0 or nota > 10:
        return "A nota deve estar entre 0 e 10."

    banco = conectar_banco()
    banco.execute(
        """
        INSERT INTO alunos
        (nome, idade, nota, usuario_id)
        VALUES (?, ?, ?, ?)
        """,
        (
            nome,
            idade,
            nota,
            session["usuario_id"]
        )
    )
    banco.commit()
    banco.close()

    return redirect(url_for("painel"))


# =========================
# REMOVER ALUNO
# =========================

@app.route("/aluno/remover/<int:aluno_id>")
def remover_aluno(aluno_id):
    if "usuario_id" not in session:
        return redirect(url_for("login"))

    banco = conectar_banco()
    banco.execute(
        """
        DELETE FROM alunos
        WHERE id = ?
        AND usuario_id = ?
        """,
        (
            aluno_id,
            session["usuario_id"]
        )
    )
    banco.commit()
    banco.close()

    return redirect(url_for("painel"))


# =========================
# INICIAR
# =========================

@app.route("/comprar/essencial")
def comprar_essencial():
    if "usuario_id" not in session:
        return redirect(url_for("login"))
    return redirect("https://pay.kiwify.com.br/PLPL8Tq")


@app.route("/comprar/premium")
def comprar_premium():
    if "usuario_id" not in session:
        return redirect(url_for("login"))
    return redirect("https://pay.kiwify.com.br/bQAdEAS")


if __name__ == "__main__":
    criar_banco()
    app.run(debug=True)
