from flask import Flask, render_template, request, redirect, url_for, session
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# Chave usada para proteger a sessão
app.secret_key = "heitor e lindo"


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
            senha TEXT NOT NULL
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

    banco.commit()
    banco.close()


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

        nome = request.form["nome"]
        email = request.form["email"]
        senha = request.form["senha"]

        senha_hash = generate_password_hash(senha)

        banco = conectar_banco()

        try:

            banco.execute(
                """
                INSERT INTO usuarios (nome, email, senha)
                VALUES (?, ?, ?)
                """,
                (nome, email, senha_hash)
            )

            banco.commit()

        except sqlite3.IntegrityError:

            banco.close()

            return "Esse e-mail já está cadastrado."

        banco.close()

        return redirect(url_for("login"))

    return render_template("cadastro.html")


# =========================
# LOGIN
# =========================

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        email = request.form["email"]
        senha = request.form["senha"]

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

        if usuario and check_password_hash(usuario["senha"], senha):

            session["usuario_id"] = usuario["id"]
            session["usuario_nome"] = usuario["nome"]

            return redirect(url_for("inicio"))

        return "E-mail ou senha incorretos."

    return render_template("login.html")


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
