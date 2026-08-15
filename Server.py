from flask import Flask, render_template, request, redirect, url_for, session, jsonify
import os
import json
import sqlite3
import secrets

from dotenv import load_dotenv
from werkzeug.security import generate_password_hash

import firebase_admin
from firebase_admin import credentials, auth


# =========================================================
# CONFIGURAÇÃO
# =========================================================

load_dotenv()

app = Flask(__name__)

app.secret_key = os.getenv(
    "SECRET_KEY",
    "troque-esta-chave-no-render"
)


# Segurança da sessão
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

app.config["SESSION_COOKIE_SECURE"] = (
    os.getenv("SESSION_COOKIE_SECURE", "false").lower()
    in ["1", "true", "yes", "on"]
)


# =========================================================
# FIREBASE ADMIN
# =========================================================

def inicializar_firebase():

    try:

        # Só retorna se o APP PADRÃO realmente existir.
        try:
            firebase_admin.get_app()
            print("Firebase Admin já estava inicializado.")
            return

        except ValueError:
            pass


        firebase_json = os.getenv(
            "FIREBASE_SERVICE_ACCOUNT_JSON"
        )


        if firebase_json:

            dados_credencial = json.loads(
                firebase_json
            )

            credencial = credentials.Certificate(
                dados_credencial
            )

        else:

            caminho_credencial = os.path.join(
                os.path.dirname(
                    os.path.abspath(__file__)
                ),
                "firebase-service-account.json"
            )

            credencial = credentials.Certificate(
                caminho_credencial
            )


        firebase_admin.initialize_app(
            credencial,
            {
                "projectId": "vendas-online-e98a2"
            }
        )

        print(
            "Firebase Admin inicializado com sucesso."
        )


    except Exception as erro:

        print(
            "ERRO AO INICIALIZAR FIREBASE ADMIN:",
            erro
        )

        raise

inicializar_firebase()


# =========================================================
# BANCO DE DADOS
# =========================================================

def conectar_banco():

    banco = sqlite3.connect("sistema.db")

    banco.row_factory = sqlite3.Row

    return banco


def criar_banco():

    banco = conectar_banco()

    cursor = banco.cursor()


    # -----------------------------------------------------
    # USUÁRIOS
    # -----------------------------------------------------

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS usuarios (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            nome TEXT NOT NULL,

            email TEXT UNIQUE NOT NULL,

            senha TEXT NOT NULL,

            email_verificado INTEGER NOT NULL DEFAULT 0

        )
    """)


    # -----------------------------------------------------
    # ALUNOS
    # -----------------------------------------------------

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alunos (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            nome TEXT NOT NULL,

            idade INTEGER NOT NULL,

            nota REAL NOT NULL,

            usuario_id INTEGER NOT NULL,

            FOREIGN KEY (usuario_id)
                REFERENCES usuarios(id)

        )
    """)


    # -----------------------------------------------------
    # VERIFICA COLUNAS ANTIGAS
    # -----------------------------------------------------

    cursor.execute(
        "PRAGMA table_info(usuarios)"
    )

    colunas = [
        linha[1]
        for linha in cursor.fetchall()
    ]


    if "email_verificado" not in colunas:

        cursor.execute("""
            ALTER TABLE usuarios
            ADD COLUMN email_verificado
            INTEGER NOT NULL DEFAULT 0
        """)


    # -----------------------------------------------------
    # ADICIONA FIREBASE UID
    # -----------------------------------------------------

    if "firebase_uid" not in colunas:

        cursor.execute("""
            ALTER TABLE usuarios
            ADD COLUMN firebase_uid TEXT
        """)


    banco.commit()

    banco.close()


# =========================================================
# PÁGINA PRINCIPAL
# =========================================================

@app.route("/")
def inicio():

    return render_template(
        "index.html"
    )


# =========================================================
# CADASTRO
# =========================================================

@app.route("/cadastro")
def cadastro():

    return render_template(
        "cadastro.html"
    )


# =========================================================
# LOGIN
# =========================================================

@app.route("/login")
def login():

    return render_template(
        "login.html"
    )


# =========================================================
# LOGIN FIREBASE → FLASK
# =========================================================

@app.route(
    "/firebase-login",
    methods=["POST"]
)
def firebase_login():

    try:

        dados = request.get_json(
            silent=True
        )


        if not dados:

            return jsonify({
                "success": False,
                "error": "Dados não enviados."
            }), 400


        id_token = dados.get(
            "idToken"
        )


        if not id_token:

            return jsonify({
                "success": False,
                "error": "Token do Firebase não enviado."
            }), 400


        # =================================================
        # VERIFICA TOKEN NO FIREBASE
        # =================================================

        token_decodificado = (
            auth.verify_id_token(id_token)
        )


        firebase_uid = token_decodificado.get(
            "uid"
        )

        email = token_decodificado.get(
            "email"
        )

        nome = (
            token_decodificado.get(
                "name"
            )
            or email
            or "Usuário"
        )

        email_verificado = (
            token_decodificado.get(
                "email_verified",
                False
            )
        )


        if not firebase_uid:

            return jsonify({
                "success": False,
                "error": "Token sem UID."
            }), 401


        if not email:

            return jsonify({
                "success": False,
                "error": "O Firebase não informou o e-mail."
            }), 401


        # =================================================
        # EXIGE E-MAIL VERIFICADO
        # =================================================

        if not email_verificado:

            return jsonify({
                "success": False,
                "error": "E-mail ainda não verificado.",
                "email_verified": False
            }), 403


        # =================================================
        # PROCURA USUÁRIO NO SQLITE
        # =================================================

        banco = conectar_banco()


        usuario = banco.execute(
            """
            SELECT *
            FROM usuarios
            WHERE firebase_uid = ?
            """,
            (
                firebase_uid,
            )
        ).fetchone()


        # =================================================
        # SE NÃO ENCONTROU PELO UID,
        # PROCURA PELO E-MAIL
        # =================================================

        if not usuario:

            usuario = banco.execute(
                """
                SELECT *
                FROM usuarios
                WHERE email = ?
                """,
                (
                    email.lower(),
                )
            ).fetchone()


        # =================================================
        # USUÁRIO AINDA NÃO EXISTE NO SQLITE
        # =================================================

        if not usuario:

            senha_temporaria = secrets.token_urlsafe(
                32
            )

            senha_hash = generate_password_hash(
                senha_temporaria
            )


            cursor = banco.execute(
                """
                INSERT INTO usuarios
                (
                    nome,
                    email,
                    senha,
                    email_verificado,
                    firebase_uid
                )
                VALUES (?, ?, ?, 1, ?)
                """,
                (
                    nome,
                    email.lower(),
                    senha_hash,
                    firebase_uid
                )
            )


            banco.commit()


            usuario_id = cursor.lastrowid


            usuario = banco.execute(
                """
                SELECT *
                FROM usuarios
                WHERE id = ?
                """,
                (
                    usuario_id,
                )
            ).fetchone()


        # =================================================
        # USUÁRIO JÁ EXISTE
        # =================================================

        else:

            banco.execute(
                """
                UPDATE usuarios
                SET
                    nome = ?,
                    email_verificado = 1,
                    firebase_uid = ?
                WHERE id = ?
                """,
                (
                    nome,
                    firebase_uid,
                    usuario["id"]
                )
            )


            banco.commit()


            usuario = banco.execute(
                """
                SELECT *
                FROM usuarios
                WHERE id = ?
                """,
                (
                    usuario["id"],
                )
            ).fetchone()


        banco.close()


        # =================================================
        # CRIA A SESSÃO DO FLASK
        # =================================================

        session.clear()


        session["usuario_id"] = usuario["id"]

        session["usuario_nome"] = usuario["nome"]

        session["usuario_email"] = usuario["email"]

        session["firebase_uid"] = firebase_uid


        return jsonify({
            "success": True,
            "message": "Login realizado com sucesso.",
            "redirect": url_for("inicio")
        })


    except auth.InvalidIdTokenError:

        return jsonify({
            "success": False,
            "error": "Token do Firebase inválido."
        }), 401


    except auth.ExpiredIdTokenError:

        return jsonify({
            "success": False,
            "error": "Token do Firebase expirado."
        }), 401


    except Exception as erro:

        print(
            "ERRO NO LOGIN FIREBASE:",
            erro
        )

        return jsonify({
            "success": False,
            "error": "Erro interno ao autenticar."
        }), 500


# =========================================================
# LOGOUT
# =========================================================

@app.route("/logout")
def logout():

    session.clear()

    return redirect(
        url_for("login")
    )


# =========================================================
# PAINEL
# =========================================================

@app.route("/painel")
def painel():

    if "usuario_id" not in session:

        return redirect(
            url_for("login")
        )


    return render_template(
        "painel.html"
    )


# =========================================================
# ADICIONAR ALUNO
# =========================================================

@app.route(
    "/aluno/adicionar",
    methods=["POST"]
)
def adicionar_aluno():

    if "usuario_id" not in session:

        return redirect(
            url_for("login")
        )


    try:

        nome = request.form["nome"]

        idade = int(
            request.form["idade"]
        )

        nota = float(
            request.form["nota"]
        )


    except (
        ValueError,
        KeyError
    ):

        return "Dados inválidos."


    if idade < 0:

        return "A idade não pode ser negativa."


    if nota < 0 or nota > 10:

        return "A nota deve estar entre 0 e 10."


    banco = conectar_banco()


    banco.execute(
        """
        INSERT INTO alunos
        (
            nome,
            idade,
            nota,
            usuario_id
        )
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


    return redirect(
        url_for("painel")
    )


# =========================================================
# REMOVER ALUNO
# =========================================================

@app.route(
    "/aluno/remover/<int:aluno_id>"
)
def remover_aluno(
    aluno_id
):

    if "usuario_id" not in session:

        return redirect(
            url_for("login")
        )


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


    return redirect(
        url_for("painel")
    )


# =========================================================
# COMPRAR PLANO ESSENCIAL
# =========================================================

@app.route(
    "/comprar/essencial"
)
def comprar_essencial():

    if "usuario_id" not in session:

        return redirect(
            url_for("login")
        )


    return redirect(
        "https://pay.kiwify.com.br/PLPL8Tq"
    )


# =========================================================
# COMPRAR PLANO PREMIUM
# =========================================================

@app.route(
    "/comprar/premium"
)
def comprar_premium():

    if "usuario_id" not in session:

        return redirect(
            url_for("login")
        )


    return redirect(
        "https://pay.kiwify.com.br/bQAdEAS"
    )


# =========================================================
# ESCOLHER O QUE VENDER
# =========================================================

@app.route("/escolher")
def escolher():

    if "usuario_id" not in session:
        return redirect(url_for("login"))

    return render_template(
        "escolher.html"
    )


# =========================================================
# PRODUTOS FÍSICOS
# =========================================================

@app.route("/produtos-fisicos")
def produtos_fisicos():

    if "usuario_id" not in session:
        return redirect(url_for("login"))

    return render_template(
        "produtos_fisicos.html"
    )


# =========================================================
# PRODUTOS ARTESANAIS
# =========================================================

@app.route("/produtos-artesanais")
def produtos_artesanais():

    if "usuario_id" not in session:
        return redirect(url_for("login"))

    return render_template(
        "produtos_artesanais.html"
    )


# =========================================================
# PRODUTOS DIGITAIS
# =========================================================

@app.route("/produtos-digitais")
def produtos_digitais():

    if "usuario_id" not in session:
        return redirect(url_for("login"))

    return render_template(
        "produtos_digitais.html"
    )


# =========================================================
# SERVIÇOS
# =========================================================

@app.route("/servicos")
def servicos():

    if "usuario_id" not in session:
        return redirect(url_for("login"))

    return render_template(
        "servicos.html"
    )


# =========================================================
# INICIAR
# =========================================================

criar_banco()


if __name__ == "__main__":

    app.run(
        debug=True
    )