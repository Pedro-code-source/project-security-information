"""
Aplicação PROPOSITALMENTE VULNERÁVEL - uso exclusivo em demonstração acadêmica.
Roda apenas em 127.0.0.1:5000. Todas as credenciais/tokens são FICTÍCIOS.
NUNCA exponha esta aplicação em rede nem a use em produção.
"""
import sqlite3

from flask import Flask, request, jsonify
from flask_jwt_extended import (JWTManager, jwt_required, create_access_token,
                                get_jwt_identity)
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///demo.db"

# [VULN 3] Segredo hardcoded (FICTÍCIO) -> detectável por regra do Semgrep
app.config["JWT_SECRET_KEY"] = "FAKE-SECRET-KEY-do-not-use-123456"
FAKE_PAYMENT_API_KEY = "sk_test_FAKE0000000000000000000000"  # fictício

db = SQLAlchemy(app)
jwt = JWTManager(app)


class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(50))  # texto puro: só para a demo
    role = db.Column(db.String(20), default="user")


class Document(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    title = db.Column(db.String(100))
    content = db.Column(db.Text)

    def serialize(self):
        return {"id": self.id, "owner_id": self.owner_id,
                "title": self.title, "content": self.content}


def get_cursor():
    conn = sqlite3.connect("instance/demo.db")
    return conn.cursor()


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json(force=True)
    user = User.query.filter_by(name=data.get("name"),
                                password=data.get("password")).first()
    if not user:
        return jsonify(error="credenciais inválidas"), 401
    return jsonify(access_token=create_access_token(identity=str(user.id)))


# ---------------------------------------------------------------------------
# CASO 01 - DETECTADO: SQL Injection (slide 7)
# ---------------------------------------------------------------------------
@app.route("/user")
def get_user():
    name = request.args.get("name")
    cursor = get_cursor()
    # Concatenação perigosa detectada
    query = "SELECT * FROM users " \
            "WHERE name = '" + name + "'"
    cursor.execute(query)
    return jsonify(cursor.fetchall())


# ---------------------------------------------------------------------------
# CASO 02 - NÃO DETECTADO: BOLA / IDOR (slide 9)
# ---------------------------------------------------------------------------
@app.route("/api/document/<int:doc_id>")
@jwt_required()
def get_document(doc_id):
    # Sintaxe limpa, ORM seguro e parametrizado
    # Mas falta validação: doc pertence ao usuário logado?
    doc = Document.query.get(doc_id)
    if doc is None:
        return jsonify(error="não encontrado"), 404
    return jsonify(doc.serialize())


# Versão corrigida (usada na etapa de "correção" da demo)
@app.route("/api/v2/document/<int:doc_id>")
@jwt_required()
def get_document_fixed(doc_id):
    doc = Document.query.get(doc_id)
    if doc is None or str(doc.owner_id) != get_jwt_identity():
        return jsonify(error="não encontrado"), 404  # 404 evita enumeração
    return jsonify(doc.serialize())


# ---------------------------------------------------------------------------
# CASO 03 - FALSO POSITIVO: f-string em SQL com valor já tipado como int
# O Flask converte <int:year> antes; não há injeção, mas a regra sintática alerta.
# ---------------------------------------------------------------------------
@app.route("/report/<int:year>")
def report(year):
    cursor = get_cursor()
    cursor.execute(f"SELECT id, title FROM document WHERE id > {year}")
    return jsonify(cursor.fetchall())


def seed():
    db.drop_all()
    db.create_all()
    alice = User(name="alice", password="alice123", role="user")
    bob = User(name="bob", password="bob123", role="user")
    admin = User(name="admin", password="admin-FAKE-pass", role="admin")
    db.session.add_all([alice, bob, admin])
    db.session.commit()
    db.session.add_all([
        Document(owner_id=alice.id, title="Prontuário da Alice",
                 content="Dados fictícios da Alice"),
        Document(owner_id=bob.id, title="Prontuário do Bob",
                 content="Dados fictícios do Bob - CONFIDENCIAL"),
        Document(owner_id=admin.id, title="Relatório financeiro",
                 content="Dados fictícios financeiros"),
    ])
    db.session.commit()


if __name__ == "__main__":
    with app.app_context():
        seed()
    # [VULN 4] debug=True expõe console Werkzeug -> detectável pelo Semgrep
    app.run(host="127.0.0.1", port=5000, debug=True)
