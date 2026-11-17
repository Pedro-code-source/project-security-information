#!/usr/bin/env bash
# Roteiro de comandos da demonstração (rodar na raiz do projeto, venv ativo)
set -u
echo "### 1) Regras customizadas (/rules): Caso 01, segredos, debug, falso positivo"
semgrep --config rules/ app.py --metrics=off
echo
echo "### 2) Registro oficial (slide 7), requer internet:"
echo "    semgrep --config=p/owasp-top-ten app.py"
echo
echo "### 3) Caso 02 (BOLA/IDOR): achados DENTRO da função get_document()"
semgrep --config rules/ app.py --metrics=off --json > /tmp/sg.json
python3 - <<'PY'
import ast, json
src = open("app.py").read()
fn = next(n for n in ast.walk(ast.parse(src))
          if isinstance(n, ast.FunctionDef) and n.name == "get_document")
res = json.load(open("/tmp/sg.json"))["results"]
hits = [r["check_id"] for r in res if fn.lineno <= r["start"]["line"] <= fn.end_lineno]
print(f"get_document() linhas {fn.lineno}-{fn.end_lineno}: {len(hits)} achado(s) -> {hits}")
PY
echo
echo "### 4) BÔNUS: heurística que apenas pede revisão manual"
semgrep --config rules-bonus/ app.py --metrics=off
