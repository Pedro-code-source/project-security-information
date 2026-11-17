# Demo Semgrep: app Flask propositalmente vulnerável

> **Uso acadêmico.** Roda só em `127.0.0.1:5000`. Todas as credenciais e chaves são **fictícias**. Nunca exponha em rede ou produção.

## Setup (uma vez)
```bash
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
mkdir -p instance
```

## Mapa slides ↔ código
| Slide | O que mostrar | Onde |
|---|---|---|
| 6 | App Flask local, tokens mockados | `app.py` (topo) |
| 7 | **Caso 01** SQL Injection detectado | `get_user()` · regra `demo.sql-concatenation-in-execute` |
| 8 | Impacto (bypass, vazamento, integridade) | `scripts/exploit_demo.py` |
| 9 | **Caso 02** BOLA/IDOR **não detectado** | `get_document()` · 0 achados |
| 10 | Complementaridade SAST/DAST/SCA | tabela do slide + etapa "outra ferramenta" abaixo |
| 5 | Shift-left | `.pre-commit-config.yaml`, `.github/workflows/semgrep.yml` |
| 11 | Autofix | seção "Autofix" abaixo |
| 12 | `/rules` | pasta `rules/` |

## Roteiro da demonstração (~8 min)
**Terminal A**: `python app.py`  (mantenha rodando)
**Terminal B**:

1. **Mostrar o código** de `get_user()` (Caso 01).
2. **Rodar o Semgrep**: `./scripts/run_semgrep.sh`
   Esperado (5 achados): `sql-concatenation-in-execute`, `sql-fstring-audit`, `hardcoded-jwt-secret`, `hardcoded-api-key`, `flask-debug-true`.
   Opcional online: `semgrep --config=p/owasp-top-ten app.py` (cite o resultado real que aparecer; os alertas do registro podem variar com a versão).
3. **Explicar e explorar (conceitual)**: `python scripts/exploit_demo.py`
   `x' OR '1'='1` retorna **todos** os usuários (bypass/vazamento).
4. **Falso positivo**: aponte `sql-fstring-audit` em `/report/<int:year>`. O Flask já converte para `int`, então não há injeção; a regra é sintática e não sabe disso. Resultado: ruído (fadiga de alertas, slide 2).
5. **Ponto cego (obrigatório)**: mostre `get_document()` e o passo 3 do script: **0 achados** dentro da função. Rode a segunda parte do `exploit_demo.py`: a Alice (id 1) lê o documento do Bob (id 2) e do Admin (id 3) só trocando o ID na URL.
6. **Por que não detectou**: a sintaxe é correta e o ORM é seguro. A falha é de **regra de negócio** (falta `doc.owner_id == usuário logado`). O Semgrep não sabe o que é "dono".
7. **Quem detectaria**: teste autorizado com **duas contas** (OWASP ZAP com *Access Control Testing*/Autorize no Burp Suite), testes automatizados de autorização, revisão de código/threat modeling.
8. **Correção**: rota `/api/v2/document/<id>`: o mesmo teste agora retorna **404**.
9. **Bônus**: `semgrep --config rules-bonus/ app.py` → heurística que só pede "confira o dono". Mostra que dá para *mitigar* com regra customizada, mas só quando já se conhece o padrão.

## Autofix (slide 11)
Exemplo: acrescentar `fix:` a uma regra, e rodar `semgrep --config rules/ --autofix app.py`. Para a demo, copie `app.py` antes (`cp app.py app.bak.py`) porque o comando altera o arquivo.

## Perguntas que a banca pode fazer
- **O que ele encontra?** Padrões sintáticos/dataflow dentro do código: injeções, segredos, APIs inseguras, configurações perigosas.
- **O que ele não encontra?** Falhas de lógica/autorização (BOLA/IDOR), config de servidor/infra em runtime, vulnerabilidades em dependências (SCA) e erros que só aparecem em execução.
- **Falso positivo?** Sim, `sql-fstring-audit` em `/report`. **Falso negativo?** Sim, BOLA.
