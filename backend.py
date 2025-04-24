import sqlite3
import pandas as pd
import re
import sqlparse
import json
import subprocess
import tempfile
import os
import tkinter as tk
from tkinter import ttk, scrolledtext
from tkinter import messagebox

# Criação do banco em memória
conn = sqlite3.connect(':memory:')
cursor = conn.cursor()

# Criar uma tabela de exemplo
cursor.execute('''
CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    email TEXT UNIQUE
)
''')

# Inserir alguns dados para teste
cursor.execute("INSERT INTO users (name, email) VALUES ('John Doe', 'john@example.com')")
cursor.execute("INSERT INTO users (name, email) VALUES ('Jane Smith', 'jane@example.com')")
conn.commit()

# Biblioteca para validação de SQL
class SQLValidator:
    def _init_(self):
        # Palavras-chave por dialeto
        self.keywords = {
            'sqlite': ['CREATE', 'TABLE', 'SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'ALTER', 'FROM', 'WHERE', 'GROUP BY', 'HAVING', 'ORDER BY', 'PRIMARY KEY', 'FOREIGN KEY', 'JOIN', 'INDEX', 'UNIQUE', 'NOT NULL', 'DEFAULT', 'CHECK'],
            'mysql': ['CREATE', 'TABLE', 'SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'ALTER', 'FROM', 'WHERE', 'GROUP BY', 'HAVING', 'ORDER BY', 'PRIMARY KEY', 'FOREIGN KEY', 'JOIN', 'INDEX', 'UNIQUE', 'NOT NULL', 'DEFAULT', 'CHECK', 'ENGINE', 'AUTO_INCREMENT', 'TRIGGER', 'BEFORE', 'AFTER', 'FOR EACH ROW', 'BEGIN', 'END', 'DELIMITER'],
            'postgresql': ['CREATE', 'TABLE', 'SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'ALTER', 'FROM', 'WHERE', 'GROUP BY', 'HAVING', 'ORDER BY', 'PRIMARY KEY', 'FOREIGN KEY', 'JOIN', 'INDEX', 'UNIQUE', 'NOT NULL', 'DEFAULT', 'CHECK', 'SERIAL', 'TRIGGER', 'BEFORE', 'AFTER', 'FOR EACH ROW', 'LANGUAGE', 'PLPGSQL', 'FUNCTION', 'RETURNS TRIGGER', 'BEGIN', 'END'],
            'oracle': ['CREATE', 'TABLE', 'SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'ALTER', 'FROM', 'WHERE', 'GROUP BY', 'HAVING', 'ORDER BY', 'PRIMARY KEY', 'FOREIGN KEY', 'JOIN', 'INDEX', 'UNIQUE', 'NOT NULL', 'DEFAULT', 'CHECK', 'SEQUENCE', 'TRIGGER', 'FOR EACH ROW', 'DECLARE', 'BEGIN', 'END', 'EXCEPTION', 'WHEN', 'OTHERS', 'THEN'],
            'tsql': ['CREATE', 'TABLE', 'SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'ALTER', 'FROM', 'WHERE', 'GROUP BY', 'HAVING', 'ORDER BY', 'PRIMARY KEY', 'FOREIGN KEY', 'JOIN', 'INDEX', 'UNIQUE', 'NOT NULL', 'DEFAULT', 'CHECK', 'IDENTITY', 'TRIGGER', 'FOR', 'AFTER', 'INSTEAD OF', 'BEGIN', 'END', 'AS', 'SET', 'NOCOUNT'],
        }
        
        # Padrões de expressões regulares para validar estruturas específicas
        self.patterns = {
            'trigger_mysql': r'CREATE\s+TRIGGER\s+(\w+)\s+(BEFORE|AFTER)\s+(INSERT|UPDATE|DELETE)\s+ON\s+(\w+(\.\w+)?)\s+FOR\s+EACH\s+ROW\s+(BEGIN\s+.?\s+END)(?:\s;)?',
            'trigger_oracle': r'CREATE\s+(?:OR\s+REPLACE\s+)?TRIGGER\s+(\w+(?:\.\w+)?)\s+(BEFORE|AFTER)\s+(INSERT|UPDATE|DELETE)\s+ON\s+(\w+(?:\.\w+)?)\s+(?:FOR\s+EACH\s+ROW\s+)?(?:WHEN\s+\(.?\)\s+)?(?:DECLARE\s+.?\s+)?BEGIN\s+.?\s+END(?:\s;)?',
            'trigger_postgresql': r'CREATE\s+(?:OR\s+REPLACE\s+)?TRIGGER\s+(\w+)\s+(BEFORE|AFTER)\s+(INSERT|UPDATE|DELETE)\s+ON\s+(\w+(?:\.\w+)?)\s+(?:FOR\s+EACH\s+ROW\s+)?EXECUTE\s+(?:PROCEDURE|FUNCTION)\s+(\w+(?:\.\w+)?)',
            'trigger_tsql': r'CREATE\s+(?:OR\s+ALTER\s+)?TRIGGER\s+(\w+(?:\.\w+)?)\s+ON\s+(\w+(?:\.\w+)?)\s+(AFTER|INSTEAD\s+OF)\s+(INSERT|UPDATE|DELETE)(?:\s+AS)?\s+BEGIN\s+.?\s+END(?:\s;)?',
            'query_select': r'SELECT\s+(?:(?:ALL|DISTINCT)\s+)?(?:TOP\s+\d+\s+)?((?:.*?))(?:\s+FROM\s+)',
            'query_insert': r'INSERT\s+INTO\s+(\w+(?:\.\w+)?)\s*(?:\((.?)\))?\s(?:VALUES|SELECT|DEFAULT\s+VALUES)',
            'query_update': r'UPDATE\s+(\w+(?:\.\w+)?)\s+SET\s+(.?)(?:\s+WHERE\s+|\s$)',
            'query_delete': r'DELETE\s+FROM\s+(\w+(?:\.\w+)?)',
            'create_table': r'CREATE\s+TABLE\s+(\w+(?:\.\w+)?)\s*\((.*?)\)',
        }
        
    def is_trigger(self, sql, dialect):
        """Verifica se o SQL é um trigger"""
        sql = " ".join(sql.split()).upper()  # Normaliza espaços e converte para maiúsculas
        return sql.strip().startswith('CREATE TRIGGER') or sql.strip().startswith('CREATE OR REPLACE TRIGGER')
    
    def validate_trigger(self, sql, dialect):
        """Valida a sintaxe de um trigger baseado no dialeto"""
        issues = []
        sql_upper = sql.upper()
        
        # Verificações básicas para todos os dialetos
        if not re.search(r'CREATE\s+(?:OR\s+REPLACE\s+)?TRIGGER', sql_upper, re.IGNORECASE):
            issues.append("O trigger deve começar com 'CREATE TRIGGER' ou 'CREATE OR REPLACE TRIGGER'")
        
        # Verificação de ON para a tabela
        if not re.search(r'ON\s+\w+', sql_upper, re.IGNORECASE):
            issues.append("Especifique a tabela após a cláusula 'ON'")
        
        # Verificação de BEGIN/END para o corpo do trigger
        if dialect in ['mysql', 'oracle', 'tsql']:
            if not re.search(r'BEGIN', sql_upper, re.IGNORECASE):
                issues.append("O corpo do trigger deve começar com 'BEGIN'")
            if not re.search(r'END', sql_upper, re.IGNORECASE):
                issues.append("O corpo do trigger deve terminar com 'END'")
        
        # Verificações específicas por dialeto
        if dialect == 'mysql':
            if not re.search(r'(BEFORE|AFTER)\s+(INSERT|UPDATE|DELETE)', sql_upper, re.IGNORECASE):
                issues.append("Especifique o momento (BEFORE/AFTER) e o evento (INSERT/UPDATE/DELETE)")
            if not re.search(r'FOR\s+EACH\s+ROW', sql_upper, re.IGNORECASE):
                issues.append("Inclua 'FOR EACH ROW' para triggers row-level")
                
        elif dialect == 'oracle':
            if not re.search(r'(BEFORE|AFTER)\s+(INSERT|UPDATE|DELETE)', sql_upper, re.IGNORECASE):
                issues.append("Especifique o momento (BEFORE/AFTER) e o evento (INSERT/UPDATE/DELETE)")
            if ':NEW' in sql or ':OLD' in sql:
                if not re.search(r'FOR\s+EACH\s+ROW', sql_upper, re.IGNORECASE):
                    issues.append("Ao usar :NEW ou :OLD, inclua 'FOR EACH ROW'")
            
        elif dialect == 'postgresql':
            if not re.search(r'(BEFORE|AFTER|INSTEAD\s+OF)\s+(INSERT|UPDATE|DELETE)', sql_upper, re.IGNORECASE):
                issues.append("Especifique o momento (BEFORE/AFTER/INSTEAD OF) e o evento (INSERT/UPDATE/DELETE)")
            if not re.search(r'EXECUTE\s+(PROCEDURE|FUNCTION)', sql_upper, re.IGNORECASE):
                issues.append("Especifique a função/procedimento a ser executada com 'EXECUTE FUNCTION' ou 'EXECUTE PROCEDURE'")

        elif dialect == 'tsql':
            if not re.search(r'(AFTER|INSTEAD\s+OF)\s+(INSERT|UPDATE|DELETE)', sql_upper, re.IGNORECASE):
                issues.append("Especifique o momento (AFTER/INSTEAD OF) e o evento (INSERT/UPDATE/DELETE)")
        
        # Verificações de balanceamento de parênteses
        if sql.count('(') != sql.count(')'):
            issues.append("Parênteses desbalanceados no código")
            
        # Verificação de sintaxe usando sqlparse
        try:
            parsed = sqlparse.parse(sql)
            if not parsed:
                issues.append("Não foi possível analisar a sintaxe SQL")
        except Exception as e:
            issues.append(f"Erro ao analisar sintaxe: {str(e)}")
            
        return issues
    
    def validate_query(self, sql, dialect):
        """Valida uma query SQL genérica"""
        issues = []
        
        # Normaliza o SQL
        sql_normalized = " ".join(sql.split())
        
        # Verifica se tem ponto e vírgula no final
        if not sql_normalized.rstrip().endswith(';'):
            issues.append("Adicione ponto e vírgula (;) ao final da query")
        
        # Verificações específicas por tipo de query
        if re.search(r'^\s*SELECT', sql_normalized, re.IGNORECASE):
            if not re.search(r'FROM\s+\w+', sql_normalized, re.IGNORECASE) and not re.search(r'SELECT\s+\d+', sql_normalized, re.IGNORECASE):
                issues.append("Especifique uma tabela após a cláusula FROM")
                
        elif re.search(r'^\s*INSERT', sql_normalized, re.IGNORECASE):
            if not re.search(r'INTO\s+\w+', sql_normalized, re.IGNORECASE):
                issues.append("Especifique uma tabela após INSERT INTO")
            if not re.search(r'VALUES\s*\(', sql_normalized, re.IGNORECASE) and not re.search(r'SELECT', sql_normalized, re.IGNORECASE):
                issues.append("Especifique VALUES ou uma subconsulta SELECT após INSERT INTO")
                
        elif re.search(r'^\s*UPDATE', sql_normalized, re.IGNORECASE):
            if not re.search(r'SET\s+\w+\s*=', sql_normalized, re.IGNORECASE):
                issues.append("Especifique as colunas a serem atualizadas após a cláusula SET")
                
        elif re.search(r'^\s*DELETE', sql_normalized, re.IGNORECASE):
            if not re.search(r'FROM\s+\w+', sql_normalized, re.IGNORECASE):
                issues.append("Especifique uma tabela após DELETE FROM")
                
        # Verificações de balanceamento
        if sql.count('(') != sql.count(')'):
            issues.append("Parênteses desbalanceados na query")
            
        # Verificação de sintaxe usando sqlparse
        try:
            parsed = sqlparse.parse(sql)
            if not parsed:
                issues.append("Não foi possível analisar a sintaxe SQL")
        except Exception as e:
            issues.append(f"Erro ao analisar sintaxe: {str(e)}")
            
        return issues

# Função para usar SQLFluff para corrigir código SQL
def corrigir_com_sqlfluff(sql, dialect='sqlite'):
    # Criar um arquivo temporário para o SQL
    with tempfile.NamedTemporaryFile(mode='w', suffix='.sql', delete=False) as temp_file:
        temp_file.write(sql)
        temp_path = temp_file.name
    
    try:
        # Rodar sqlfluff fix no arquivo temporário
        result = subprocess.run(
            ['sqlfluff', 'fix', '--dialect', dialect, temp_path, '--force'],
            capture_output=True,
            text=True
        )
        
        # Executar também o lint para obter análise de erros
        lint_result = subprocess.run(
            ['sqlfluff', 'lint', '--dialect', dialect, temp_path, '--format', 'json'],
            capture_output=True,
            text=True
        )
        
        # Ler o arquivo corrigido
        with open(temp_path, 'r') as fixed_file:
            sql_corrigido = fixed_file.read()
        
        # Tentar carregar resultados de lint como JSON
        try:
            lint_json = json.loads(lint_result.stdout)
            return sql_corrigido, lint_json, result.stderr
        except:
            return sql_corrigido, None, result.stderr
    except Exception as e:
        return sql, None, f"Erro ao usar SQLFluff: {str(e)}"
    finally:
        # Limpar o arquivo temporário
        if os.path.exists(temp_path):
            os.remove(temp_path)

# Função para correções manuais que o SQLFluff pode não pegar
def correções_adicionais(sql):
    correcoes = []
    sql_original = sql
    
    # Correção de palavras-chave comuns
    palavras_chave = {
        'creat ': 'create ',
        'tablee': 'table',
        'inserttt': 'insert',
        'ino': 'into',
        'slect': 'select',
        'selectt': 'select',
        'form': 'from',
        'frmo': 'from',
        'wherre': 'where',
        'wher': 'where',
        'intt': 'int',
        'primaryy': 'primary',
        'kay': 'key',
        'kye': 'key',
        'interger': 'integer',
        'triggerr': 'trigger',
        'trigge': 'trigger',
        'befor': 'before',
        'aftr': 'after',
        'aftter': 'after',
        'upadte': 'update',
        'updat': 'update',
        'insrt': 'insert',
        'dlete': 'delete',
        'begn': 'begin',
        'en': 'end',
        'iff': 'if',
        'els': 'else',
        'theen': 'then',
        'declar': 'declare',
        'vachar': 'varchar',
        'varcharr': 'varchar',
        'varchr': 'varchar'
    }
    
    for incorreto, correto in palavras_chave.items():
        if incorreto.lower() in sql.lower():
            pattern = re.compile(re.escape(incorreto), re.IGNORECASE)
            sql = pattern.sub(correto, sql)
            correcoes.append(f"Corrigido: '{incorreto}' para '{correto}'")
    
    # Corrigir PRIMARY KAY para PRIMARY KEY
    if "primary kay" in sql.lower():
        sql = re.sub(r'(?i)primary\s+kay', 'PRIMARY KEY', sql)
        correcoes.append("Corrigido: 'PRIMARY KAY' para 'PRIMARY KEY'")
    
    # Correção de vírgulas ausentes entre colunas em INSERTs
    if "insert into" in sql.lower():
        # Encontra a lista de colunas entre parênteses
        colunas_match = re.search(r'insert\s+into\s+\w+\s*\((.*?)\)', sql, re.IGNORECASE)
        if colunas_match:
            colunas = colunas_match.group(1)
            # Verifica se há palavras sem vírgulas entre elas
            nova_colunas = re.sub(r'(\w+)\s+(\w+)', r'\1, \2', colunas)
            if nova_colunas != colunas:
                sql = sql.replace(colunas, nova_colunas)
                correcoes.append("Corrigido: adicionadas vírgulas ausentes entre colunas no INSERT")
    
    # Correção de vírgulas ausentes entre valores
    values_match = re.search(r'values\s*\((.*?)\)', sql, re.IGNORECASE)
    if values_match:
        valores = values_match.group(1)
        # Procura strings consecutivas sem vírgula
        nova_valores = re.sub(r"'([^']?)'\s+'([^']?)'", r"'\1', '\2'", valores)
        if nova_valores != valores:
            sql = sql.replace(valores, nova_valores)
            correcoes.append("Corrigido: adicionadas vírgulas ausentes entre valores no VALUES")
    
    # Correção de parênteses ausentes em declarações VARCHAR
    def fix_varchar_parentheses(match):
        text = match.group(0)
        if not re.search(r'\)$', text):
            return text + ')'
        return text
    
    sql = re.sub(r'varchar\(\d+(?!\))', fix_varchar_parentheses, sql, flags=re.IGNORECASE)
    
    # Correções específicas para triggers
    if "create trigger" in sql.lower():
        # Adiciona BEGIN se estiver faltando antes de declarações
        if re.search(r'for\s+each\s+row\s+(?!begin)', sql, re.IGNORECASE):
            sql = re.sub(r'(for\s+each\s+row\s+)(?!begin)', r'\1BEGIN ', sql, flags=re.IGNORECASE)
            correcoes.append("Corrigido: adicionado 'BEGIN' ausente após FOR EACH ROW")
        
        # Adiciona END se não estiver presente no final do trigger
        if not re.search(r'end\s*;?\s*$', sql, re.IGNORECASE):
            if not sql.strip().endswith(';'):
                sql = sql.rstrip() + " END;"
            else:
                sql = re.sub(r';$', ' END;', sql)
            correcoes.append("Corrigido: adicionado 'END;' ausente no final do trigger")
    
    if sql != sql_original:
        return sql, correcoes
    else:
        return sql, []

# Função para analisar erros comuns do SQLite
def analisar_erro(erro, dialect='sqlite'):
    erro = erro.lower()
    
    # Erros comuns em todos os dialetos
    if "syntax error" in erro:
        return "Erro de sintaxe. Verifique vírgulas, parênteses e palavras-chave SQL."
    elif "no such table" in erro:
        return "Tabela não encontrada. Verifique se a tabela foi criada corretamente."
    elif "near" in erro:
        palavra = re.findall(r'near "(.*?)"', erro)
        if palavra:
            return f"Erro próximo a '{palavra[0]}'. Verifique se há erro de digitação ou falta de pontuação."
    elif "unique constraint failed" in erro:
        return "Violação de unicidade. Verifique se o valor já existe em uma coluna UNIQUE."
    elif "datatype mismatch" in erro:
        return "Tipo de dado incompatível. Verifique se está inserindo os tipos corretos (ex: texto, número)."
    
    # Erros específicos por dialeto
    if dialect == 'mysql':
        if "unknown column" in erro:
            return "Coluna não encontrada. Verifique o nome da coluna e se ela existe na tabela."
        elif "duplicate entry" in erro:
            return "Entrada duplicada. Verifique os valores únicos nas colunas com restrição UNIQUE ou PRIMARY KEY."
    
    elif dialect == 'postgresql':
        if "column" in erro and "does not exist" in erro:
            return "Coluna não encontrada. Verifique se a coluna existe na tabela."
        elif "violates not-null constraint" in erro:
            return "Violação de restrição NOT NULL. A coluna não pode ser NULL."
    
    elif dialect == 'oracle':
        if "ora-00942" in erro:
            return "Tabela ou view não existe. Verifique o nome da tabela."
        elif "ora-00904" in erro:
            return "Identificador inválido. Verifique nomes de colunas e tabelas."
    
    elif dialect == 'tsql':
        if "invalid object name" in erro:
            return "Nome de objeto inválido. Verifique se a tabela ou view existe."
        elif "invalid column name" in erro:
            return "Nome de coluna inválido. Verifique se a coluna existe na tabela."
    
    return "Erro não identificado com sugestão automática."

def mostrar_guia_trigger(dialect):
    help_text = ""
    
    if dialect == 'mysql':
        help_text = """
Sintaxe MySQL:
CREATE TRIGGER nome_trigger
{BEFORE | AFTER} {INSERT | UPDATE | DELETE} ON nome_tabela
FOR EACH ROW
BEGIN
    -- corpo do trigger
END;

Exemplo:
CREATE TRIGGER atualiza_estoque
AFTER INSERT ON vendas
FOR EACH ROW
BEGIN
    UPDATE estoque 
    SET quantidade = quantidade - NEW.quantidade
    WHERE produto_id = NEW.produto_id;
END;
        """
    
    elif dialect == 'postgresql':
        help_text = """
Sintaxe PostgreSQL:
CREATE TRIGGER nome_trigger
{BEFORE | AFTER} {INSERT | UPDATE | DELETE} ON nome_tabela
FOR EACH ROW
EXECUTE FUNCTION nome_funcao();

-- A função deve ser definida separadamente:
CREATE OR REPLACE FUNCTION nome_funcao()
RETURNS TRIGGER AS $$
BEGIN
    -- corpo da função
    RETURN NEW; -- ou OLD dependendo do tipo de trigger
END;
$$ LANGUAGE plpgsql;

Exemplo:
CREATE OR REPLACE FUNCTION atualiza_estoque_func()
RETURNS TRIGGER AS $$
BEGIN
    UPDATE estoque 
    SET quantidade = quantidade - NEW.quantidade
    WHERE produto_id = NEW.produto_id;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER atualiza_estoque
AFTER INSERT ON vendas
FOR EACH ROW
EXECUTE FUNCTION atualiza_estoque_func();
        """
    
    elif dialect == 'oracle':
        help_text = """
Sintaxe Oracle:
CREATE [OR REPLACE] TRIGGER nome_trigger
{BEFORE | AFTER} {INSERT | UPDATE | DELETE} ON nome_tabela
[FOR EACH ROW [WHEN (condição)]]
[DECLARE
    -- declarações de variáveis]
BEGIN
    -- corpo do trigger
[EXCEPTION
    WHEN ... THEN ...]
END;

Exemplo:
CREATE OR REPLACE TRIGGER atualiza_estoque
AFTER INSERT ON vendas
FOR EACH ROW
BEGIN
    UPDATE estoque 
    SET quantidade = quantidade - :NEW.quantidade
    WHERE produto_id = :NEW.produto_id;
END;
        """
    
    elif dialect == 'tsql':
        help_text = """
Sintaxe SQL Server:
CREATE TRIGGER nome_trigger
ON nome_tabela
{AFTER | INSTEAD OF} {INSERT | UPDATE | DELETE}
AS
BEGIN
    -- corpo do trigger
END;

Exemplo:
CREATE TRIGGER atualiza_estoque
ON vendas
AFTER INSERT
AS
BEGIN
    UPDATE e
    SET e.quantidade = e.quantidade - i.quantidade
    FROM estoque e
    INNER JOIN inserted i ON e.produto_id = i.produto_id;
END;
        """
    
    elif dialect == 'sqlite':
        help_text = """
Sintaxe SQLite:
CREATE TRIGGER nome_trigger
{BEFORE | AFTER | INSTEAD OF} {INSERT | UPDATE | DELETE} ON nome_tabela
[FOR EACH ROW]
[WHEN condição]
BEGIN
    -- corpo do trigger
END;

Exemplo:
CREATE TRIGGER atualiza_estoque
AFTER INSERT ON vendas
FOR EACH ROW
BEGIN
    UPDATE estoque 
    SET quantidade = quantidade - NEW.quantidade
    WHERE produto_id = NEW.produto_id;
END;
        """
    
    return help_text

# Interface Tkinter
class SQLValidatorApp:
    def _init_(self, root):
        self.root = root
        self.root.title("SQL Validator")
        self.root.geometry("900x700")
        
        # Configurar o estilo
        self.style = ttk.Style()
        self.style.configure("TButton", padding=6, relief="flat", background="#3498db")
        
        # Frame principal
        main_frame = ttk.Frame(root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Dialeto
        dialect_frame = ttk.Frame(main_frame)
        dialect_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(dialect_frame, text="Dialeto SQL:").pack(side=tk.LEFT, padx=5)
        self.dialect_var = tk.StringVar(value="sqlite")
        dialects = ["sqlite", "mysql", "postgresql", "oracle", "tsql"]
        self.dialect_combo = ttk.Combobox(dialect_frame, textvariable=self.dialect_var, values=dialects, width=15)
        self.dialect_combo.pack(side=tk.LEFT, padx=5)
        
        # Botão de ajuda para trigger
        self.help_button = ttk.Button(dialect_frame, text="Guia de Triggers", command=self.mostrar_ajuda)
        self.help_button.pack(side=tk.RIGHT, padx=5)
        
        # Campo de entrada SQL
        ttk.Label(main_frame, text="SQL:").pack(anchor=tk.W, pady=(10, 5))
        
        self.sql_input = scrolledtext.ScrolledText(main_frame, height=10)
        self.sql_input.pack(fill=tk.BOTH, expand=True, pady=5)
        self.sql_input.insert(tk.END, "SELECT * FROM users;")
        
        # Botões
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=10)
        
        self.execute_button = ttk.Button(button_frame, text="Executar SQL", command=self.executar_sql)
        self.execute_button.pack(side=tk.LEFT, padx=5)
        
        # Campo de saída
        ttk.Label(main_frame, text="Resultado:").pack(anchor=tk.W, pady=(10, 5))
        
        self.output = scrolledtext.ScrolledText(main_frame, height=15)
        self.output.pack(fill=tk.BOTH, expand=True, pady=5)
        self.output.config(state=tk.DISABLED)
        
        # Inicializar o validador
        self.validator = SQLValidator()
    
    def executar_sql(self):
        self.output.config(state=tk.NORMAL)
        self.output.delete(1.0, tk.END)
        
        query_original = self.sql_input.get(1.0, tk.END).strip()
        dialect = self.dialect_var.get()
        
        self.output.insert(tk.END, "🔄 Analisando e corrigindo SQL...\n")
        
        # Verificar se é um trigger ou uma query normal
        is_trigger = self.validator.is_trigger(query_original, dialect)
        
        if is_trigger:
            self.output.insert(tk.END, "\n🔍 Detectado código de TRIGGER - validando estrutura...\n")
            issues = self.validator.validate_trigger(query_original, dialect)
            if issues:
                self.output.insert(tk.END, "\n⚠️ Problemas detectados no trigger:\n")
                for issue in issues:
                    self.output.insert(tk.END, f"- {issue}\n")
        
        # Passo 1: Correções manuais básicas
        query_pre_corrigido, correcoes_manuais = correções_adicionais(query_original)
        
        # Passo 2: Usar SQLFluff para correções mais avançadas
        try:
            query_corrigido, lint_results, mensagens_sqlfluff = corrigir_com_sqlfluff(query_pre_corrigido, dialect)
            
           if lint_results:
                self.output.insert(tk.END, "\n🔬 Análise de qualidade do SQL:\n")
                violations_found = False
                for file_result in lint_results:
                    if 'violations' in file_result and file_result['violations']:
                        violations_found = True
                        for violation in file_result['violations']:
                            self.output.insert(tk.END, f"- Linha {violation.get('line_no', '?')}: {violation.get('description', 'Erro não especificado')}\n")
                
                if not violations_found:
                    self.output.insert(tk.END, "✅ Nenhum problema de qualidade detectado pelo SQLFluff\n")
            
            if mensagens_sqlfluff and "erro" in mensagens_sqlfluff.lower():
                self.output.insert(tk.END, f"\n⚠️ Avisos do SQLFluff: {mensagens_sqlfluff}\n")
        except Exception as e:
            query_corrigido = query_pre_corrigido
            self.output.insert(tk.END, f"\n⚠️ SQLFluff não pôde ser executado: {str(e)}\n")
            self.output.insert(tk.END, "Aplicando apenas correções básicas.\n")
        
        # Se não for um trigger, validar como query normal
        if not is_trigger:
            query_issues = self.validator.validate_query(query_corrigido, dialect)
            if query_issues:
                self.output.insert(tk.END, "\n⚠️ Problemas detectados na query:\n")
                for issue in query_issues:
                    self.output.insert(tk.END, f"- {issue}\n")
        
        # Mostrar correções
        if query_corrigido != query_original:
            self.output.insert(tk.END, "\n🔍 SQL Corrigido:\n")
            self.output.insert(tk.END, query_corrigido + "\n")
            
            if correcoes_manuais:
                self.output.insert(tk.END, "\n📝 Correções manuais realizadas:\n")
                for correcao in correcoes_manuais:
                    self.output.insert(tk.END, f"- {correcao}\n")
            
            if query_corrigido != query_pre_corrigido:
                self.output.insert(tk.END, "\n🔧 SQLFluff aplicou correções adicionais de formatação e sintaxe.\n")
            
            self.output.insert(tk.END, "\n")
        else:
            self.output.insert(tk.END, "\n✅ O código SQL parece estar sintaticamente correto e não precisou de ajustes de formatação.\n")
        
        # Não executar triggers por causa das limitações do SQLite
        if is_trigger:
            self.output.insert(tk.END, "\n🚫 A execução de triggers não é suportada no ambiente atual.\n")
            self.output.insert(tk.END, "Este código foi apenas validado quanto à sua sintaxe.\n")
        else:
            try:
                # Tenta executar o SQL corrigido
                cursor.execute(query_corrigido)
                if query_corrigido.lower().strip().startswith("select"):
                    # Buscar os resultados
                    results = cursor.fetchall()
                    # Obter nomes das colunas
                    column_names = [desc[0] for desc in cursor.description]
                    
                    # Exibir resultados em formato tabular
                    self.output.insert(tk.END, "\n✅ Consulta executada com sucesso!\n\n")
                    
                    # Cabeçalho da tabela
                    header = " | ".join(column_names)
                    separator = "-" * len(header)
                    self.output.insert(tk.END, header + "\n")
                    self.output.insert(tk.END, separator + "\n")
                    
                    # Linhas da tabela
                    for row in results:
                        row_formatted = " | ".join([str(item) for item in row])
                        self.output.insert(tk.END, row_formatted + "\n")
                    
                    self.output.insert(tk.END, f"\nTotal de registros: {len(results)}\n")
                else:
                    conn.commit()
                    self.output.insert(tk.END, "\n✅ Comando executado com sucesso!\n")
            except Exception as e:
                self.output.insert(tk.END, "\n❌ Erro ao executar SQL mesmo após correções:\n")
                self.output.insert(tk.END, str(e) + "\n")
                sugestao = analisar_erro(str(e), dialect)
                self.output.insert(tk.END, f"\nSugestão: {sugestao}\n")
                
                # Se ainda houver erro, sugere verificar manualmente
                self.output.insert(tk.END, "\nVerifique manualmente os seguintes pontos:\n")
                self.output.insert(tk.END, "- Verifique se os nomes das tabelas e colunas estão corretos\n")
                self.output.insert(tk.END, "- Verifique se todas as instruções terminam com ponto e vírgula\n")
                self.output.insert(tk.END, "- Verifique se os tipos de dados são compatíveis\n")
                self.output.insert(tk.END, f"- Verifique a sintaxe específica do {dialect.upper()} para o comando que está tentando executar\n")
        
        self.output.config(state=tk.DISABLED)
    
    def mostrar_ajuda(self):
        dialect = self.dialect_var.get()
        help_text = mostrar_guia_trigger(dialect)
        
        # Criar uma janela de ajuda
        help_window = tk.Toplevel(self.root)
        help_window.title(f"Guia de Triggers - {dialect.upper()}")
        help_window.geometry("700x500")
        
        help_text_widget = scrolledtext.ScrolledText(help_window)
        help_text_widget.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        help_text_widget.insert(tk.END, help_text)
        help_text_widget.config(state=tk.DISABLED)
        
        close_button = ttk.Button(help_window, text="Fechar", command=help_window.destroy)
        close_button.pack(pady=10)

# Função principal
def main():
    root = tk.Tk()
    app = SQLValidatorApp(root)
    root.mainloop()

if _name_ == "_main_":
    main()
