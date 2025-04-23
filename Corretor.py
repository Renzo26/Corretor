# Executar em Google Colab

# Instalar SQLFluff se ainda não estiver instalado
!pip install sqlfluff

import sqlite3
import pandas as pd
import ipywidgets as widgets
from IPython.display import display, clear_output
import subprocess
import tempfile
import os
import re

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
        
        # Ler o arquivo corrigido
        with open(temp_path, 'r') as fixed_file:
            sql_corrigido = fixed_file.read()
        
        return sql_corrigido, result.stderr
    except Exception as e:
        return sql, f"Erro ao usar SQLFluff: {str(e)}"
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
        'interger': 'integer'
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
        nova_valores = re.sub(r"'([^']*?)'\s+'([^']*?)'", r"'\1', '\2'", valores)
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
    
    if sql != sql_original:
        return sql, correcoes
    else:
        return sql, []

# Função para analisar erros comuns do SQLite
def analisar_erro(erro):
    erro = erro.lower()
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
    else:
        return "Erro não identificado com sugestão automática."

# Widget de texto e botão
sql_input = widgets.Textarea(
    value='SELECT * FROM users;',
    placeholder=''' CREAT TABLE usuarios (
    id INT PRIMARY KAY AUTO_INCREMENT,
    nomee VARCHAR(50 NOT NULL,
    email VARCHAR(100),
    data_nascimento DATE,
    PRIMARY KEY id)
;

INSERT INTO usuarios (id nome, email, data_nascimento)
VALUES (1, 'Maria Silva', 'maria@email.com' '1995-04-23'); ''',
    description='SQL:',
    layout=widgets.Layout(width='100%', height='150px')
)

dialect_dropdown = widgets.Dropdown(
    options=['sqlite', 'mysql', 'postgresql', 'tsql', 'ansi'],
    value='sqlite',
    description='Dialeto SQL:',
)

output = widgets.Output()

def executar_sql(b):
    with output:
        clear_output()
        query_original = sql_input.value.strip()
        
        print("🔄 Analisando e corrigindo SQL...")
        
        # Passo 1: Correções manuais básicas
        query_pre_corrigido, correcoes_manuais = correções_adicionais(query_original)
        
        # Passo 2: Usar SQLFluff para correções mais avançadas
        try:
            query_corrigido, mensagens_sqlfluff = corrigir_com_sqlfluff(query_pre_corrigido, dialect_dropdown.value)
            if mensagens_sqlfluff and "erro" in mensagens_sqlfluff.lower():
                print(f"⚠️ Avisos do SQLFluff: {mensagens_sqlfluff}")
        except Exception as e:
            query_corrigido = query_pre_corrigido
            print(f"⚠️ SQLFluff não pôde ser executado: {str(e)}")
            print("Aplicando apenas correções básicas.")
        
        # Mostrar correções
        if query_corrigido != query_original:
            print("🔍 SQL Corrigido:")
            print(query_corrigido)
            
            if correcoes_manuais:
                print("\n📝 Correções manuais realizadas:")
                for correcao in correcoes_manuais:
                    print(f"- {correcao}")
            
            if query_corrigido != query_pre_corrigido:
                print("\n🔧 SQLFluff aplicou correções adicionais de formatação e sintaxe.")
            
            print("\n")
        else:
            print("✅ O código SQL parece estar correto e não precisou de ajustes.")
        
        try:
            # Tenta executar o SQL corrigido
            cursor.execute(query_corrigido)
            if query_corrigido.lower().startswith("select"):
                df = pd.DataFrame(cursor.fetchall(), columns=[desc[0] for desc in cursor.description])
                print("✅ Consulta executada com sucesso!")
                display(df)
            else:
                conn.commit()
                print("✅ Comando executado com sucesso!")
        except Exception as e:
            print("❌ Erro ao executar SQL mesmo após correções:")
            print(e)
            sugestao = analisar_erro(str(e))
            print(f"\nSugestão: {sugestao}")
            
            # Se ainda houver erro, sugere verificar manualmente
            print("\nVerifique manualmente os seguintes pontos:")
            print("- Verifique se os nomes das tabelas e colunas estão corretos")
            print("- Verifique se todas as instruções terminam com ponto e vírgula")
            print("- Verifique se os tipos de dados são compatíveis")
            print(f"- Verifique a sintaxe específica do {dialect_dropdown.value.upper()} para o comando que está tentando executar")

botao_executar = widgets.Button(description="Executar SQL")
botao_executar.on_click(executar_sql)

# Mostrar widgets
display(widgets.HBox([dialect_dropdown]))
display(sql_input, botao_executar, output)
