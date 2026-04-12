

# NetLab ferramenta  
### Ferramenta de Demonstração de Segurança Educacional

---

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python)](https://python.org)
[![License](https://img.shields.io/badge/License-Acadêmica%20%2F%20Educacional-green)](#-licença)
[![Status](https://img.shields.io/badge/status-estável-brightgreen)](#)

**`netlab_ferramenta.py`** · Versão 3.0  
*Módulo independente para simulação de ataques em ambiente controlado*

</div>

---

## Índice

- [Visão Geral](#-visão-geral)
- [Funcionalidades](#-funcionalidades)
- [Estrutura do Código](#-estrutura-do-código)
- [Tecnologias Utilizadas](#-tecnologias-utilizadas)
- [Instalação e Execução](#-instalação-e-execução)
- [Exemplos de Uso](#-exemplos-de-uso)
- [Casos de Aplicação Didática](#-casos-de-aplicação-didática)
- [Decisões de Design](#-decisões-de-design)
- [Limitações](#-limitações)
- [Licença](#-licença)

---

## Visão Geral

O **NetLab Pentest Tool** é uma ferramenta educacional independente desenvolvida para demonstrar, de forma prática e controlada, técnicas comuns de **teste de intrusão (pentest)**.

Seu objetivo é permitir que estudantes compreendam **como ataques funcionam na prática**, analisando:

- comportamento de sistemas sob ataque  
- vulnerabilidades em aplicações web  
- mecanismos de defesa (rate limiting, bloqueios, headers, etc.)

Embora faça parte do ecossistema didático do NetLab, o `netlab_ferramenta.py` é **totalmente autônomo**, podendo ser utilizado isoladamente em qualquer ambiente de laboratório.

---

## ⚠️ Aviso Ético

> Esta ferramenta deve ser utilizada **exclusivamente em ambientes controlados e autorizados**.

- ✔ Servidores locais (localhost)  
- ✔ Redes de laboratório  
- ✔ Ambientes educacionais  

❌ Uso contra sistemas reais sem autorização é ilegal.

---

## Funcionalidades

### 1. Força Bruta Assíncrona

Simula ataques de tentativa de login com alto paralelismo.

**Características:**
- Execução com `asyncio` + `aiohttp`
- Alta concorrência (centenas de requisições simultâneas)
- Múltiplas estratégias de senha:
  - lista interna
  - intervalos numéricos
  - por comprimento
  - datas
  - wordlist externa

**Mecanismos avançados:**
- Detecção heurística de sucesso (status + conteúdo)
- Backoff exponencial (HTTP 429)
- Rotação de User-Agent
- Spoof de IP (`X-Forwarded-For`)
- Detecção de bloqueios (WAF / rate limit)

---

### 2. Teste de Estresse (DoS)

Simula sobrecarga de servidor com diferentes vetores.

**Modos disponíveis:**
- HTTP Flood
- TCP Flood
- Slowloris
- UDP Flood

**Métricas:**
- requisições por segundo  
- erros / recusas  
- tempo total de execução  

---

### 3. Scanner de Endpoints

Enumeração de rotas web e análise de segurança.

**Inclui:**
- lista de endpoints comuns (`/admin`, `/api`, `/config`, etc.)
- análise de headers:
  - `HSTS`
  - `CSP`
  - `X-Frame-Options`
  - `X-Content-Type-Options`

**Saída:**
- tabela com status HTTP
- alertas de segurança

---

### 4. Interceptação HTTP

Demonstra exposição de dados em tráfego não criptografado.

**Mostra:**
- headers completos
- payload de formulários
- credenciais em texto puro

**Objetivo:**
Evidenciar a necessidade de HTTPS.

---

## Estrutura do Código

```

netlab_ferramenta.py
├── Utilitários (CLI, cores, tabelas)
├── Geradores de Wordlist
├── Helpers de Rede
│
├── BaseAtaque (classe abstrata)
│
├── ModuloBruteForce
├── ModuloEstresse
├── ModuloScanner
├── ModuloIntercepcaoHTTP
│
└── Menu principal

```

### Arquitetura

- **Padrão orientado a objetos**
- Classe base (`BaseAtaque`) define fluxo padrão:
```

configurar → executar → mostrar_resultado

````

- **Concorrência assíncrona**
- `asyncio`
- controle via `Semaphore`

- **Fallback automático**
- `aiohttp` → `requests`
- `rich` → ANSI

---

## Tecnologias Utilizadas

| Tecnologia | Função |
|----------|------|
| Python 3.8+ | Base do sistema |
| asyncio | Concorrência |
| aiohttp | HTTP assíncrono |
| requests | fallback síncrono |
| rich | interface CLI (opcional) |
| socket / ssl | operações de rede |

---

## Instalação e Execução

### 1. Clonar

```bash
git clone https://github.com/seu-usuario/netlab-ferramenta.git
cd netlab-ferramenta
````

### 2. Instalar dependências

```bash
pip install aiohttp requests rich
```

### 3. Executar

```bash
python netlab_ferramenta.py
```

---

## Exemplos de Uso

### Força Bruta

* alvo: `http://localhost:8080`
* usuário: `admin`
* estratégia: senhas comuns

Resultado esperado:

* senha descoberta rapidamente
* estatísticas de execução

---

### Teste de Estresse

* 200 workers
* 30 segundos

Observação:

* aumento de carga no servidor
* possíveis bloqueios

---

### Scanner

* entrada: URL base
* saída: endpoints + alertas

---

### Interceptação

* envio de formulário
* exibição do tráfego bruto

---

## 🎓 Casos de Aplicação Didática

| Tema          | Aplicação         |
| ------------- | ----------------- |
| Autenticação  | força bruta       |
| DoS           | teste de estresse |
| Segurança Web | scanner           |
| Criptografia  | interceptação     |
| Pentest       | uso integrado     |

---

## Decisões de Design

### Concorrência Controlada

Limites máximos evitam exaustão de recursos.

---

### Heurísticas Inteligentes

Detecção de sucesso baseada em:

* conteúdo
* redirecionamento
* status HTTP

---

### Resiliência

* backoff exponencial
* detecção de bloqueios

---

### Modularidade

Cada ataque é um módulo independente.

---

## ⚠️ Limitações

* Interface CLI (sem GUI)
* Dependência de ambiente controlado
* Não substitui ferramentas profissionais
* Desempenho reduzido sem `aiohttp`

---

## 📄 Licença

Uso **acadêmico e educacional**.

---

## 👨‍💻 Autor

**Yuri Gonçalves Pavão**
Técnico em Informática — IFFar Campus Uruguaiana

---

<div align="center">

**NetLab ferramenta v1.0**


*Aprender atacando para defender melhor.*

</div>
```
