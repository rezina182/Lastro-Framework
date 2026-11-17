'use strict';

// Legenda dos relatórios: o que significa cada prefixo (CORE, AUTH...), estado, classe, pilar, categoria STRIDE e sigla.
// Texto próprio, em português simples, para quem lê o relatório sem conhecer o kit.

const { PACK_PREFIX, FLAGS } = require('./schema');
const { PILLARS, PILLAR_HELP, KINDS, CLASS_PT } = require('./risk');
const { STRIDE, SURFACES } = require('./threatmodel');
const { FLAG_LABELS } = require('./context');
const L = require('./links');

const PACK_INFO = {
  core: { name: 'Base', what: 'O que vale para qualquer projeto: segredos fora do código, dependências, CI, injeção de SQL e de comando, criptografia, logs, modelo de ameaças e desenvolvimento com agente de IA.' },
  web: { name: 'Aplicação web', what: 'Cabeçalhos de segurança, CSP, HSTS, erros que não vazam detalhe, métodos HTTP, CORS, cache e CSRF.' },
  auth: { name: 'Autenticação e sessão', what: 'Login, senha, segundo fator, recuperação de conta, sessão, OAuth e OpenID, e autorização por função e por objeto.' },
  pii: { name: 'Dados pessoais', what: 'Coleta mínima, retenção e exclusão, aviso de privacidade (inclusive de menores) e dado pessoal fora dos logs.' },
  realtime: { name: 'Tempo real', what: 'WebSocket, SSE e WebRTC: origem verificada, limites de conexão e salas que expiram.' },
  uploads: { name: 'Upload de arquivos', what: 'Tipo conferido pelo conteúdo, limites de tamanho, arquivo que nunca executa no servidor e arquivo compactado.' },
  assets: { name: 'Ativos de mídia', what: 'Origem e licença de imagem, áudio, fonte e vídeo versionados no repositório.' },
  agent: { name: 'Agente de código', what: 'Arquivos de instrução do agente de IA, hooks sem rede, segredos fora do alcance dele e revisão humana.' },
};

const STATES = [
  ['verificado', 'há prova: uma verificação automática passou, ou há atestação vigente de uma pessoa'],
  ['falhando', 'a verificação encontrou o problema'],
  ['sem prova', 'ninguém provou ainda; conta como zero e nunca como aprovado'],
  ['não se aplica', 'o perfil diz que a aplicação não tem aquilo (por exemplo, sem upload)'],
];

const TERMS = [
  ['ASVS', 'Application Security Verification Standard, da OWASP: lista de requisitos de segurança para aplicações. O kit mapeia cada controle aos requisitos que ele cobre.', L.ASVS_URL],
  ['CWE', 'Common Weakness Enumeration: catálogo de tipos de fraqueza (por exemplo, CWE-89 é injeção de SQL). Cada número leva à página oficial.', 'https://cwe.mitre.org/'],
  ['CVE', 'Identificador de uma vulnerabilidade conhecida em um produto ou biblioteca. Só faz sentido para dependências.', 'https://nvd.nist.gov/'],
  ['GHSA', 'Aviso de segurança do GitHub. É o identificador que o npm audit informa, e a página dele traz o CVE.', null],
  ['CVSS', 'Nota de 0 a 10 da gravidade técnica de uma vulnerabilidade conhecida.', null],
  ['STRIDE', 'Seis categorias de ameaça: falsificação de identidade, adulteração, repúdio, divulgação de informação, negação de serviço e elevação de privilégio.', null],
  ['SSDLC', 'Ciclo de vida de desenvolvimento seguro: projeto, desenvolvimento, teste, entrega, operação e resposta a incidentes.', null],
  ['LGPD', 'Lei Geral de Proteção de Dados (Lei 13.709/2018). Os artigos citados indicam onde olhar, não são parecer jurídico.', L.LGPD_URL],
  ['Portão de CI', 'A verificação que bloqueia a publicação quando aparece um achado novo, alto ou crítico. Não é nota da aplicação.', null],
  ['Baseline', 'Dívida conhecida registrada: o portão passa a bloquear só o que for novo.', null],
  ['Atestação', 'Declaração de uma pessoa, com responsável e validade, de que um controle manual está em dia. É autodeclaração, não prova de máquina.', null],
  ['Fronteira de confiança', 'Ponto em que o dado passa de uma zona para outra com mais ou menos confiança (internet para aplicação, aplicação para banco).', null],
];

const IDS = [
  ['CORE-012, AUTH-027...', 'Controle do catálogo: prefixo do pacote e número.'],
  ['TM-E-auth, TM-I-web...', 'Ameaça do modelo de ameaças: TM, categoria STRIDE e superfície.'],
  ['F1, F2...', 'Fluxo no desenho da arquitetura.'],
  ['A-01', 'Ativo do modelo de ameaças.'],
  ['T-0001', 'Ticket do backlog (P0 é o mais urgente, P3 o menos).'],
  ['RISK-0001', 'Risco aceito, com dono, aprovador e validade.'],
  ['L-A05, L-B07', 'Lição de origem: problema real que motivou o controle.'],
  ['VULN:pacote', 'Dependência com vulnerabilidade conhecida.'],
];

/** Pacotes do catálogo, com prefixo, descrição, condição de aplicação e quantidade de controles. */
function packLegend(catalog) {
  return Object.entries(catalog.packs).map(([id, p]) => ({
    id,
    prefix: PACK_PREFIX[id] || id.toUpperCase(),
    name: (PACK_INFO[id] && PACK_INFO[id].name) || id,
    what: (PACK_INFO[id] && PACK_INFO[id].what) || p.title,
    requires: (p.requires || []).map((f) => (FLAG_LABELS[f] ? `${FLAG_LABELS[f]} (${f})` : f)),
    controls: catalog.controls.filter((c) => c.pack === id).length,
  }));
}

function staticLegend() {
  return {
    states: STATES,
    kinds: Object.values(KINDS).map((k) => [k.label, k.help]),
    classes: [
      [CLASS_PT.critical, 'produto 12 a 16: só com evidência (achado confirmado)'],
      [CLASS_PT.high, 'produto 8 a 11 (risco sem prova fica, no máximo, aqui)'],
      [CLASS_PT.medium, 'produto 4 a 7'],
      [CLASS_PT.low, 'produto 1 a 3'],
    ],
    scales: [['Probabilidade (1 a 4)', 'rara, possível, provável, quase certa'], ['Impacto (1 a 4)', 'pequeno, moderado, grande, severo']],
    pillars: Object.keys(PILLARS).map((k) => [PILLARS[k], PILLAR_HELP[k]]),
    stride: Object.keys(STRIDE).map((k) => [`${k}: ${STRIDE[k].name}`, STRIDE[k].ask]),
    surfaces: Object.entries(SURFACES),
    terms: TERMS,
    ids: IDS,
    flagCount: FLAGS.length,
  };
}

module.exports = { packLegend, staticLegend, PACK_INFO };
