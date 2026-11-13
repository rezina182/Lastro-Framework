# Pontuação de maturidade

O relatório do LASTRO traz um nível de maturidade e percentuais. Esta página explica como eles são calculados, para que ninguém precise confiar em um número sem saber de onde ele vem.

## O que a pontuação mede

**Evidência verificável de que os controles aplicáveis estão atendidos.** Ela não mede a segurança da aplicação. Uma aplicação pode ter nota baixa e ser segura, só que ninguém provou, e uma nota alta pode esconder um risco que o catálogo ainda não cobre.

## Como é calculada

1. Entram só os controles **aplicáveis** ao perfil. O que não se aplica fica de fora.
2. Cada controle pesa pela gravidade: crítica 8, alta 5, média 3, baixa 1.
3. Só o estado **verificado** vale ponto. **Sem prova** e **falhando** valem zero: desconhecido não é aprovado.
4. O que está verificado se divide em:
   - **por máquina**: o verificador provou (varredura do repositório ou sonda HTTP);
   - **autodeclarado**: há atestação em `.lastro/status.json`, com responsável e validade de até 366 dias.
5. Os percentuais são fatias do peso total aplicável: provado (máquina mais autodeclarado), falhando e sem prova. Somam 100%.

O mesmo cálculo é feito por pacote (base, web, autenticação etc.), para mostrar onde está a lacuna.

## Níveis

| Nível | Nome | Regra |
|---|---|---|
| 0 | Inicial | Há achados bloqueantes: o portão falha. Vale mais que qualquer percentual. |
| 1 | Básico | Sem bloqueantes, mas com menos de 30% do peso provado. |
| 2 | Estruturado | Sem bloqueantes e com 30% ou mais provado. |
| 3 | Verificado | 60% ou mais provado e nenhum controle alto ou crítico falhando ou sem prova. |
| 4 | Comprovado | 90% ou mais provado, nenhum controle falhando e nenhum alto ou crítico sem prova. |

Os limites (30, 60 e 90) e os pesos são uma convenção do kit, escolhida para ser simples de explicar. Não são um padrão de mercado e podem mudar entre versões do catálogo. O campo `score.method` do relatório JSON identifica a versão do cálculo.

## Como interpretar

- **Quase todo controle do catálogo é manual**, então no começo a nota é baixa para qualquer aplicação. Isso é esperado: ela sobe quando as atestações com evidência são registradas.
- **Autodeclarado vale menos que provado por máquina** no critério de confiança, mesmo contando igual no percentual. Por isso o relatório mostra as duas fatias separadas.
- **Quem escreveu o código não deve ser o único a atestar** controles de nível alto (lição L-B10). Uma nota inflada por autoatestação não prova nada.
- **A nota depende do perfil.** Marcar flags como `false` para fugir de controles melhora o número e piora a segurança. Revise o perfil com outra pessoa.
- **Compare com a mesma versão do catálogo.** Um catálogo novo pode trazer controles novos e derrubar a nota sem que nada mude na aplicação.

## O que não usar a pontuação para fazer

- Certificar, auditar ou declarar conformidade com ASVS, SSDF ou qualquer padrão.
- Comparar aplicações de perfis diferentes como se fossem equivalentes.
- Cobrar uma meta numérica sem olhar quais controles estão abertos: a lista de controles sem prova e o próximo passo importam mais que o percentual.
