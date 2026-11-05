# Pedidos da Fazenda: como colocar no ar

O app funciona de dois jeitos:

- **Demonstração**: já funciona hoje. Usa dados de exemplo, que ficam só no aparelho. A senha de todos é `123456`.
- **Real**: funciona depois de seguir os passos abaixo. Os pedidos ficam num banco compartilhado (Firebase), e todos os celulares veem a mesma informação ao vivo.

O plano gratuito (Spark) do Firebase é suficiente. As fotos são comprimidas no próprio celular e guardadas no banco, sem usar o Firebase Storage, que é pago.

---

## Parte 1: Criar o projeto Firebase (uns 10 minutos)

1. Acesse https://console.firebase.google.com e clique em **Adicionar projeto**. Nome sugerido: `pedidos-fazenda`. O Google Analytics pode ficar desligado.
2. Vá em **Authentication** → **Vamos começar** → aba **Método de login**, ative **E-mail/senha** e salve.
   O app usa isso por baixo dos panos. A pessoa só escolhe a função, o nome e digita 6 números.
3. Vá em **Firestore Database** → **Criar banco de dados**, escolha o local `southamerica-east1 (São Paulo)` e o **modo de produção**.
4. Vá em **Configurações do projeto** (engrenagem) → **Seus apps** → ícone **</>** (Web), use o apelido `pedidos` e clique em **Registrar app**.
   Copie o bloco `firebaseConfig`.
5. No `index.html`, procure `var FIREBASE_CONFIG`, perto do começo do script, e cole as chaves. Com as chaves preenchidas, o modo demonstração desliga sozinho.

---

## Parte 2: Regras de segurança (obrigatório)

As regras abaixo fazem as permissões valerem **no servidor**, e não só na tela. Mesmo que alguém mexa no app ou no navegador, o banco recusa o que a função dele não permite:

- O que foi pedido (descrição, quantidade, código, chassi, fotos, local, urgência, tipo de operação) **nunca pode ser mudado**.
- Cada mudança de situação é conferida item por item, de acordo com a permissão de quem está mexendo:
  - só o Estoque separa, pede compra e envia;
  - só Compras cota e compra;
  - só um encarregado **da mesma frente** confirma o recebimento.
- O histórico só cresce. Ninguém altera nem apaga os registros de auditoria.
- Excluir um pedido só é possível para **quem abriu**, com a **senha**, e só enquanto o estoque não respondeu. A exclusão fica registrada na auditoria.
- O encarregado só lê os pedidos da frente dele.
- O **Administrativo financeiro** só lê os pedidos que precisaram de compra.
- **Compra feita** só é aceita com o **local da compra** e o **valor pago** preenchidos.
- No primeiro acesso, a pessoa só consegue criar a conta com exatamente o nome, a função e a equipe que o Administrador cadastrou.
- Só o Administrador cadastra, edita e desativa usuários. Ele não consegue dar a uma função uma permissão que ela não pode ter, e não consegue mudar a própria função nem as próprias permissões.
- Estoque, Compras e Financeiro não têm nenhum acesso administrativo.

Em **Firestore Database** → aba **Regras**, apague tudo, cole o bloco abaixo e clique em **Publicar**.

> As listas de permissões abaixo são as mesmas da variável `PERFIL` no `index.html`. Se um dia mudar uma, mude a outra também.

```
rules_version = '2';
service cloud.firestore {
  match /databases/{db}/documents {

    // ---------- quem é o usuário ----------
    function logado() { return request.auth != null; }
    function caminhoEu() { return /databases/$(db)/documents/usuarios/$(request.auth.uid); }
    function eu() { return get(caminhoEu()).data; }
    function ativo() { return logado() && exists(caminhoEu()) && eu().ativo == true; }
    function setupFeito() { return exists(/databases/$(db)/documents/config/setup); }

    // ---------- funções e permissões (iguais à variável PERFIL do index.html) ----------
    function obrig(c) {
      return c == 'encarregado' ? ['pedido.criar', 'pedido.ver_frente', 'pedido.confirmar_recebimento']
        : c == 'estoque' ? ['pedido.ver_todos', 'estoque.atender']
        : c == 'compras' ? ['pedido.ver_todos', 'compras.gerenciar']
        : c == 'financeiro' ? ['financeiro.ver_compras']
        : c == 'admin' ? ['pedido.ver_todos', 'painel.fluxo', 'relatorios.exportar', 'admin.usuarios', 'admin.config', 'admin.backup', 'admin.auditoria', 'admin.pedidos', 'financeiro.ver_compras']
        : [];
    }
    function opcionais(c) {
      return c == 'encarregado' ? ['pedido.excluir', 'painel.fluxo']
        : c == 'estoque' ? ['painel.fluxo', 'relatorios.exportar']
        : c == 'compras' ? ['compras.marcar_chegada', 'painel.fluxo', 'relatorios.exportar']
        : c == 'financeiro' ? ['relatorios.exportar']
        : [];
    }
    function padrao(c) {
      return obrig(c).concat(c == 'encarregado' ? ['pedido.excluir']
        : c == 'compras' ? ['compras.marcar_chegada', 'painel.fluxo']
        : c == 'financeiro' ? ['relatorios.exportar'] : []);
    }
    function perms() { let u = eu(); return ('permissoes' in u) ? u.permissoes : padrao(u.cargo); }
    // as obrigatórias da função valem sempre; 'pedido.cancelar' é o nome antigo de 'pedido.excluir'
    function pode(p) {
      return ativo() && (perms().hasAny([p]) || obrig(eu().cargo).hasAny([p])
        || (p == 'pedido.excluir' && perms().hasAny(['pedido.cancelar'])));
    }

    function cadastroValido(d) {
      return d.cargo in ['encarregado', 'estoque', 'compras', 'financeiro', 'admin']
        && d.nome is string && d.nome.size() >= 3 && d.nome.size() <= 80
        && d.frente is string && d.frente.size() >= 2 && d.frente.size() <= 80
        && d.login is string && d.permissoes is list
        && d.permissoes.hasAll(obrig(d.cargo))
        && d.permissoes.hasOnly(obrig(d.cargo).concat(opcionais(d.cargo)));
    }

    // ---------- pessoas cadastradas aguardando o primeiro acesso ----------
    // A tela de entrada lê os nomes para reconhecer quem está entrando (não há senha aqui).
    match /convites/{cid} {
      allow read: if true;
      allow create: if pode('admin.usuarios') && cadastroValido(request.resource.data) && request.resource.data.usado == false;
      allow update: if (pode('admin.usuarios') && resource.data.usado == false && cadastroValido(request.resource.data))
        || (logado() && resource.data.usado == false
            && request.resource.data.diff(resource.data).affectedKeys().hasOnly(['usado', 'usadoPor', 'usadoEm'])
            && request.resource.data.usado == true && request.resource.data.usadoPor == request.auth.uid
            && getAfter(caminhoEu()).data.convite == cid);
      allow delete: if pode('admin.usuarios') && resource.data.usado == false;
    }

    // ---------- usuários ----------
    function veioDoConvite(d) {
      let c = get(/databases/$(db)/documents/convites/$(d.convite)).data;
      return c.usado == false && d.nome == c.nome && d.cargo == c.cargo && d.frente == c.frente
        && d.permissoes == c.permissoes && d.login == c.login && d.ativo == true
        && request.auth.token.email == c.login + '@pedidos-biazi.app';
    }
    match /usuarios/{uid} {
      allow read: if true;
      allow create: if (logado() && request.auth.uid == uid && ('convite' in request.resource.data) && veioDoConvite(request.resource.data))
        || (logado() && request.auth.uid == uid && !setupFeito()
            && existsAfter(/databases/$(db)/documents/config/setup)
            && request.resource.data.cargo == 'admin' && cadastroValido(request.resource.data));
      // cada pessoa pode mudar só o próprio nome
      allow update: if (ativo() && request.auth.uid == uid
          && request.resource.data.diff(resource.data).affectedKeys().hasOnly(['nome'])
          && request.resource.data.nome is string
          && request.resource.data.nome.size() >= 3 && request.resource.data.nome.size() <= 80)
        || (pode('admin.usuarios') && cadastroValido(request.resource.data)
            && request.resource.data.login == resource.data.login
            && (request.auth.uid != uid || !('permissoes' in resource.data)
                || !request.resource.data.diff(resource.data).affectedKeys().hasAny(['cargo', 'ativo', 'permissoes'])));
      allow delete: if false;
    }

    match /config/setup {
      allow read: if true;
      allow create: if logado() && !setupFeito();
      allow update, delete: if false;
    }
    match /config/geral {
      allow read: if ativo();
      allow write: if pode('admin.config') && request.resource.data.operacoes is list;
    }
    match /config/contador {
      allow read: if ativo();
      allow create: if pode('pedido.criar') && request.resource.data.n == 1;
      allow update: if pode('pedido.criar') && request.resource.data.n == resource.data.n + 1;
      allow delete: if false;
    }

    // ---------- pedidos ----------
    // compra com entrega direta na frente (sem passar pelo estoque)
    function direto(e) { return ('info' in e) && ('entrega' in e.info) && e.info.entrega == 'direto'; }
    function transicao(de, para, ped, ant) {
      return (pode('estoque.atender') && ((de == 'aguardando' && para in ['separado', 'compra', 'devolvido'])
                || (de in ['separado', 'nasede'] && para == 'enviado')
                || (de == 'comprado' && para == 'nasede' && !direto(ant))))
        || (pode('compras.gerenciar') && ((de == 'compra' && para in ['cotacao', 'comprado', 'devolvido'])
                || (de == 'cotacao' && para in ['comprado', 'devolvido'])
                || (de == 'comprado' && para == 'enviado' && direto(ant))))
        || (pode('compras.marcar_chegada') && de == 'comprado' && para == 'nasede' && !direto(ant))
        || (pode('pedido.confirmar_recebimento') && ped.frente == eu().frente
            && ((de == 'enviado' && para == 'recebido') || (de == 'comprado' && para == 'recebido' && direto(ant))))
        // quem fez o pedido: corrige e reenvia o item devolvido, ou cancela
        || (pode('pedido.criar') && ped.criadoPor == request.auth.uid
            && ((de == 'devolvido' && para in ['aguardando', 'cancelado']) || (de == 'aguardando' && para == 'cancelado')));
    }
    // "Compra feita" só passa com o local da compra e o valor pago
    function compraCompleta(n) {
      return n.st != 'comprado' || (('info' in n) && ('fornecedor' in n.info) && ('valor' in n.info)
        && n.info.fornecedor is string && n.info.fornecedor.size() >= 2
        && n.info.valor is number && n.info.valor > 0);
    }
    function itemOk(i) {
      let v = resource.data.estado;
      let n = request.resource.data.estado;
      return i >= v.size() || n[i].st == v[i].st || (transicao(v[i].st, n[i].st, resource.data, v[i]) && compraCompleta(n[i]));
    }
    function todosItensOk() {
      return itemOk(0) && itemOk(1) && itemOk(2) && itemOk(3) && itemOk(4)
        && itemOk(5) && itemOk(6) && itemOk(7) && itemOk(8) && itemOk(9)
        && itemOk(10) && itemOk(11) && itemOk(12) && itemOk(13) && itemOk(14)
        && itemOk(15) && itemOk(16) && itemOk(17) && itemOk(18) && itemOk(19)
        && itemOk(20) && itemOk(21) && itemOk(22) && itemOk(23) && itemOk(24);
    }
    // pedido "direto para Compras" nasce em 'compra'; enquanto ninguém mexeu, ainda pode ser excluído
    function inicial() { return ('destino' in resource.data) && resource.data.destino == 'compras' ? 'compra' : 'aguardando'; }
    function aguardando(i) { return i >= resource.data.estado.size() || resource.data.estado[i].st == inicial(); }
    function nadaRespondido() {
      return aguardando(0) && aguardando(1) && aguardando(2) && aguardando(3) && aguardando(4)
        && aguardando(5) && aguardando(6) && aguardando(7) && aguardando(8) && aguardando(9)
        && aguardando(10) && aguardando(11) && aguardando(12) && aguardando(13) && aguardando(14)
        && aguardando(15) && aguardando(16) && aguardando(17) && aguardando(18) && aguardando(19)
        && aguardando(20) && aguardando(21) && aguardando(22) && aguardando(23) && aguardando(24);
    }
    function historicoCresceUm() {
      return request.resource.data.historico.size() == resource.data.historico.size() + 1
        && request.resource.data.historico[0:resource.data.historico.size()] == resource.data.historico
        && request.resource.data.historico[resource.data.historico.size()].por == request.auth.uid;
    }

    match /pedidos/{id} {
      allow read: if pode('pedido.ver_todos')
        || (pode('pedido.ver_frente') && resource.data.frente == eu().frente)
        || (pode('financeiro.ver_compras') && resource.data.teveCompra == true);

      allow create: if pode('pedido.criar')
        && request.resource.data.criadoPor == request.auth.uid
        && request.resource.data.frente == eu().frente
        && request.resource.data.tipoOperacao is string && request.resource.data.tipoOperacao.size() >= 2
        && request.resource.data.itens.size() > 0 && request.resource.data.itens.size() <= 15
        && request.resource.data.estado.size() == request.resource.data.itens.size()
        && request.resource.data.historico.size() == 1
        && request.resource.data.historico[0].por == request.auth.uid;

      // o conteúdo do pedido é travado; só a situação anda, e só nas transições permitidas
      allow update: if ativo()
        && request.resource.data.diff(resource.data).affectedKeys().hasOnly(['estado', 'historico', 'status', 'atualizadoEm', 'teveCompra'])
        && request.resource.data.estado.size() == resource.data.estado.size()
        && historicoCresceUm()
        && todosItensOk();

      // estoque tinha só uma parte: o item é dividido e o restante entra como item novo (vai para compra)
      allow update: if pode('estoque.atender')
        && request.resource.data.diff(resource.data).affectedKeys().hasOnly(['itens', 'estado', 'historico', 'status', 'atualizadoEm', 'teveCompra'])
        && request.resource.data.itens.size() == resource.data.itens.size() + 1
        && request.resource.data.itens.size() <= 25
        && request.resource.data.estado.size() == request.resource.data.itens.size()
        && request.resource.data.estado[request.resource.data.estado.size() - 1].st == 'compra'
        && historicoCresceUm();

      // item devolvido: quem fez o pedido corrige os dados do item e reenvia (ou cancela)
      allow update: if pode('pedido.criar') && resource.data.criadoPor == request.auth.uid
        && request.resource.data.diff(resource.data).affectedKeys().hasOnly(['itens', 'estado', 'historico', 'status', 'atualizadoEm'])
        && request.resource.data.itens.size() == resource.data.itens.size()
        && request.resource.data.estado.size() == resource.data.estado.size()
        && historicoCresceUm()
        && todosItensOk();

      // correção do administrador: situação de qualquer item e dados de entrega, nunca o que foi pedido
      allow update: if pode('admin.pedidos')
        && request.resource.data.diff(resource.data).affectedKeys().hasOnly(['estado', 'historico', 'status', 'atualizadoEm', 'localidade', 'situacao', 'maquinaParada', 'teveCompra'])
        && request.resource.data.estado.size() == resource.data.estado.size()
        && request.resource.data.situacao in ['normal', 'urgente']
        && historicoCresceUm();

      // exclusão: só quem abriu, com a permissão, antes de o estoque responder (a senha é conferida no app)
      allow delete: if pode('pedido.excluir')
        && resource.data.criadoPor == request.auth.uid
        && nadaRespondido();
    }

    // vídeos: a ficha em 'midias' e o arquivo dividido em pedaços em 'midiapartes'
    match /midias/{id} {
      allow read: if ativo();
      allow create: if ativo() && request.resource.data.por == request.auth.uid
        && request.resource.data.partes is int && request.resource.data.partes <= 40;
      allow update: if false;
      allow delete: if ativo() && resource.data.por == request.auth.uid;
    }
    match /midiapartes/{id} {
      allow read: if ativo();
      allow create: if ativo() && request.resource.data.por == request.auth.uid && request.resource.data.data.size() <= 750000;
      allow update: if false;
      allow delete: if ativo() && resource.data.por == request.auth.uid;
    }

    match /fotos/{id} {
      allow read: if ativo();
      allow create: if ativo() && request.resource.data.por == request.auth.uid;
      allow update: if false;
      allow delete: if ativo() && resource.data.por == request.auth.uid;
    }

    // ---------- auditoria (só cresce) ----------
    match /auditoria/{id} {
      allow read: if pode('admin.auditoria');
      allow create: if (ativo() && request.resource.data.por == request.auth.uid && request.resource.data.em is number)
        || (!logado() && request.resource.data.acao == 'login_falhou'
            && request.resource.data.keys().hasOnly(['em', 'por', 'porNome', 'cargo', 'acao', 'alvo', 'alvoNome', 'detalhes'])
            && request.resource.data.detalhes.size() < 200);
      allow update, delete: if false;
    }
  }
}
```

Se o Firebase acusar erro ao publicar, copie a mensagem e me mande.

---

## Parte 3: Publicar no GitHub Pages (mesmo jeito do Urtigão no Campo)

1. No GitHub, crie o repositório `pedidos-fazenda` como público.
2. Clique em **Add file → Upload files** e envie os arquivos: `index.html`, `manifest.json`, `sw.js`, `icon-192.png`, `icon-512.png` e este `SETUP.md`.
3. Vá em **Settings → Pages**, escolha **Branch: main / (root)** e clique em **Save**.
4. O endereço fica `https://luizmartinhagom-cell.github.io/pedidos-fazenda/`.
5. No Firebase, vá em **Authentication → Configurações → Domínios autorizados** e adicione `luizmartinhagom-cell.github.io`.

---

## Parte 4: Primeiro acesso e cadastro da equipe

1. Abra o link. Com o banco vazio, aparece a tela **Primeiro acesso**. Preencha nome completo, frente/equipe e senha. Esse primeiro usuário é o **Administrador**.
2. Em **Configurações → Pessoas**, toque em **Cadastrar equipe inicial**. O app cadastra de uma vez:

   | Nome | Função |
   |---|---|
   | Marco Antônio | Administrador |
   | Ana Paula | Administrador |
   | Matheus | Estoque (almoxarifado) |
   | Rodrigo | Compras |
   | Marcelo, Cláudio, Maicon e Estevaldo | Encarregado |

   Os encarregados entram com a frente **"A definir"**. Enquanto ela não for trocada, os quatro enxergam os pedidos uns dos outros. Defina a frente de cada um em **Usuários → Editar**.
3. Para cadastrar outras pessoas, de qualquer função, use **Configurações → Pessoas → Cadastrar pessoa** (ou a aba **Usuários**). Preencha:
   - **Nome**: é o que a pessoa vai digitar para entrar. O app não aceita dois cadastros com o mesmo nome.
   - **Função**: Encarregado, Estoque, Compras, Administrativo financeiro ou Administrador.
   - **Frente ou equipe**: obrigatória para encarregado. Para as outras funções, já vem preenchida com a equipe da sede.
   - **Permissões**: as da função já vêm marcadas. As opcionais, o Administrador libera ou não.
   - **Não tem senha no cadastro.**
4. **Primeiro acesso:** a pessoa abre o app, digita o nome e toca em **Entrar**. O app mostra o nome e a função dela e pede para **criar a senha** de 6 números, duas vezes. A partir daí ela entra com nome e senha, e só vê as telas da função cadastrada.
5. Até a pessoa fazer o primeiro acesso, ela aparece como **Aguardando 1º acesso**. Nesse intervalo, quem souber o nome e a função dela conseguiria criar a senha no lugar dela. Por isso, avise a pessoa assim que cadastrar. Se acontecer, use **Gerar novo primeiro acesso** no cadastro dela.

### O que cada função pode fazer

| Permissão | Encarregado | Estoque | Compras | Financeiro | Administrador |
|---|:-:|:-:|:-:|:-:|:-:|
| Abrir pedidos (qualquer tipo de operação) | ● | — | — | — | — |
| Ver os pedidos da sua frente | ● | — | — | — | — |
| Confirmar recebimento na frente | ● | — | — | — | — |
| Excluir o próprio pedido (com senha) antes do estoque responder | ○ ligada | — | — | — | — |
| Ver os pedidos de todas as frentes | — | ● | ● | — | ● |
| Atender pelo estoque | — | ● | — | — | — |
| Gerenciar compras (cotação e compra, com local e valor) | — | — | ● | — | — |
| Registrar que a compra chegou na sede | — | — | ○ ligada | — | — |
| Ver fluxo geral e tempos | ○ | ○ | ○ ligada | — | ● |
| Relatórios (PDF e planilha) | — | ○ | ○ | ○ ligada | ● |
| Ver compras realizadas (local e valor pago) | — | — | — | ● | ● |
| Usuários e permissões | — | — | — | — | ● |
| Configurações (tipos de operação) | — | — | — | — | ● |
| Backup | — | — | — | — | ● |
| Auditoria | — | — | — | — | ● |
| Corrigir pedidos (com justificativa) | — | — | — | — | ● |

Legenda: ● sempre tem · ○ opcional, liberada pelo Administrador ("ligada" = já vem marcada no cadastro novo) · — não pode ter.

- O encarregado **não fica preso a um tipo de operação**. Ele escolhe o tipo (Plantio, Colheita, Manutenção de máquinas etc.) a cada pedido. A lista de tipos é editada pelo Administrador nas **Configurações** (engrenagem no topo).
- Todos os encarregados da mesma frente veem e acompanham os pedidos daquela frente.

### Senhas

- Cada pessoa troca a própria senha nas **Configurações**, pela engrenagem no canto superior direito.
- Se alguém esquecer a senha, o Administrador abre o cadastro e toca em **Gerar novo primeiro acesso**. A senha antiga deixa de valer, e a pessoa cria outra no próximo acesso. Pedidos e histórico continuam. Tudo fica na auditoria.

---

## Auditoria e backup (Configurações, só o Administrador)

- **Auditoria**: registra entradas no app, senha errada, saídas, troca de senha, pedidos abertos, cada mudança de situação, exclusões de pedido, cadastro, edição, desativação e reativação de usuários, mudanças de permissão, nova senha, mudanças de configuração e exportações. Ninguém consegue apagar ou editar esses registros.
- **Backup**: baixa um arquivo `.json` com usuários (sem senhas), pedidos, configurações e auditoria. As fotos são opcionais. Faça uma vez por semana e guarde no computador ou no Google Drive.
- **Planilha**: baixa os pedidos item por item em `.csv`, que abre no Excel.

---

## Configurações (engrenagem no canto superior direito)

Para todas as funções:

- **Meu nome**: a pessoa corrige o próprio nome. A troca fica na auditoria.
- **Trocar senha**.
- **Notificações**: permitir que o celular avise.

O Administrador vê também os **ajustes do sistema**: **backup dos dados** (primeiro da lista), tipos de operação, tabela de funções e permissões e auditoria.

Para **sair do app**, toque no próprio nome, no topo da tela, e depois em **Sair do app**.

## Vídeo no pedido

- Em cada item, além das fotos (até 3), dá para anexar **um vídeo de até 30 segundos**, pelo botão **🎥 Vídeo**. No celular, ele abre a câmera ou a galeria.
- O item precisa ter **foto ou vídeo**. Um dos dois já basta.
- O app **diminui o vídeo no próprio celular** (480p, sem som) antes de enviar. Um vídeo de 20 segundos em Full HD, com uns 20 MB, fica com cerca de 1 MB. Assim cabe no plano gratuito do Firebase.
- Quem atende toca na miniatura com o ▶ e o vídeo abre em tela cheia.
- Vídeos ocupam bem mais espaço que fotos. O plano gratuito tem 1 GB, o que dá para centenas de vídeos curtos. Se um dia encher, dá para apagar vídeos de pedidos antigos.
- O backup em `.json` não leva os vídeos, porque ficaria grande demais.

## Atalho: pedido direto para Compras

Ao abrir o pedido, o encarregado escolhe **Para quem vai o pedido?**:

- **Estoque da sede** (padrão);
- **Direto para Compras**, quando ele já sabe que não tem no estoque.

O pedido direto pula a etapa do estoque e já aparece para Compras como solicitação de compra, com a etiqueta **Direto p/ Compras**. O estoque continua vendo o pedido, só para acompanhar. Enquanto Compras não mexer, o encarregado ainda pode excluir o pedido.

## Entrega: direto para a frente ou pelo estoque

Na **Compra feita**, Compras escolhe a entrega:

- **Vai para o estoque** (padrão): segue o caminho normal. O estoque marca **Chegou na sede** e depois envia para a frente.
- **Direto para a frente**: o fornecedor ou Compras leva direto, sem passar pela sede. Compras marca **Saiu direto para a frente** quando o material sair. O encarregado pode confirmar **Recebi o material** assim que chegar, mesmo que Compras ainda não tenha marcado a saída.

O painel de Compras ganhou o botão **Envio direto**, com os itens comprados que vão direto para a frente.

## Histórico do encarregado

Na aba **Histórico**, o encarregado vê todos os pedidos que fez: em andamento, recebidos e cancelados. Ele pode filtrar por período e por situação e buscar por número, peça, chassi ou local. Um botão alterna para **Toda a frente**.

## Compras: local e valor obrigatórios

Ao tocar em **Compra feita**, o setor de Compras precisa informar:

- **onde comprou** (loja ou fornecedor), obrigatório;
- **o valor pago** de cada item, obrigatório;
- o número da nota e a previsão de chegada, opcionais.

Sem o local e o valor, o app não deixa avançar, e o Firebase também recusa. Os valores aparecem só para Compras, Financeiro e Administrador. Estoque e encarregados não veem preço.

## Administrativo financeiro

Essa função vê **só os pedidos que precisaram de compra**. A tela **Compras realizadas** mostra:

- total pago no período e total do mês no painel;
- cada item comprado, com local, valor, número da nota, quem comprou e quando;
- busca por item, local, nota ou número do pedido, e filtro por local;
- resumo por local de compra;
- planilha (Excel) e PDF das compras, para conferir com as notas que chegam por e-mail.

O Administrador também acessa essa tela pelo painel.

## Excluir pedido

- O botão **Excluir pedido** aparece no próprio pedido, na lista e dentro dele, só para quem abriu o pedido, e só enquanto o estoque ainda não respondeu.
- Para confirmar, o app pede a **senha** da pessoa, o que evita exclusão sem querer. O pedido some para todos, e a auditoria guarda quem excluiu, quando e os itens.
- Depois que o estoque responde, não dá mais para excluir, porque o pedido já gerou trabalho na sede.
- A opção de avisar pelo WhatsApp foi retirada do app.

## Se o app já estava no ar com a versão anterior

Nada é apagado e nada é duplicado:

1. Publique as **regras novas** (Parte 2) e suba o `index.html` novo.
2. Entre como Administrador. No primeiro acesso, o app verifica todos os cadastros existentes:
   - quem não tinha lista de permissões recebe as permissões padrão da sua função;
   - quem não tinha frente/equipe (Estoque, Compras e Administrador, na versão anterior) recebe **"Sede (revisar)"**, e aparece um aviso em **Usuários** para você corrigir.
3. Os pedidos antigos continuam com a frente de quem pediu. Eles aparecem sem tipo de operação ("—"), porque esse campo ainda não existia.
4. Funções e nomes antigos não mudam por dentro. A função "Administrativo" agora aparece como **Administrador**, com o mesmo cadastro. A permissão antiga "cancelar pedido" vira "excluir pedido" automaticamente.
5. Se você já tinha publicado no repositório `pedidos-biazi`, pode continuar nele. Basta subir os arquivos novos: `index.html`, `manifest.json`, `sw.js` e os dois ícones. Para o ícone novo aparecer no celular, remova o atalho antigo da tela inicial e instale de novo.

---

## Entrada e painel

- **Entrada:** a pessoa digita o **nome**, escolhe a **função** e digita a **senha**. O app aceita o nome sem acento e com letra minúscula. Se só houver uma pessoa com aquele primeiro nome na função, basta o primeiro nome. O celular lembra o último nome usado.
- **Painel:** depois de entrar, cada função cai no seu painel, com botões grandes e contadores:
  - **Encarregado:** fazer novo pedido, confirmar recebimento, acompanhar pedidos, em compra e concluídos.
  - **Estoque:** responder pedidos, enviar para a frente, compras a chegar e acompanhar pedidos.
  - **Compras:** comprar, em cotação, comprados, na sede sem envio, acompanhar pedidos e fluxo geral.
  - **Administrador:** fluxo, todos os pedidos, tempos, usuários, backup e auditoria.

  Embaixo dos botões aparecem as últimas movimentações. Se houver item atrasado esperando a pessoa, aparece um aviso vermelho no topo.

## Correções do administrador

Dentro de qualquer pedido, o Administrador tem o botão **Corrigir este pedido**. Ele serve para consertar engano:

- mudar a situação de um item (por exemplo, quando alguém tocou no botão errado);
- cancelar os itens que não valem mais;
- corrigir para onde enviar, a urgência ou se a máquina está parada.

O que foi pedido (peça, quantidade, código, chassi e fotos) continua travado. Toda correção exige justificativa e fica no histórico do pedido e na auditoria.

## Instalar na tela do celular

- **Android (Chrome):** abra o link → menu ⋮ → **Instalar app**.
- **iPhone (Safari):** abra o link → Compartilhar → **Adicionar à Tela de Início**.

## Como funciona o fluxo

| Situação do item | Quem age | Botões |
|---|---|---|
| Aguardando o estoque | Estoque | **Tem no estoque – separar** / **Não tem – pedir compra** |
| Compra solicitada | Compras | **Iniciar cotação** / **Compra feita** |
| Em cotação | Compras | **Compra feita** |
| Comprado | Estoque (ou Compras com a permissão) | **Chegou na sede** |
| Separado / Chegou na sede | Estoque | **Enviar para a frente** |
| A caminho | Encarregado da frente | **Recebi o material** |

**Prazos de atraso:**

| Etapa | Urgente ou máquina parada | Normal |
|---|---|---|
| Estoque responder | 1h | 4h |
| Compras iniciar | 2h | 8h |
| Cotação | 12h | 48h |
| Compra chegar | 2 dias | 4 dias |
| Enviar depois de pronto | 2h | 24h |
| Confirmar recebimento | 12h | 48h |

Esses prazos ficam na variável `PRAZOS` do `index.html`.
