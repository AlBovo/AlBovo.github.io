---
title: "Campo minato \U0001F6A9"
date: 2024-05-27T00:00:00+00:00
# weight: 1
tags: ["mine", "minesweeper", "game", "python", "c++"]
author: "AlBovo"
# author: ["Me", "You"] # multiple authors
showToc: true
TocOpen: false
draft: false
hidemeta: false
comments: false
description: "Un progetto riguardo il gioco Campo minato per terminale e interfaccia web."
canonicalURL: "https://albovo.tech/it/project/"
disableHLJS: true # to disable highlightjs
disableShare: false
disableHLJS: false
hideSummary: false
searchHidden: true
ShowReadingTime: true
ShowBreadCrumbs: true
ShowPostNavLinks: true
ShowWordCount: true
ShowRssButtonInSectionTermList: true
UseHugoToc: true
cover:
    image: "https://opengraph.githubassets.com/c81c777f86833bb1c607bce8b7ff26ec2a22d3daccbaeab7e35bc1739dd99c69/AlBovo/Mine" # image path/url
    alt: "Campo minato" # alt text
    caption: "Un progetto riguardo il gioco Campo minato per terminale e interfaccia web." # display caption under cover
    relative: false # when using page bundles set this to true
    hidden: true # only hide on current single page
editPost:
    URL: "https://github.com/AlBovo/AlBovo.github.io/blob/main/content/it"
    Text: "Suggerisci modifiche" # edit text
    appendFilePath: true # to append file path to Edit link
---
# Campo minato 🚩
> Campo minato è un classico gioco per computer che richiede una combinazione di strategia e logica. Il gioco si svolge su una griglia e l'obiettivo è scoprire tutte le mine nascoste senza farle esplodere. Per fare questo, i giocatori cliccano su singoli quadrati, e i numeri rivelati indicano il numero di mine nei quadrati adiacenti. Con queste informazioni, i giocatori utilizzano il ragionamento deduttivo per segnare con bandierine i quadrati che sospettano contengano mine e gradualmente liberano la griglia da tutte le aree non minate. La sfida sta nel fare ipotesi calcolate ed evitare le mine, questo sviluppa nei giocatori di Campo minato un occhio attento per i modelli e strategie di questo gioco.

ChatGPT.

## Come giocare 🎮
Per giocare alla versione terminale, è necessario compilare il codice sorgente o scaricare la release (vedi [installazione](#installazione-)), eseguirla e seguire le istruzioni fino a quando viene richiesto di scoprire un quadrato.
Questa richiesta specificherà le coordinate X Y (ad esempio, 1 4), partendo da 1 e arrivando fino a 16.
Per giocare sul web, semplicemente fai clic con il tasto destro per segnare un quadrato selezionato come una bomba e usa il clic sinistro per rivelarlo.

## Installazione 📦
In questa repository, ci sono due tipi di software, uno per la [versione terminale](#terminal-) e l'altro con un'interfaccia grafica basata sul [web](#web-gui-).

### Terminal 💻
Al momento in cui sto scrivendo, Mine per il terminale è stato testato solo su Linux utilizzando g++20. I comandi per compilarlo sono i seguenti:

#### Release 🚀
```bash
g++ -std=c++20 colors.cpp utils.cpp main.cpp -o mine
```

#### Debug 🛠️
```bash
g++ -std=c++20 colors.cpp utils.cpp main.cpp -fsanitize=address -g -o mine
```
Se trovi qualche bug, sarò felice ricevere una segnalazione/pull request.

### Web GUI 🌐
Per quanto riguarda il sito web che ho sviluppato, può essere eseguito come un contenitore Docker eseguendo questi comandi:
```bash
cd Mine/site/
docker build -t mine/mine:latest .
docker run mine/mine:latest
```
In seguito, Docker mostrerà la porta locale su cui il sito web è ospitato.

## Come appare 👀
![web gui](/screenWeb.png)
![console](/screenTerminal.png)
