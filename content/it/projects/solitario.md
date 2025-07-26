---
title: "Solitario Croce"
date: 2024-07-23T00:00:00+00:00
# weight: 1
tags: ["solitaire", "game", "c#", "wpf", "project-work", "school", "homework"]
author: ["AlBovo", "Mark-74"]
# author: ["Me", "You"] # multiple authors
showToc: true
TocOpen: false
draft: false
hidemeta: false
comments: false
description: "Un progetto scolastico riguardo un solitario di carte progettato da un piccolo team di studenti."
canonicalURL: "https://albovo.github.io/it/projects/"
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
    image: "" # TODO: add image path/url
    alt: "Solitario Croce" # alt text
    caption: "Un progetto scolastico riguardo un solitario di carte progettato da un piccolo team di studenti." # display caption under cover
    relative: false # when using page bundles set this to true
    hidden: true # only hide on current single page
editPost:
    URL: "https://github.com/AlBovo/AlBovo.github.io/blob/main/content/it"
    Text: "Suggerisci modifiche" # edit text
    appendFilePath: true # to append file path to Edit link
---
# Solitario Croce ♣️
Realizzazione di un gioco 🎮 scritto in C# utilizzando il framework WPF, il gioco in questione è un solitario basato su carte da gioco personalizzate.

## Team di sviluppo 🤖
Questo progetto è sviluppato da:

- **Agostini** Alan
- **Angiolillo** Matteo
- **Balducci** Marco
- **Bovo** Alan Davide


## Gioco 🎮
Il gioco da sviluppare è il Solitario a Croce.
{{< youtube g7TJviLmuMg >}}

**Come si gioca 🤔:** 5 carte del *mazzo* vengono posizionate al centro del tavolo a formare una **croce ➕**. Sono lasciate libere 4 postazioni dette *basi*.

Lo scopo del *solitario* è costruire e completare le basi (dall’asso al re per ciascun seme, in senso ascendente), trasferendovi tutte le carte. Mentre per le basi vale la regola dello stesso seme in senso ascendente, nella croce vale quella del seme diverso in senso discendente.

La prima carta di ciascun mazzetto che forma la croce può andare alle basi o essere spostata su un posto vuoto o su di un’altra carta della croce. Si può spostare una sola carta alla volta. La carta del pozzo può andare direttamente alle basi o essere trasferita al tavolo.

**Tipo di carte:** carte italiane 🇮🇹 (4 semi ♠️ ♣️ ♥️ ♦️, 10 carte per ogni seme).