---
title: "Email Harvester \U0001F575"
date: 2025-07-26T00:00:00+00:00
# weight: 1
tags: ["scraping", "breaches", "osint-tool", "pcto", "cybersecurity"]
# author: "AlBovo"
author: ["AlBovo", "Mark-74"] # multiple authors
showToc: true
TocOpen: false
draft: false
hidemeta: false
comments: false
description: "Uno strumento che raccoglie gli indirizzi email legati al dominio di un’azienda e verifica se l’organizzazione ha subito violazioni di dati in passato."
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
    image: "https://opengraph.githubassets.com/b4cc6c2c47d87f93ed2988df0d8eaac6470e433ded4c93b8d6dd0901de672e66/AlBovo/emailHarvester" # image path/url
    alt: "Email Harvester" # alt text
    caption: "Uno strumento che raccoglie gli indirizzi email legati al dominio di un’azienda e verifica se l’organizzazione ha subito violazioni di dati in passato." # display caption under cover
    relative: false # when using page bundles set this to true
    hidden: true # only hide on current single page
editPost:
    URL: "https://github.com/AlBovo/AlBovo.github.io/blob/main/content/it"
    Text: "Suggerisci modifiche" # edit text
    appendFilePath: true # to append file path to Edit link
---
# Email Harvester 🕵️‍♂️

## 📋 Panoramica
Email Harvester è un’applicazione web full‑stack che trova automaticamente gli indirizzi email associati a un dominio specificato, li confronta con API pubbliche su violazioni di dati per segnalare eventuali account compromessi e presenta i risultati in un’interfaccia semplice e interattiva. Unisce un backend Python basato su Flask per lo scraping e i controlli delle violazioni a un frontend Node.js/EJS, il tutto orchestrato con Docker Compose per un deploy in un solo passaggio.

## 🎯 Caratteristiche principali
- **Estrazione email da dominio**: esplora siti web e risorse pubbliche per raccogliere indirizzi email.  
- **Elaborazione asincrona**: i processi di backend vengono eseguiti in parallelo per garantire alte prestazioni.  
- **“Secure” vs. “Predicted”**: distingue le email trovate direttamente (“secure”) da quelle ricavate per pattern (“predicted”).  
- **Verifica violazioni**: si integra con HaveIBeenPwned (o servizi simili) per evidenziare gli account compromessi.  
- **Interfaccia intuitiva**: realizzata con Node.js ed EJS per un feedback in tempo reale.  
- **Archivio persistente**: memorizza i risultati in MongoDB per analisi successive ed esportazione.  
- **Deploy containerizzato**: uno script Docker Compose avvia tutti i servizi (backend, frontend, database) con un unico comando.

## 🏗️ Architettura
1. **Backend (Flask/Python)**  
    - Espone endpoint REST per avviare la scansione di un dominio, recuperare i risultati archiviati e controllare le violazioni.  
    - Usa richieste HTTP asincrone e worker in background per gestire crawl di grandi dimensioni.  
2. **Frontend (Node.js/EJS)**  
    - Renderizza il modulo di ricerca e le pagine dei risultati.  
    - Comunica con l’API del backend per avviare le scansioni e aggiornare i dati.  
3. **Database (MongoDB)**  
    - Conserva gli indirizzi email estratti, le etichette di classificazione e le informazioni sullo stato delle violazioni.  
4. **Orchestrazione**  
    - Docker Compose definisce tre servizi: `backend`, `frontend` e `mongodb`, garantendo ambienti coerenti e facile scalabilità.

## 🔧 Prerequisiti
- [Docker](https://docs.docker.com/)  
- [Docker Compose](https://docs.docker.com/compose/)

## 🚀 Avvio rapido
1. **Clona il repository**  
    ```bash
    git clone https://github.com/AlBovo/emailHarvester.git
    cd emailHarvester
    ```

2. **Configura**

    * Copia `.env.example` in `.env` e inserisci la tua URI MongoDB e la chiave API per i controlli violazioni.
3. **Build & run**

    ```bash
    docker-compose up -d --build
    ```
4. **Accedi all’app**
    
    Apri [http://localhost:3000](http://localhost:3000) nel browser.

## ⚙️ Utilizzo

1. Inserisci il **dominio di destinazione** nel campo di ricerca.
2. Clicca **“Harvest”** per avviare lo scraping e la verifica delle violazioni.
3. Consulta la **tabella dei risultati**, con la classificazione di ogni email e il suo stato di violazione.
4. Esporta o cancella i risultati utilizzando i controlli dell’interfaccia.

## 🖼️ Screenshot

![Home Page](/images/emailhomepage.png)
![Result Page](/images/emailresultpage.png)