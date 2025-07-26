---
title: "Test di Suricata \U0001F6E1"
date: 2025-07-26T00:00:00+00:00
# weight: 1
tags: ["suricata", "ips", "ids", "cybersecurity", "network", "pcto"]
# author: "AlBovo"
author: ["AlBovo", "Mark-74"] # multiple authors
showToc: true
TocOpen: false
draft: false
hidemeta: false
comments: false
description: "Un ambiente pronto per eseguire Suricata in modalità IDS (e, se necessario, IPS) per proteggere una rete industriale simulata."
canonicalURL: "https://albovo.github.io/en/projects/"
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
    image: "https://opengraph.githubassets.com/445e6b2049c4fad8cb147b5da751e926d1d64c4841191f921acedb27e91492e4/AlBovo/Suricata-Testing" # image path/url
    alt: "Test di Suricata" # alt text
    caption: "Un ambiente pronto per eseguire Suricata in modalità IDS (e, se necessario, IPS) per proteggere una rete industriale simulata." # display caption under cover
    relative: false # when using page bundles set this to true
    hidden: true # only hide on current single page
editPost:
    URL: "https://github.com/AlBovo/AlBovo.github.io/blob/main/content/en"
    Text: "Suggerisci modifiche" # edit text
    appendFilePath: true # to append file path to Edit link
---
# Test di Suricata 🛡️

## 📋 Introduzione

Suricata è un motore open source ad alte prestazioni per Network Intrusion Detection (IDS), Intrusion Prevention (IPS) e Network Security Monitoring (NSM), sviluppato e mantenuto dalla Open Information Security Foundation (OISF).  
Questo repository mette a disposizione un ambiente chiavi in mano, basato su Docker e Docker Compose, per schierare Suricata in modalità IDS (con opzione IPS) su una **rete industriale simulata**. Potrai così sperimentare regole di rilevamento personalizzate, generare traffico realistico e visualizzare gli allarmi in tempo reale.

## 🎯 Scopo

Configurare Suricata in modalità IDS (e IPS, se serve) per proteggere una rete industriale simulata.

## 🛠️ Caratteristiche principali

- **Modalità flessibile**: Suricata può funzionare in IDS per il monitoraggio passivo o in IPS inline per bloccare automaticamente il traffico sospetto.  
- **Regole personalizzate**: Definisci e testa firme in `custom.rules`, da semplici scansioni di porte fino ad anomalie di protocolli industriali.  
- **Simulazione del traffico**: Gli script nella cartella `scripts/` creano traffico sia legittimo che malevolo, simulando workstation (A, B), host non autorizzati (U) e un nodo attaccante (M).  
- **Architettura modulare**: Ogni componente gira in un container dedicato, per estendere facilmente la topologia o sostituire parti con configurazioni più avanzate.  
- **Visualizzazione in tempo reale**: Gli allarmi vengono inviati a Elasticsearch e mostrati in una dashboard Kibana (template inclusi), così da monitorare le rilevazioni e analizzare i trend di traffico.

## 🌐 Topologia di rete

```
 +-----+         +-----+   +-----+
 |  A  |         |  B  |   |  U  |
 +-----+         +-----+   +-----+ 
     \             /         /
      \           /---------
       \         /
         +-----+           +-----+
         |  S  | --------- |  M  |
         +-----+           +-----+
            ⇅            /
      .~~~~~~~~~~~.     /
   .~~   INTERNET   ~~.
  '~~~~~~~~~~~~~~~~~~~'
```

- **A** e **B**: workstation legittime che generano traffico normale.  
- **U**: host non autorizzato, le cui richieste dovrebbero scatenare allarmi.  
- **M**: macchina malevola che esegue exploit e scansioni.  
- **S**: container Suricata, funge da router e sensore IDS/IPS; il traffico è replicato verso Suricata senza modificare il flusso principale.

## 🚀 Avvio

1. **Costruisci e avvia i container:**
    ```bash
    make
    ```
    oppure:
    ```bash
    docker-compose up -d --build
    ```

2. **Apri l’interfaccia grafica:**  
   Vai su [http://localhost:3000](http://localhost:3000).

## ⚙️ Funzionamento

1. **Cattura dei pacchetti**: Suricata sfrutta AF‑Packet o NFQueue in modalità promiscua per replicare tutto il traffico dal router “S”.  
2. **Verifica delle regole**: Ogni pacchetto viene confrontato con le firme in `custom.rules`; le corrispondenze generano allarmi (o, in IPS, il blocco del pacchetto).  
3. **Ingestione dei log**: Allarmi e flussi vengono scritti in JSON su `eve.json`, raccolti da Filebeat e inviati a Elasticsearch tramite Logstash.  
4. **Dashboard**: Con i template Kibana inclusi puoi esplorare:
   * Le firme più attivate  
   * Mappe di calore degli indirizzi IP  
   * Andamento temporale degli allarmi  
   * Suddivisione per protocollo

## 🧪 Test

Nel container **Malicious** (`M`), esegui gli script `.sh` presenti in `scripts/` per simulare minacce ICS (fuzzing Modbus/TCP, scansioni di porte, ecc.) e verificare il rilevamento da parte di Suricata.

## 📊 Dashboard (GUI)

La GUI, disponibile su [http://localhost:3000](http://localhost:3000), offre una vista interattiva dei dati di Elasticsearch.  
Per configurarla:

1. Aggiungi una nuova fonte dati in Elasticsearch: `http://elasticsearch:9200`.  
2. Importa il file JSON della dashboard (cartella `dashboards/`, se presente).  
3. Personalizza i grafici (numero di allarmi, regole principali, volume di traffico).

![suricata-gui](/images/suricata.png)