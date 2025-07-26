---
title: "Suricata Testing \U0001F6E1"
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
description: "A setup for Suricata in IDS mode (and IPS if needed) to protect a simulated industrial network."
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
    alt: "Suricata Testing" # alt text
    caption: "A setup for Suricata in IDS mode (and IPS if needed) to protect a simulated industrial network." # display caption under cover
    relative: false # when using page bundles set this to true
    hidden: true # only hide on current single page
editPost:
    URL: "https://github.com/AlBovo/AlBovo.github.io/blob/main/content/en"
    Text: "Suggest Changes" # edit text
    appendFilePath: true # to append file path to Edit link
---
# Suricata testing 🛡️

## 📋 Overview

Suricata is a high‑performance, open‑source Network Intrusion Detection System (IDS), Intrusion Prevention System (IPS) and Network Security Monitoring (NSM) engine maintained by the Open Information Security Foundation (OISF). 
This repository provides a turnkey environment, using Docker and Docker Compose, to deploy Suricata in IDS mode (with an option for IPS) against a **simulated industrial network**, enabling you to test custom detection rules, generate realistic traffic patterns, and visualize alerts in real time.

## 🎯 Objective

Setup Suricata in IDS mode (and IPS if needed) to protect a simulated industrial network.

## 🛠️ Key Features

- **Multi‑mode operation**: Run Suricata in IDS mode for passive monitoring or inline IPS mode to actively block malicious traffic.
- **Custom ruleset**: Define and test signatures in `custom.rules` to detect anything from basic port scans to complex industrial protocol anomalies.  
- **Traffic simulation**: Generate both legitimate and malicious traffic using example scripts under `scripts/`, mimicking user workstations (A, B), unauthorized hosts (U), and an attacker node (M).  
- **Scalable architecture**: Each component runs in its own container, making it easy to extend the network or swap out components for more advanced setups.  
- **Live visualization**: Ingest alerts into Elasticsearch and explore them via a Kibana dashboard, templates provided, so you can monitor detections and explore network trends.

## 🌐 Network Structure

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

- **A** and **B**: Authorized workstations generating normal industrial traffic.  
- **U**: Unauthorized host whose requests should trigger alerts.  
- **M**: Malicious node running exploit and scanning scripts.  
- **S**: Suricata container acting as both router (routing engine) and IDS/IPS sensor. Traffic mirroring is configured to feed packets into Suricata without altering production flow.

## 🚀 How to Run

1. **Build and start the services:**
    ```bash
    make
    ```

    Or:

    ```bash
    docker-compose up -d --build
    ```

2. **Access the GUI:**
    
    Open your browser to [http://localhost:3000](http://localhost:3000).

## ⚙️ How It Works

1. **Packet capture**: Suricata uses AF‑Packet or NFQueue in promiscuous mode to mirror all forwarded packets from the “S” router container.
2. **Rule matching**: Each packet is evaluated against rules in `custom.rules`. Matching packets generate alerts (and, in IPS mode, can be dropped).
3. **Log ingestion**: Alerts and flow logs are output in JSON to the `eve.json` log file, then picked up by Filebeat and shipped through Logstash into Elasticsearch.
4. **Dashboard visualization**: The included Kibana templates let you view:

   * Top threat signatures triggered
   * Source/destination IP heatmaps
   * Timeline of alerts
   * Protocol‑specific breakdowns

## 🧪 Tests

Launch attack or scanning scripts from the **Malicious** container (`M`) by running any of the `.sh` files in `scripts/`. These simulate real-world ICS threats (e.g., Modbus/TCP fuzzing, port scans) so you can verify that Suricata flags them.

## 📊 GUI

The GUI at [http://localhost:3000](http://localhost:3000) presents an interactive dashboard built on Elasticsearch data.
To set it up:

1. Create a new Elasticsearch data source: `http://elasticsearch:9200`.
2. Import the provided Kibana dashboard JSON (in `dashboards/` if you add one).
3. Customize charts to display metrics like alert counts, top rules, and traffic volume.

![suriacta-gui](/images/suricata.png)