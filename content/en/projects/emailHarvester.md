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
description: "A tool that discovers email addresses associated with a company's domain and checks whether the organization has been involved in any past data breaches."
canonicalURL: "https://albovo.github.io/en/projects/"
disableHLJS: false
disableShare: false
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
    caption: "A project about the famous minesweeper game made for Console or Web GUI." # display caption under cover
    relative: false # when using page bundles set this to true
    hidden: true # only hide on current single page
editPost:
    URL: "https://github.com/AlBovo/AlBovo.github.io/blob/main/content/en"
    Text: "Suggest Changes" # edit text
    appendFilePath: true # to append file path to Edit link
---
# Email Harvester 🕵️‍♂️

## 📋 Overview
Email Harvester is a full‑stack web application that automatically discovers email addresses under a given domain, checks each against public data‑breach APIs to flag compromised accounts and presents the results in a simple, interactive interface. It combines a Flask‑powered Python backend for scraping and breach lookups with a Node.js/EJS frontend, all orchestrated via Docker Compose for one‑step deployment.

## 🎯 Key Features
- **Domain email scraping**: Crawl websites and public resources to extract email addresses.  
- **Asynchronous processing**: Backend tasks run in parallel for high throughput.  
- **Secure vs. predicted**: Classify emails found directly (“secure”) versus those inferred by pattern (“predicted”).  
- **Breach verification**: Integrate with HaveIBeenPwned (or similar) to highlight compromised addresses.  
- **Intuitive UI**: Built with Node.js and EJS templates for real‑time feedback.  
- **Persistent storage**: Store results in MongoDB for later analysis and export.  
- **Containerized deployment**: Docker Compose script brings up all services (backend, frontend, database) in one command.

## 🏗️ Architecture
1. **Backend (Flask/Python)**  
    - Exposes REST endpoints to initiate domain scans, retrieve stored results and perform breach checks.  
    - Utilizes asynchronous HTTP requests and background workers to handle large crawls.  
2. **Frontend (Node.js/EJS)**  
    - Renders search form and results pages.  
    - Interacts with the backend API to start scans and fetch updates.  
3. **Database (MongoDB)**  
    - Persists scraped email addresses, classification tags and breach‑status metadata.  
4. **Orchestration**  
    - Docker Compose defines three services: `backend`, `frontend` and `mongodb`, ensuring consistent environments and easy scaling.

## 🔧 Prerequisites
- [Docker](https://docs.docker.com/)  
- [Docker Compose](https://docs.docker.com/compose/)

## 🚀 Getting Started
1. **Clone the repo**  
    ```bash
    git clone https://github.com/AlBovo/emailHarvester.git
    cd emailHarvester
    ```

2. **Configure**

    * Copy `.env.example` to `.env` and set your MongoDB URI and breach‑API key.
3. **Build & run**

    ```bash
    docker-compose up -d --build
    ```
4. **Access the app**
    
    Open [http://localhost:3000](http://localhost:3000) in your browser.

## ⚙️ Usage
1. Enter the **target domain** in the search field.
2. Click **“Harvest”** to start scraping and breach verification.
3. View the **results table**, with each email’s classification and breach status.
4. Export or clear results as needed via the UI controls.

## 🖼️ Screenshots
![Home Page](/images/emailhomepage.png)
![Result Page](/images/emailresultpage.png)
