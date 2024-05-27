---
title: "Minesweeper \U0001F6A9"
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
description: "A project about the famous minesweeper game made for Console or Web GUI."
canonicalURL: "https://albovo.tech/en/project/"
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
    alt: "Minesweeper game" # alt text
    caption: "A project about the famous minesweeper game made for Console or Web GUI." # display caption under cover
    relative: false # when using page bundles set this to true
    hidden: true # only hide on current single page
editPost:
    URL: "https://github.com/AlBovo/AlBovo.github.io/blob/main/content/en"
    Text: "Suggest Changes" # edit text
    appendFilePath: true # to append file path to Edit link
---
# Minesweeper Game 🚩
> Minesweeper is a classic computer game that requires a combination of strategy and logic. The game is played on a grid, and the objective is to uncover all the hidden mines without detonating any of them. To do this, players click on individual squares, and the numbers revealed indicate the number of mines in adjacent squares. Armed with this information, players use deductive reasoning to mark squares they suspect contain mines with flags and gradually clear the grid of all non-mined areas. The challenge lies in making calculated guesses and avoiding mines, and successful Minesweeper players often develop a keen eye for patterns and strategies to conquer the game.

ChatGPT.

## How to play 🎮
To play the terminal version, you need to compile the source code or download the release (see [installation](#install-)), execute it, and follow the prompts until it requests you to uncover a square.
This request will specify coordinates X Y (e.g., 1 4), starting from 1 and going up to 16. 
To play on the web, simply right-click to flag a selected square as a bomb, and use the left-click to reveal it.

## Install 📦
In this repository, there are two types of software, one for the [terminal](#terminal-) and the other with a [web-based GUI](#web-gui-).

### Terminal 💻
At the moment I am writing this, Mine for the terminal is only tested on Linux using g++20. The commands to compile it are as follows:

#### Release 🚀
```bash
g++ -std=c++20 colors.cpp utils.cpp main.cpp -o mine
```

#### Debug 🛠️
```bash
g++ -std=c++20 colors.cpp utils.cpp main.cpp -fsanitize=address -g -o mine
```
If you find any bug feel free to open an issue/pull request.

### Web GUI 🌐
Regarding the website I've developed, it can be run as a Docker container by executing these commands:
```bash
cd Mine/site/
docker build -t mine/mine:latest .
docker run mine/mine:latest
```
Then Docker will display the local port where the website is being hosted.

## How does it look like 👀
![web gui](/screenWeb.png)
![console](/screenTerminal.png)