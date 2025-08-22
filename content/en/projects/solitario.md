---
title: "Solitario Croce"
date: 2024-07-22T00:00:00+00:00
# weight: 1
tags: ["solitaire", "game", "c#", "wpf", "project-work", "school", "homework"]
author: ["AlBovo", "Mark-74"]
# author: ["Me", "You"] # multiple authors
showToc: true
TocOpen: false
draft: false
hidemeta: false
comments: false
description: "A school project about a solitaire card game designed by a small team of students."
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
    image: "" # TODO: add image path/url
    alt: "Solitario Croce" # alt text
    caption: "A school project about a solitaire card game designed by a small team of students." # display caption under cover
    relative: false # when using page bundles set this to true
    hidden: true # only hide on current single page
editPost:
    URL: "https://github.com/AlBovo/AlBovo.github.io/blob/main/content/en"
    Text: "Suggest Changes" # edit text
    appendFilePath: true # to append file path to Edit link
---
# Solitario Croce ♣️
Development of a game 🎮 in C# using the WPF framework; the game is a solitaire based on customized playing cards.

## Development team 🤖
This project has been developed by:

- **Agostini** Alan
- **Angiolillo** Matteo
- **Balducci** Marco
- **Bovo** Alan Davide


## Game 🎮
The game we developed is the Solitario a Croce.
{{< youtube g7TJviLmuMg >}}

**How to play 🤔:** Five cards from the *deck* are placed in the center of the table to form a **cross ➕**. Four positions, called *bases*, are left free.

The goal of the *solitaire game* is to build and complete the bases (from ace to king for each suit, in ascending order) by transferring all the cards to them. While the bases must follow the rule of the same suit in ascending order, the cross follows the rule of different suits in descending order.

The top card of each pile forming the cross can be moved to the bases, placed in an empty spot, or on top of another card in the cross. Only one card can be moved at a time. The card from the stock can go directly to the bases or be transferred to the table.

**Type of cards:** Italian 🇮🇹 cards (4 suits ♠️ ♣️ ♥️ ♦️, 10 cards per suit).