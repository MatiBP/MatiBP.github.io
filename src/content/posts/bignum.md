---
title: Bignum
published: 2024-07-01
tags: [RSA, c++]
category: 'Crypto'
draft: false
---

# Bignum

Le projet **Bignum** consistait à réimplémenter l'algorithme RSA en **C++**. Pour réaliser cela, il a été nécessaire de développer une bibliothèque de gestion de **grands nombres** (BigNum), car les calculs utilisés dans RSA nécessitent des opérations sur des entiers de très grande taille, bien au-delà de ce que peuvent gérer les types de données natifs.

La réimplémentation de la bibliothèque de grands nombres a permis d'effectuer des opérations telles que l'addition, la soustraction, la multiplication, la division, ainsi que l'exponentiation modulaire, nécessaires pour le chiffrement et déchiffrement RSA.

Pour plus de détails, le projet est disponible sur GitHub :

[GitHub - Bignum Project](https://github.com/MatiBP/bignum)
