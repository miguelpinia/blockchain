#!/usr/bin/env python3

"""
Implementa una blockchain de juguete donde para cada bloque nuevo,
el puzzle criptográfico que debe resolver para agregar el bloque a la
cadena debe ser encontrar una hash de sha-256 a partir hash del bloque
anterior y un nonce.

Evaluación en terminal

$ python3 ejercicio.py
"""

import hashlib
import time
import signal
import sys
import pickle


def sha_256(val):
    """Calcula el hash para un valor dado.

    Ejemplo:

    >>> sha_256('foo')
    '2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae'"""
    HASH = hashlib.new('sha256')
    HASH.update(bytes(val.encode('utf-8')))
    return HASH.hexdigest()


def calcula_hash(bloque):
    """Calcula el hash para un bloque con estructura [hash, nonce].

    Ejemplo:

    >>> calcula_hash(['2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae', 0])
    '484be7fa5ff49679757b1ec4c18be5bf279ca56ff6ded2fab76d3704d2583fd1'"""
    hash_previo, nonce = bloque
    return sha_256('{}{}'.format(hash_previo, str(nonce)))


def valido(hash, dificultad):
    """Dado un nivel de dificultad, indica si el hash es válido para
    resolver el puzlle criptográfico.

    Ejemplo:

    Ejecución Falsa
    >>> valido('484be7fa5ff49679757b1ec4c18be5bf279ca56ff6ded2fab76d3704d2583fd1', 1)
    False

    Ejecución verdadera
    >>> valido('084be7fa5ff49679757b1ec4c18be5bf279ca56ff6ded2fab76d3704d2583fd1', 1)
    True"""
    return hash.startswith('0' * dificultad)


def inicia_bloque(valor):
    """Dado un valor cualquiera, genera inicializa una blockchain de
    tamaño 1, con cero como nonce y 0 segundos de generación."""
    return [(sha_256(valor), 0, 0)]


def nuevo_bloque(blockchain):
    """Genera un nuevo bloque para una blockchain dada

    Ejemplo:


    >>> blockchain = inicia_bloque('foo')

    >>> blockchain
    [('2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae', 0, 0)]

    >>> nuevo_bloque(blockchain)

    >>> blockchain
    [('2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae', 0, 0),
    ('484be7fa5ff49679757b1ec4c18be5bf279ca56ff6ded2fab76d3704d2583fd1', 0, 5.3999999999998494e-05)]"""
    nonce = 0
    bloque_previo = blockchain[-1]
    dificultad = int(len(blockchain) / 4)
    start = time.clock()
    nuevo_hash = calcula_hash((bloque_previo[0], nonce))
    while not valido(nuevo_hash, dificultad):
        nonce += 1
        nuevo_hash = calcula_hash((bloque_previo[0], nonce))
    end = time.clock() - start
    blockchain.append((nuevo_hash, nonce, end))


def info(blockchain):
    """Imprime información acerca del último bloque calculado."""
    longitud = len(blockchain)
    dificultad = int(longitud / 4)
    tiempo = blockchain[-1][2]
    print('Longitud de la lista: {} bloques\nDificultad: {}\n\
Tiempo en encontrar la última solución: {} segundos\n\n\n'.format(
        longitud,
        dificultad,
        tiempo))


def ejecuta():
    """Ejecuta la generación de una cadena de blockchain para el valor
    'Foo bar'"""
    blockchain = inicia_bloque('Foo bar')
    info(blockchain)
    while True:
        try:
            nuevo_bloque(blockchain)
            info(blockchain)
        except KeyboardInterrupt:
            with open('/tmp/blockchain.txt', 'w') as f:
                for b in blockchain:
                    f.write('{}\n'.format(b))
            print('Se guardó la blockchain generada en /tmp/blockchain.txt')
            sys.exit(0)


if __name__ == '__main__':
    ejecuta()
