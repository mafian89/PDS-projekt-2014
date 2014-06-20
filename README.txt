Projekt do pøedmìtu PDS - Agregace a tøídìní
Autor: Tomáš Mikulica, xmikul45

Pøeložení projektu: 
v adresáøi src/ pøíkazem make

Parametry spuštìní:
flow -f directory -a aggregation -s sort
directory - Vstupní adresáø s binárními soubory. Program zpracuje všechny 
            soubory v adresáøi (pokud je to pøímo soubor, zpracuje se ten). 
aggregation - Podle jakého klíèe se budou toky agregovat. Povolené hodnoty:
              srcip, dstip, srcport, dstport, srcip4/x, dstip4/x, srcip6/x,
              dstip6/x, kde x je èíslo v rozmezí 1-32 pro ipv4 a 1-128 pro ipv6. 
sort - Podle jakého klíèe se bude tøídit. Hodnoty: packets, bytes.

Omezení:
Program nekontroluje, zda se v parametru -a za symbolem / (napø. srcip4/) 
nachází pouze èíslo (tj. neošetøuje pøípady, kdy /3a1 nebo za / není nic)

Zdroje:
http://en.cppreference.com/w/cpp/container/unordered_map/unordered_map
http://en.cppreference.com/w/cpp/utility/hash/operator()
http://en.cppreference.com/w/cpp/algorithm/sort