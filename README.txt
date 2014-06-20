Projekt do p�edm�tu PDS - Agregace a t��d�n�
Autor: Tom� Mikulica, xmikul45

P�elo�en� projektu: 
v adres��i src/ p��kazem make

Parametry spu�t�n�:
flow -f directory -a aggregation -s sort
directory - Vstupn� adres�� s bin�rn�mi soubory. Program zpracuje v�echny 
            soubory v adres��i (pokud je to p��mo soubor, zpracuje se ten). 
aggregation - Podle jak�ho kl��e se budou toky agregovat. Povolen� hodnoty:
              srcip, dstip, srcport, dstport, srcip4/x, dstip4/x, srcip6/x,
              dstip6/x, kde x je ��slo v rozmez� 1-32 pro ipv4 a 1-128 pro ipv6. 
sort - Podle jak�ho kl��e se bude t��dit. Hodnoty: packets, bytes.

Omezen�:
Program nekontroluje, zda se v parametru -a za symbolem / (nap�. srcip4/) 
nach�z� pouze ��slo (tj. neo�et�uje p��pady, kdy /3a1 nebo za / nen� nic)

Zdroje:
http://en.cppreference.com/w/cpp/container/unordered_map/unordered_map
http://en.cppreference.com/w/cpp/utility/hash/operator()
http://en.cppreference.com/w/cpp/algorithm/sort