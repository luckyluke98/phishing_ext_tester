# phishing_ext_tester

Script in python per tesatre l'algorimto dell'estensione anti-phishing. 

## Funzionamento

Lo script è stato realizzato per testare fuori dal browser l'algoritmo dell'estensione anti-phishing. Il suo funzionamento consiste nell'analizzare una lista di domini (dataset.yaml) la quale contiene domini di phishing, verificati dal tool [phishing_catcher](https://github.com/x0rz/phishing_catcher) e da [PhishTank](https://www.phishtank.com), e domini leciti.

L'algoritmo di detection è basato su features domain-based, prese da [phishing_catcher](https://github.com/x0rz/phishing_catcher), e features content-based, estrapolate dai seguenti articoli:

* "Machine Learning Approach to Phishing Detection"
* "Intelligent phishing url detection using association rule mining"
* "Intelligent Rule based Phishing Websites Classification"

L'algoritmo di detection mette insieme i due approcci. Ad ogni dominio nella lista verrà assegnato un punteggio in base al quale verrà etichettato come di phishing o meno.
Il punteggi assegnati alle features domain-based sono stati estrapolati dal tool di [x0rz](https://github.com/x0rz), mentre i pesi delle features content-based sono estratti dagli articoli sopra indicati, in particolor modo da **"Machine Learning Approach to Phishing Detection"**.

L'algoritmo andrà a verificare la presenza o meno di tutte le features. Le features content-based restituiranno ```1``` (se la features si verifica), ```0``` (se si verifica parzialmente) o ```-1``` (se non si verifica),  successivamente questi valori verranno moltiplicati con i rispettivi pesi. Quindi il punteggio content-based sarà un numero ```<=0``` o ```>=0```.

Le features domain-based restituiranno invece ```1``` (se si verifica) o ```0``` (se non si verfica), che successivamente verrano moltipicati con i rispettivi pesi, oppure restituiranno direttamente un punteggio.

I punteggi dei due gruppi di features successivamente verranno sommati insieme, da cui si avrà che:

* se il punteggio è ```>= 60``` il dominio verrà valutato come di phishing ed assegnato il valore ```1```
* se il punteggio è ```<60``` il dominio verrà valutato come sicuro ed assegnato il valore ```0```

Per verificare il corretto rilevamento, i valori (0 o 1) risultanti, verranno confrontati con i vaolri all'interno della lista dei domini utilizzati per il test ```dataset.yaml``` . Il file è cosi formattato:
```yaml
data:
  ...
  'safe_domain': 0
  'phishing_domain': 1
  ...
```
Al termine dello script verranno visualizzati i seguneti risulati (risultati per ```dataset.yaml```):
```
+------------+---------+----------+
|   TOT:110  | Actual: | Actual:  |
|  pos: 88   |   POS   |   NEG    |
|  neg: 22   |         |          |
+------------+---------+----------+
| Predicted: |    65   |    7     |
|    POS     |         |          |
+------------+---------+----------+
| Predicted: |    23   |    15    |
|    NEG     |         |          |
+------------+---------+----------+


+-------------+-------------+----------+-----------+
| Sensitivity | Specificity | Accuracy | Precision |
+-------------+-------------+----------+-----------+
| 0.74        | 0.68        | 0.73     | 0.9       |
+-------------+-------------+----------+-----------+
```
## Utilizzo

Per eseguire lo script sarà sufficiente eseguire:

```shell
$ python3 main.py 
```
Requisiti

* bs4
* termcolor
* terminaltables 
* yaml
* requests
* tld
* tldextract
* Levenshtein

![Image](https://github.com/luckyluke98/phishing_ext_tester/blob/main/images/screen.gif)

## Licenza
GNU GPLv3
