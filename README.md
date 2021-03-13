# phishing_ext_tester

Script in python per tesatre l'algorimto dell'estensione anti-phishing. 

##Funzionamento

Lo script è stato realizzato per testare fuori dal browser l'algoritmo dell'estensione anti-phishing. Il suo funzionamento consiste nell'andare ad analizzare una lista di domini (dataset.yaml) la quale contiene domini di phishing, verificati dal tool phishing_catcher e da PhishTank, e domini leciti.

Il contenuto del file dataset.yaml è cosi formattato:
```yaml
data:
  ...
  'safe_domain': 0
  'phishing_domain': 1
  ...
```
