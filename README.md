# phishing_ext_tester

Python script to test the algorimto of the anti-phishing extension.

## How work?

The script was created to test the anti-phishing extension algorithm outside the browser. Its working consists in analyzing a list of domains which contains phishing domains, verified by tool [phishing_catcher](https://github.com/x0rz/phishing_catcher) and [PhishTank](https://www.phishtank.com), and legal domains.

The detection algorithm is based on domain-based features, taken from [phishing_catcher](https://github.com/x0rz/phishing_catcher), and content-based features, extrapolated from the following articles:

* A. R. Sura, J. Kini, and K. Athrey. [Machine Learning Approach to Phishing Detection](https://github.com/arvind-rs/phishing_detector/blob/master/Final%20Report/Report.pdf)
* Jeeva, S.C., Rajsingh, E.B. Intelligent phishing url detection using association rule mining. Hum. Cent. Comput. Inf. Sci. 6, 10 (2016). https://doi.org/10.1186/s13673-016-0064-3
* Mohammad, Rami & Mccluskey, T. & Thabtah, Fadi. (2013). Intelligent Rule based Phishing Websites Classification. IET Information Security. 8. 10.1049/iet-ifs.2013.0202. 

The detection algorithm brings the two approaches together. Each domain in the list will be given a score according to which it will be labeled as phishing or not.
The scores assigned to the domain-based features have been extrapolated from the tool of [x0rz](https://github.com/x0rz), while the weights of the content-based features are extracted from the articles above, especially by **"[Machine Learning Approach to Phishing Detection](https://github.com/arvind-rs/phishing_detector/blob/master/Final%20Report/Report.pdf)"**.

The algorithm will check whether or not all the features are present. Content-based features will return ```1``` (if features occur), ```0``` (if partially occur) or ```-1``` (if they do not occur), then these values will be multiplied with the respective weights. So the content-based score will be ```<=0``` or ```>=0```.

Domain-based features will return ```1``` (if they occur) or ```0``` (if they do not occur), then they will be multiplied with their respective weights.

The scores of the two groups of features will then be added together, from which:

* if the score is ```>= 60``` the domain will be rated as phishing and assigned the value ```1```
* if the score is ```<60```  the domain will be rated as secure and assigned the value ```0```

To verify the correct detection, the resulting values (0 or 1) will be compared with the values within the list of domains used for the test (```dataset.yaml```). ```dataset.yaml``` is formatted as follows:
```yaml
data:
  ...
  #'safe_domain': 0
  #'phishing_domain': 1
  'www.google.com': 0
  'www.scam.com': 1
  ...
```
At the end of the script the following results will be displayed (results for ```dataset.yaml```):
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
## Usage

To run the script, simply run:

```shell
$ python3 main.py 
```
Requirements

* bs4
* termcolor
* terminaltables 
* yaml
* requests
* tld
* tldextract
* Levenshtein

![Image](https://github.com/luckyluke98/phishing_ext_tester/blob/main/images/screen.gif)

## License
GNU GPLv3
