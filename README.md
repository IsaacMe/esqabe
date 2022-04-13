# Encrypted Search Query Analysis By Eavesdropping (ESQABE)
ESQABE analyses network traffic traces in order to determine the search query a user entered on an online search engine.
Most of the traffic generated is HTTPS encrypted, but useful information is still leaked through side-channels and other
protocols.

Find out more in [our paper](https://doi.org/10.1007/978-3-030-78120-0_7) published at IFIP SEC 2021. Research done at Hasselt University/EDM/Flanders Make.

The WebExtension with defences against ESQABE (and other search query fingerprinting techniques) is located in a
separate repository called [ESQABE-Defences](https://github.com/IsaacMe/esqabe-defences).

## Getting started
- Python 3 is required. [Pipenv](https://pypi.org/project/pipenv/) is recommended (otherwise all dependencies need to be installed manually)
- Install all dependencies listed in the `Pipfile`. With Pipenv, run `pipenv install`
- For the fingerprinting part, Weka needs to be installed. The install path needs to be set in `esqabe/fingerprinting/config.py` More info [here](https://github.com/kpdyer/website-fingerprinting).
- Start the tool with: `python main.py trace.pcapng` 

## Citing
Accompanying paper published at IFIP SEC 2021. If this project was helpful to you, please list the following citation in your work: 
> Meers I., Di Martino M., Quax P., Lamotte W. (2021) ESQABE: Predicting Encrypted Search Queries. In: Jøsang A., Futcher L., Hagen J. (eds) ICT Systems Security and Privacy Protection. SEC 2021. IFIP Advances in Information and Communication Technology, vol 625. Springer, Cham. https://doi.org/10.1007/978-3-030-78120-0_7

## References
This work builds further on previous work by other great researchers:

- [kreep](https://github.com/vmonaco/kreep): Keystroke Recognition and Entropy Elimination Program by Vinnie Monaco
- [Traffic Analysis Framework](https://github.com/kpdyer/website-fingerprinting) by Kevin P. Dyer
