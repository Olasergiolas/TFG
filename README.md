# Bachelor's Thesis: "*Introduction to fuzzing, use and fuzzing strategies to find vulnerabilities in IoT devices*"

### **Author** :bust_in_silhouette:: Sergio García Cabrera :octocat: [@Olasergiolas](https://github.com/Olasergiolas)
### **Tutor** :bust_in_silhouette:: Gustavo Romero López
___

## Introduction ✏️
**Fuzzing** is a technique that tries to identify bugs and vulnerabilities in software by repeatedly running code using input data that is modified during the process. The main goal is to find an input that is not properly managed by the software, leading to crashes and instability. This technique has proven to help find bugs that would otherwise not be found by other means and even while presenting difficult challenges to take on, fuzzing is of special interest in the field of IoT since it can help alleviate the current suboptimal state of security in these devices. This way, the number of bugs present in firmware that in some cases will never be updated by the end-user is reduced, with the consequent improvement in the industry's security standards.

During this project, we will try to **investigate and implement** some of the current different approaches of code **IoT fuzzing**, while also trying to propose solutions to the additional challenges that come with this type of fuzzing. 

## Documentation 📖

### Document
The thesis in PDF format can be obtained from the latest [release](https://github.com/Olasergiolas/TFG/releases) available in this repository.

If needed, the document in PDF format can also be generated manually from the `LaTeX` files present at `Memoria/doc/` using `TeXLive` or any other `LaTeX` distribution. From this path, use the following command to generate the document.
```bash
$ pdflatex proyecto.tex
```

Once successfully finished, a file named `proyecto.pdf` should have been created at the current path.

### Repository
Alongside the documentation included in the thesis document, each one of the experiments that were performed have also been documented in this repository:

- [**Fuzzing the cJSON library**](Fuzzing/QEMU/cJSON/README.md)
- [**Qiling Proof of Concept**](Fuzzing/Qiling/PoC/README.md)
- [**Fuzzing Netgear R7000's firmware upgrade process**](Fuzzing/Qiling/netgear)

## Tools 🧰
Additionally, a Docker image has been provided in order to facilitate the process of reproducing these experiments. This image comes preinstalled with the different utilities that have been used and can be downloaded from [Dockerhub](https://hub.docker.com/repository/docker/olasergiolas/multiarch-fuzzing) by using the following command.

```bash
$ docker pull olasergiolas/multiarch-fuzzing
```