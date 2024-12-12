# Edge-Cloud-Privacy-Control

This repository contains the code implementation for the paper:

**"Certificateless and Revocable Bilateral Access Control for Privacy-Preserving Edge-Cloud Computing"**

It serves as a prototype scheme for academic research purposes.

---

## Citation

If you use this code, please cite our paper as follows:

```
@ARTICLE{10786356,
  author={Huang, Qi-An and Si, Yain-Whar},
  journal={IEEE Internet of Things Journal},
  title={Certificateless and Revocable Bilateral Access Control for Privacy-Preserving Edge-Cloud Computing},
  year={2024},
  volume={},
  number={},
  pages={1-1},
  keywords={Cloud computing;Encryption;Access control;Internet of Things;Security;Outsourcing;Servers;Privacy;Data privacy;Protection;Edge-cloud computing;Bilateral access control;Privacy-Preserving;Revocation},
  doi={10.1109/JIOT.2024.3513326}
}
```

---

## Description

This implementation demonstrates a certificateless and revocable bilateral access control mechanism tailored for privacy-preserving edge-cloud computing environments. The scheme focuses on ensuring robust security and privacy protections while addressing challenges in:

- **Certificateless cryptography**: Reducing overhead by eliminating the need for traditional certificates.
- **Revocable access control**: Enabling efficient revocation of user access when needed.
- **Privacy preservation**: Safeguarding sensitive data during storage and computation in edge-cloud ecosystems.

---

## Prerequisites

### Charm-Crypto Library

This implementation relies on the [Charm-Crypto](https://github.com/JHUISI/charm) library, a powerful framework for rapid prototyping of cryptographic schemes. Ensure you have Charm-Crypto installed before running this code.

### Installation Guide for Charm-Crypto

1. Clone the Charm-Crypto repository:
   ```bash
   git clone https://github.com/JHUISI/charm.git
   cd charm
   ```
2. Install the necessary dependencies:
   ```bash
   sudo apt-get install build-essential python3-dev libgmp-dev libssl-dev
   ```
3. Build and install Charm-Crypto:
   ```bash
   ./configure.sh
   make
   sudo make install
   ```
   For detailed instructions, refer to the [Charm-Crypto GitHub page](https://github.com/JHUISI/charm).

---

## Usage

1. Clone this repository:
   ```bash
   git clone https://github.com/your_username/Edge-Cloud-Privacy-Control.git
   cd Edge-Cloud-Privacy-Control
   ```

2. Run the provided scripts to test the prototype.
   
   ```bash
   python3 main.py
   ```

---

## Note

This implementation is for academic research and prototype demonstration only. It is not recommended for use in production environments without further security enhancements and optimizations.

---

## Contributions

Feel free to contribute to the project by submitting issues or pull requests. Your feedback is valuable for improving this work.

---

## License

This project is released under the MIT License. See the LICENSE file for more details.

