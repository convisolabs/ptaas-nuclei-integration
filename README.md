<p align="center">
  <img src="https://raw.githubusercontent.com/convisoappsec/Burp-AppSecFlow/master/assets/readme/logo-conviso.png">
  <p align="center">PTaNI - PTaaS Nuclei Integration</p>
  <p align="center">
    <a href="/LICENSE.md">
      <img src="https://img.shields.io/badge/license-MIT-blue.svg">
    </a>
    <a href="https://github.com/convisolabs/ptaas-nuclei-integration/releases">
      <img src="https://img.shields.io/badge/stable%20version-gamma-green.svg">
    </a>
  </p>
</p>

---

## Summary

[AppSec Flow](https://blog.convisoappsec.com/en/appsec-flow-a-complete-devsecops-platform/) is a Software as a Service (SaaS) platform created by [Conviso](https://www.convisoappsec.com/) that supports the entire security cycle in the software development life cycle. It was created based on the Software Assurance Maturity Model (SAMM) - a project in the portfolio of the Open Web Application Security Project (OWASP) that defines a series of practices with the objective of improving software security. This tool [ptaas-nuclei-integration](https://github.com/convisolabs/ptaas-nuclei-integration) was been developed to serve as an extension to [AppSec Flow CLI](https://docs.convisoappsec.com/cli/installation). It aims to automate vulnerability issuance in [AppSec Flow](https://blog.convisoappsec.com/en/appsec-flow-a-complete-devsecops-platform/) using the [Nuclei](nuclei.projectdiscovery.io/) as a scanner engine.

---

## Documentation

### Download and install

```bash
# Download
git clone git@github.com:convisolabs/ptaas-nuclei-integration.git &&
  cd ptaas-nuclei-integration

# Install dependencies
pip3 install -r requirements.txt

# Get help
python3 src/main.py --help
```

### Options

```
usage: ptani [-h] -apk API_KEY -pid PROJECT_ID -no NUCLEI_OUTPUT [-eng] [-hml] [-L {DEBUG,INFO,WARNING,ERROR}]

ptaas-nuclei-integration@v:gamma -- MIT © Conviso 2021-2022 -- https://github.com/convisolabs/ptaas-nuclei-integration

optional arguments:
  -h, --help            show this help message and exit
  -apk API_KEY, --api-key API_KEY
                        Your apikey generated in Conviso Platform
  -pid PROJECT_ID, --project-id PROJECT_ID
                        Project ID in Conviso Platform
  -no NUCLEI_OUTPUT, --nuclei-output NUCLEI_OUTPUT
                        Nuclei test result file path. Input from pipe/STDIN use "-". i.e., --nuclei-output -
  -eng, --english       Issue reports in English
  -hml, --homologation  Use API in homologation enviroment. Useful for testing and development
  -L {DEBUG,INFO,WARNING,ERROR}, --log-level {DEBUG,INFO,WARNING,ERROR}
                        Log the occurred actions. Useful for debugging. Check "ptani.log" file


Usage examples: 
        From pipe: $ nuclei -irr -json -u https://www.target.com -t ~/nuclei-templates/misconfiguration/http-missing-security-headers.yaml | python -pid $PID -apk $CONVISO_APIKEY -no -
        From file: $ python3 -pid $PID -apk $CONVISO_APIKEY -no ./nuclei-output.json 
        
Observation: Nuclei parameters "-json" and "-irr" are required for script operation.
```

### Demos

- Installing PTaNI
![1-get ptani](https://user-images.githubusercontent.com/8931900/150802951-b43eb14e-b161-4869-87be-2e9e2cee34b0.gif )

---

## Contribution

- Your contributions and suggestions are heartily ♥ welcome. [See here the contribution guidelines.](/.github/CONTRIBUTING.md) Please, report bugs via [issues page](https://github.com/convisolabs/ptaas-nuclei-integration/issues) and for security issues, see here the [security policy.](/SECURITY.md)

---

## License

- This work is licensed under [MIT License.](/LICENSE.md)
