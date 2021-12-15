<p align="center">
  <img src="https://raw.githubusercontent.com/convisoappsec/ptani/master/assets/readme/logo-conviso.png">
  <p align="center">PTaNI - PTaaS Nuclei Integration</p>
  <p align="center">
    <a href="/LICENSE.md">
      <img src="https://img.shields.io/badge/license-MIT-blue.svg">
    </a>
    <a href="https://github.com/convisoappsec/ptani/releases">
      <img src="https://img.shields.io/badge/version-1.0.0-blue.svg">
    </a>
  </p>
</p>

---

### Summary

[AppSec Flow](https://blog.convisoappsec.com/en/appsec-flow-a-complete-devsecops-platform/) is a Software as a Service (SaaS) platform created by [Conviso](https://www.convisoappsec.com/) that supports the entire security cycle in the software development life cycle. It was created based on the Software Assurance Maturity Model (SAMM) - a project in the portfolio of the Open Web Application Security Project (OWASP) that defines a series of practices with the objective of improving software security. This tool [PTaNI](https://github.com/convisolabs/ptaas-nuclei-integration) was been developed to serve as an extension to [AppSec Flow CLI](https://docs.convisoappsec.com/cli/installation). It aims to automate vulnerability issuance in [AppSec Flow](https://blog.convisoappsec.com/en/appsec-flow-a-complete-devsecops-platform/) using the [Nuclei](nuclei.projectdiscovery.io/) as a scanner engine.

> Automated identification and issuance of vulnerability reports to Conviso Platform using nuclei as scanner engine.

---

### Documentation

You can find the full documentation at: [wiki page.](https://github.com/convisoappsec/ptani/wiki)

---

### Contribution

- Your contributions and suggestions are heartily ♥ welcome. [See here the contribution guidelines.](/.github/CONTRIBUTING.md) Please, report bugs via [issues page](https://github.com/convisoappsec/ptani/issues) and for security issues, see here the [security policy.](/SECURITY.md)

---

### License

- This work is licensed under [MIT License.](/LICENSE.md)

---

### References

> Left here for anyone who wants to know how the development process went. Reference links were added in chronological order, as doubts arose.

- https://nuclei.projectdiscovery.io/template-examples/http/#matchers-with-conditions
- https://pypi.org/project/pyCLI/
- https://pypi.org/project/click/
- https://pypi.org/project/PyInquirer/
- https://docs.python.org/3/library/argparse.html
- https://docs.python.org/3/library/venv.html
- https://pypi.org/project/python-graphql-client/
- https://gql.readthedocs.io/en/latest/intro.html
- https://github.com/convisolabs/ptani/blob/master/src/main/java/models/graphql/query/GraphQLQueries.java
- https://stackoverflow.com/questions/39303181/wait-for-user-input-when-not-sys-stdin-isatty#61962566
- https://www.w3schools.com/python/ref_func_map.asp
- https://refactoring.guru/design-patterns/abstract-factory
- https://stackoverflow.com/questions/7576525/optional-stdin-in-python-with-argparse
- https://nuclei.projectdiscovery.io/templating-guide/operators/matchers/#negative-matchers
- https://realpython.com/python-reduce-function/#reducing-iterables-with-pythons-reduce
- https://gist.github.com/andersonbosa/feded0dcb0d6e12f39bd78bf29c79a64
- https://stackoverflow.com/questions/28228345/how-to-search-through-dictionaries
