# ptaas-nuclei-integration [#](https://app.clickup.com/t/3016679/PS-9146)
> Tool for integration between Nuclei and Octopus to automate the identification and issuance of vulnerability reports.

### Getting Started

1. Installation

```bash
git clone git@github.com:convisolabs/ptaas-nuclei-integration.git

cd ptaas-nuclei-integration
```

2. Integrate in your shell

```bash
cat<EOF>>~/.bashrc
alias ptani="$(pwd)/ptaas-nuclei-integration/src/main.py"
EOF
```

### Usage

```bash
# parse nuclei output scan to generate automated reports in APPSECFLOW 
nuclei -include-rr --json --template <template_path> | python src/main.py -sid 278 -pid 2730 

# run nuclei in background
python src/main.py --template <template_path> -sid 278 -pid 2730

# from alias
ptani --help
```

-----------------------------------------------------------

### References

- https://github.com/convisolabs/Burp-AppSecFlow/blob/master/src/main/java/models/graphql/query/GraphQLQueries.java
- https://stackoverflow.com/questions/39303181/wait-for-user-input-when-not-sys-stdin-isatty#61962566
- https://pypi.org/project/pyCLI/
- https://pypi.org/project/click/
- https://pypi.org/project/PyInquirer/
- https://nuclei.projectdiscovery.io/template-examples/http/#matchers-with-conditions
- https://docs.python.org/3/library/argparse.html
- https://pypi.org/project/python-graphql-client/
- https://gql.readthedocs.io/en/latest/intro.html
- https://www.w3schools.com/python/ref_func_map.asp
- https://refactoring.guru/design-patterns/abstract-factory
- https://stackoverflow.com/questions/7576525/optional-stdin-in-python-with-argparse
- https://nuclei.projectdiscovery.io/templating-guide/operators/matchers/#negative-matchers
- https://realpython.com/python-reduce-function/#reducing-iterables-with-pythons-reduce
- https://gist.github.com/andersonbosa/feded0dcb0d6e12f39bd78bf29c79a64
- https://stackoverflow.com/questions/28228345/how-to-search-through-dictionaries