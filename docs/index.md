<!--
title: NUCLEI + APPSECFLOW = Automated identification and issuance of vulnerability reports to Conviso Platform using nuclei as scanner engine.
layout: hacker
-->

---

## Getting Started

### Usage

```
$ flow_ptani
usage: ptani [-h] -apk API_KEY -pid PROJECT_ID [-no NUCLEI_OUTPUT]

ptaas-nuclei-integration@v1.0.0 - MIT © Conviso 2021

optional arguments:
  -h, --help            show this help message and exit
  -apk API_KEY, --api-key API_KEY
                        Api Key in APPSecFlow.
  -pid PROJECT_ID, --project-id PROJECT_ID
                        Project ID in APPSecFlow.
  -no NUCLEI_OUTPUT, --nuclei-output NUCLEI_OUTPUT
                        Nuclei test result file path.
```

- Getting [Nuclei][nucleipage] test results and issuing them as reports on the [Conviso platform][flowpage]:

```bash
nuclei --json -irr -t <nuclei_test_template> -u https://www.target-scope.com | python3 ptaas-nuclei-integration/src/main.py -pid 1234 -apk <your_flow_apikey>

# or, as described below in "Shell integration":

flow_ptani <project_id> <target_url>
flow_ptani 1234 https://www.target-scope.com
```

- ⚠️ **disclaimer**: the paremeters `-json` and `-irr` from `nuclei` are needed. Because it, we strongly recommend you using the wrapper function, `flow_ptani`. [See here to setup](#shell-integration).

### Installation

```bash
git clone git@github.com:convisolabs/ptaas-nuclei-integration.git

cd ptaas-nuclei-integration

pip3 install -r requirements.txt
```

- Note that this tool is an extension to integrate [Nuclei][nucleipage] and [Conviso AppSec Flow][flowpage]. So it only works with Nuclei output.

### Optionally, you can use aile

<div align=center>
  <img src="./env_file.png">
</div>

- Useful for development. To an example check [.env.example](../.env.example).

### Shell integration

- A more convenient way to run this program can be done as follows. Add to your `.bashrc` the following lines:

```bash
export _CONVISO_FLOW_APIKEY="<your api key>"
alias ptani="python3 $_ptani_script_path -apk $CONVISO_FLOW_APIKEY"
function flow_ptani() {
  local _project_pid="$1"
  local _target_url="$2"
  local _ptani_script_path="<script_path>/ptaas-nuclei-integration/src/main.py"

  if [[ -z $_project_pid ]] || [[ -z $_target_url ]]; then
    ptani --help
    return 1
  fi
  nuclei \
    --json -irr \
    -t ~/nuclei-templates/misconfiguration/http-missing-security-headers.yaml \
    -u "$_target_url" | ptani -pid $_project_pid
}
```

### Other links:

- How get a [Flow APIKEY][apikeydoc].
- For further information about Conviso Flow CLI check its [documentation][flowdoc].

[github_project]: https://github.com/convisolabs/ptaas-nuclei-integration
[flowdoc]: https://docs.convisoappsec.com/cli/installation
[apikeydoc]: https://help.convisoappsec.com/pt-BR/articles/4428685-api-key
[nucleipage]: https://nuclei.projectdiscovery.io/
[flowpage]: https://app.conviso.com

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
