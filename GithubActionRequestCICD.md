This vulnerability is about an old attack surface focus on the Github Action CI/CD pipeline. It occurs when developers directly execute the command that concatenate string from user control input within a sandbox environment.

# User-controlled 

Here is a long list that user can control when push request in Github CI/CD pipeline.

```
github.event.issue.title
github.event.issue.body
github.event.pull_request.title
github.event.pull_request.body
github.event.comment.body
github.event.review.body
github.event.pages.*.page_name
github.event.commits.*.message
github.event.head_commit.message
github.event.head_commit.author.email
github.event.head_commit.author.name
github.event.commits.*.author.email
github.event.commits.*.author.name
github.event.pull_request.head.ref
github.event.pull_request.head.label
github.event.pull_request.head.repo.default_branch
github.head_ref
```

Mostly, this vulnerability occurs when `github.head_ref` (the merge request name) wasn't sanitized and execute as the command.

# Example

Create a public repo, with file `.github/workflows/demo.yml` has content:

```
name: Test

on:
  pull_request:
    branches:
      - main
    types:
      - labeled
      - unlabeled
      - opened
      - synchronize
      - reopened

jobs:
  check-changesets:
    if: |
      !contains(github.event.pull_request.labels.*.name, 'Skip Major Check')
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v3

      - name: Fetch all branches
        run: git fetch --all

      - name: Checkout the feature branch
        run: git checkout ${{ github.head_ref }} --
```

Trigger condition: The workflow will run when a pull Request is directed to the main branch and one of the following events occurs:

```
opened – PR is created
reopened – PR is reopened
synchronize – a new commit is pushed to the PR
labeled – a label is assigned to the PR
unlabeled – the label is removed from the PR
```

This line contains a command injection:

```
git checkout ${{ github.head_ref }} --
```

<img width="1734" height="949" alt="image" src="https://github.com/user-attachments/assets/d317bb5d-29d4-4850-bbc6-7a3f3b1c1818" />

Use another github account, fork the project in above step, create a new branch with name `h1;id;#`, make some change and add a pull request.

Check the Action field in the repo, you can see the command `id` was executed.

# Some reports

<img width="1047" height="316" alt="image" src="https://github.com/user-attachments/assets/54d3b540-5bff-4b78-9a7f-00f070670479" />

<img width="847" height="301" alt="image" src="https://github.com/user-attachments/assets/973d3f15-ddf3-412c-8094-f16f08130a0c" />

# Ref

https://securitylab.github.com/resources/github-actions-untrusted-input/
