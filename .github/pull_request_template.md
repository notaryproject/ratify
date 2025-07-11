## Description

<!-- Please include a summary of the changes and relevant context. -->

### Which issue(s) does this PR resolve?

<!--
    Use `Fixes #<issue number>[, Fixes #<issue_number>, ...]` format.
    Use `Fixes` for bug fixes and `Resolves` for new features.
    The PR will close the issue(s) when it gets merged.
-->
Fixes #

### Type of change

- [ ] Bug fix (non-breaking change which fixes an issue)
- [ ] New feature (non-breaking change which adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] Helm Chart Change (any edit/addition/update that is necessary for changes merged to the `main` branch)
- [ ] This change requires a documentation update

## Testing and verification

<!-- Please describe the tests you ran to verify your changes, including any relevant configuration details. -->

## Checklist

- [ ] Does the affected code have corresponding tests?
- [ ] Are the changes documented, not just with inline documentation, but also with conceptual documentation such as an overview of a new feature, or task-based documentation like a tutorial? Consider if this change should be announced on your project blog.
- [ ] Does this introduce breaking changes that would require an announcement or bumping the major version?
- [ ] Do all new files have appropriate license header?

## Post merge requirements

- [ ] MAINTAINERS: manually trigger the "Publish Package" workflow after merging any PR that indicates `Helm Chart Change`
