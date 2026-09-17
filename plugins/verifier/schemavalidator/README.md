# Json schema validator
Validate Json artifacts against JSON schemas.

## Configuration
Schemas can be configured in Ratify config.json or via CRD.

```json
 "plugins": [
      {
        "name": "schemavalidator",
        "artifactTypes": "application/vnd.aquasecurity.trivy.report.sarif.v1",
        "schemas": {
            "application/sarif+json": "https://raw.githubusercontent.com/SchemaStore/schemastore/734c0e50105228741c0b76853efdd81b5f93487c/src/schemas/json/sarif-2.1.0-rtm.5.json"
          }
      }
 ]
```

```yaml
apiVersion: config.ratify.deislabs.io/v1beta1
kind: Verifier
metadata:
  name: verifier-schemavalidator
spec:
  name: schemavalidator
  artifactTypes: application/vnd.aquasecurity.trivy.report.sarif.v1
  parameters:
    schemas:
      application/sarif+json: https://raw.githubusercontent.com/SchemaStore/schemastore/734c0e50105228741c0b76853efdd81b5f93487c/src/schemas/json/sarif-2.1.0-rtm.5.json
```