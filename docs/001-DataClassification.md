# MaskRoute — Data Classification

## Model

Policy is based on:

```text
entity type
+ sensitivity
+ destination
+ operation
→ action
```

Entity type and sensitivity are separate.

Example:

```text
ORGANIZATION + PUBLIC
ORGANIZATION + CONFIDENTIAL
```

## Sensitivity levels

### PUBLIC

Safe to disclose by default.

Examples: public brands, public products, public URLs.

### INTERNAL

Intended for internal use.

Examples: internal system names, ticket IDs, process names.

### CONFIDENTIAL

Disclosure may create business or privacy risk.

Examples: customer names, project codenames, client relationships, unpublished commercial data.

### RESTRICTED

Should normally remain inside the trusted environment.

Examples: API keys, passwords, auth tokens, private keys, payment credentials.

## Initial entity types

Personal:

- `PERSON`
- `EMAIL`
- `PHONE`
- `ADDRESS`
- `DATE_OF_BIRTH`
- `IP_ADDRESS`

Identifiers:

- `CUSTOMER_ID`
- `EMPLOYEE_ID`
- `ACCOUNT_ID`
- `INVOICE_ID`
- `CUSTOM_ID`

Secrets:

- `API_KEY`
- `ACCESS_TOKEN`
- `PASSWORD`
- `PRIVATE_KEY`
- `CONNECTION_STRING`
- `SECRET`

Business:

- `ORGANIZATION`
- `BRAND`
- `CLIENT`
- `INTERNAL_PROJECT`
- `INTERNAL_SYSTEM`
- `PRODUCT_CODENAME`

Applications may define custom entity types.

## Destinations

- `EXTERNAL_LLM`
- `EXTERNAL_SEARCH`
- `EXTERNAL_TOOL`
- `INTERNAL_TOOL`
- `INTERNAL_API`
- `APPLICATION_OUTPUT`
- `LOGGING`

## Default policy

| Sensitivity | External LLM | Web search | Internal tool | Logs |
|---|---|---|---|---|
| PUBLIC | Allow | Allow | Allow | Allow |
| INTERNAL | Pseudonymize | Block | Allow | Pseudonymize |
| CONFIDENTIAL | Pseudonymize | Block | Policy-dependent | Pseudonymize |
| RESTRICTED | Block/Redact | Block | Explicit allow | Redact |

## Important rules

Repeated entities should keep stable tokens inside one scope:

```text
Ivan → ⟦PERSON_1⟧
Ivan → ⟦PERSON_1⟧
Maria → ⟦PERSON_2⟧
```

Tokens are scope-local, not global.

Classification is contextual: a public brand may become sensitive because of the surrounding relationship.

Pseudonymization is not anonymization.
