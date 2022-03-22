# redact-ckl

## Usage

```
node redact-ckl.js *path_to_original_ckl* > *path_to_output*
```

## Function

Given the path to an original CKL as an argument, output a redacted version to `stdout`. Redacts the following tag values if the tag is present:

| Tag      | Redaction |
| ----------- | ----------- |
`HOST_FQDN`| random characters with original length
`HOST_NAME`| random characters with original length
`HOST_IP` | Random IP address
`HOST_MAC` | Random MAC address
`COMMENTS` | string of random characters with original length
`FINDING_DETAILS` | string of random characters with original length
`SEVERITY_JUSTIFICATION` | string of random characters with original length
