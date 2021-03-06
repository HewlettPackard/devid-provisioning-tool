# DevID Provisioning Tool

**This tool is still under development and is not ready for production use yet.**

The DevID Provisioning tool generates and provisions TPMs with DevID credentials. 
It performs the enrolment protocol defined in the TCG specification: [TPM 2.0 Keys for Device Identity and Attestation](https://trustedcomputinggroup.org/wp-content/uploads/TCG_IWG_DevID_v1r2_02dec2020.pdf).


## Build
```
make build
```

## Configure
Example files are provided for the [agent](agent.conf) and [server](server.conf) component.


## Run

1. Run the provisioning service
```
./server
```

2. Run the provisioning agent
```
./agent
```

The agent provisions the TPM and outputs the DevID and AK certificates and keys in the current folder by default.  
