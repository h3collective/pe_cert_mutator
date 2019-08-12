# PE certificate mutator

Sections:

1. [Introduction](##Introduction)
1. [Dependencies](##Dependencies)
1. [Artifacts](##Artifacts)
1. [Help Output](##Help-output)
1. [Examples](##Examples)
1. [External Links](##External-Links)

## Introduction
The pe certificate mutator is a python module that will generate new .exe
files based on an existing .exe, with mutations to various fields associated
with certificates in the file.

## Dependencies
the pefile module is required to run this script.  Otherwise, the script is
capable of running on different platforms.

## Artifacts
* cert_mutator.py - script for modifying binary files.

## Help output
    usage: cert_mutator.py [-h] -b BINARY [-o OUTPUT] [-r REPLACE_SIGNATURE]
                        [-m MODES [MODES ...]] [-c COUNT] [-cmd RUN_CMD] [-rag]
                        [-f]

    optional arguments:
    -h, --help            show this help message and exit
    -b BINARY             Path to a binary file.
    -o OUTPUT             Directory where permuted files are placed. Default is
                            the current directory.
    -r REPLACE_SIGNATURE  Replace the authenticode signature in the binary
                            provided with -b with the signature from this file.
                            All subsequent mutations will be against the new
                            signature. Does not overwrite the existing binary, but
                            new mutations will include the new signature.
    -m MODES [MODES ...]  Enable mutation of specific sections of the binary.
                            Not specifying this flag will enable all modes.
                            Supported modes include: security_data_directory,
                            attribute_certificate_table, bcertificate_random,
                            truncate.
    -c COUNT              For modes supporting random permutations, this will
                            control the number of distinct variants generated.
                            Default is 5. The amount of random data will increase
                            as the variants are generated.
    -cmd RUN_CMD          This will result in the _run_all.bat script executing
                            this program and providing the mutated binary as
                            input, as opposed to running the mutated binary
                            directly.
    -rag, --run-after-generation
                            This option will output, run, and delete each
                            executable variant as it is generated. Use this if the
                            creation of hundreds, thousands, or even more files on
                            the system is not desireable.
    -f                    Forcefully overwrite any existing output artifact.

## Examples
Display help output

    python cert_mutator.py -h
 
Run all mutation modes against test.exe

    python cert_mutator.py -b test.exe
 
Run a specific mutation against the binary

    python cert_mutator.py -b test.exe -m attribute_certificate_table

## External Links

[H3Collective blog post](https://h3collective.io/introducing-the-h3-collective-pe-cert-mutator-tool/)