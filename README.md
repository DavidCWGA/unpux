# unpux
Convert 1Password 1PUX backup files to other formats.

## Requirements

Python 3.

## Usage

After making the script executable, and making the output directory:

Convert one vault to CSV:

```
./unpux.py -v vault_name -o csv backup_file.1pux output_directory
```

Extract all items to plain text:

```
./unpux.py -a -o text backup_file.1pux output_directory
```

For other options, see command line help:

```
./unpux.py -h
```

David Glover-Aoki
david@gloveraoki.net
February 2024
