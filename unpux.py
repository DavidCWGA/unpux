#!/usr/bin/env python3
# This script is distributed under the terms of the GNU General Public License,
# version 3.0 or later.
# David Glover-Aoki, February 2024
# david@gloveraoki.net

import argparse, zipfile, json, os, csv, sys, datetime, tempfile, shutil

def read_backup(zip_file_path: str) -> dict:
	with zipfile.ZipFile(zip_file_path, "r") as z:
		with z.open("export.data") as file:
			data = json.load(file)
	return data

def extract_files(zip_file_path: str, output_directory: str):
	os.makedirs(output_directory, exist_ok=True)

	count = 0
	with zipfile.ZipFile(zip_file_path, "r") as z:
		with tempfile.TemporaryDirectory() as temp_dir:
			for file in z.namelist():
				if file.startswith("files/") and not file.endswith("/"):
					z.extract(file, temp_dir)
					temp_file_path = os.path.join(temp_dir, file)
					new_file_path = os.path.join(output_directory, os.path.basename(file))
					shutil.move(temp_file_path, new_file_path)
					count += 1
	if count > 0:
		print(f"Extracted {count} files to {output_directory}")
	else:
		print("No attachments found")

def list_vaults(data: dict) -> list:
	return [vault["attrs"]["name"] for account in data["accounts"] for vault in account["vaults"]]

def find_vault(data: dict, vault_name: str) -> dict:
	everything = [vault for account in data["accounts"] for vault in account["vaults"]]
	if vault_name == "magic-13lEa-all":
		return {"items": [item for vault in everything for item in vault["items"]]}
	else:
		return next((vault for vault in everything if vault["attrs"]["name"] == vault_name), None)

def friendly_item_type(item_type: str) -> str:
	types = {
		"001": "Logins",
		"002": "Credit Cards",
		"003": "Notes",
		"004": "Identities",
		"005": "Passwords",
		"006": "Files",
		"100": "Software Licenses",
		"101": "Bank Accounts",
		"103": "Drivers Licenses",
		"105": "Memberships",
		"106": "Passports",
		"108": "Social Security Numbers",
		"109": "Wi-Fi",
		"110": "Servers",
		"113": "Medical Records",
		"114": "SSH Keys"
	}
	return types.get(item_type, item_type)

def dict_values_to_string(input_dict: dict) -> str:
	return ', '.join(str(value) for value in input_dict.values() if value)

def unix_time_to_date(unix_time: int) -> str:
	return datetime.datetime.fromtimestamp(unix_time).strftime('%Y-%m-%d')

def format_monthyear(monthyear: int) -> str:
	monthyear_str = str(monthyear)
	return f"{monthyear_str[:4]}-{monthyear_str[4:]}"

def item_to_dict(item: dict) -> dict:
	# Main fields
	item_type = friendly_item_type(item["categoryUuid"])
	title = item["overview"]["title"]
	url = item["overview"]["url"]
	details = item["details"]
	login_fields = details.get("loginFields", [])
	username = next((field["value"] for field in login_fields if field.get("designation") == "username"), "")
	password = details.get("password", "") or next((field["value"] for field in login_fields if field.get("designation") == "password"), "")
	notes = details.get("notesPlain", "")

	# Other sections
	otpauth = ""
	extras = []

	for section in details.get("sections", []):
		if section.get("title"):
			section_title = section["title"]
			section_header = ""
			if extras:
				section_header += "\n"
			section_header += f"{section_title}\n{'=' * len(section_title)}"
		else:
			section_header = None
		for field in section.get("fields", []):
			if "value" in field:
				key, value = next(iter(field["value"].items()))
				if "totp" in field["value"]:
					otpauth = field["value"]["totp"]
				elif value:
					if isinstance(value, dict):
						value = dict_values_to_string(value)
					if key == "date":
						value = unix_time_to_date(value)
					elif key == "monthYear":
						value = format_monthyear(value)
					if section_header:
						extras.append(section_header)
						section_header = None
					if field['title']:
						extras.append(f"{field['title']}: {value}")
					else:
						extras.append(value)

	return {
		"Type": item_type,
		"Title": title,
		"URL": url,
		"Username": username,
		"Password": password,
		"Notes": notes,
		"OTPAuth": otpauth,
		"Extras": "\n".join(extras)
	}

def itemdict_to_text(item: dict) -> str:
	fields = ["URL", "Username", "Password", "Notes", "OTPAuth", "Extras"]
	text = ""
	if sum(1 for field in fields if item[field]) == 1:
		return next(item[field] for field in fields if item[field])
	for field in fields:
		if item[field]:
			if field == "Extras":
				text += item[field]
			elif "\n" in item[field]:
				text += f"{field}:\n{item[field]}\n\n"
			else:
				text += f"{field}: {item[field]}\n"
	return text

def extract_items(vault: dict, filter: str = "") -> list:
	items = [item_to_dict(item) for item in vault["items"] if item["categoryUuid"] != "006"]
	if filter:
		old_count = len(items)
		items = [item for item in items if filter.casefold() in item["Title"].casefold() or filter.casefold() in item["URL"].casefold()]
		print(f"Selected {len(items)} items matching '{filter}' out of {old_count}")
	return items

def items_to_csv(items: list, filename: str) -> int:
	fieldnames = ['Title', 'URL', 'Username', 'Password', 'Notes', 'OTPAuth']
	writer = csv.DictWriter(filename if filename else sys.stdout, fieldnames=fieldnames, extrasaction='ignore')
	writer.writeheader()
	skip_count = 0
	written_count = 0
	for item in items:
		if item['URL'] and ( item['Username'] or item['Password'] ):
			if item['Extras']:
				item['Notes'] += "\n" + item['Extras']
			writer.writerow(item)
			written_count += 1
		else:
			skip_count += 1
	if skip_count > 0:
		print(f"Skipped {skip_count} items missing required fields", file=sys.stderr)
	return written_count

def safe_filename(filename: str) -> str:
	return "".join(c for c in filename if c.isalpha() or c.isdigit() or c==' ').rstrip()

def items_to_text(items: list, output_directory: str):
	for item in items:
		text = itemdict_to_text(item)
		subfolder = item['Type']
		file_name = safe_filename(item["Title"]) + ".txt"
		file_path = os.path.join(output_directory, subfolder, file_name)
		os.makedirs(os.path.dirname(file_path), exist_ok=True)
		with open(file_path, "w") as file:
			file.write(text)
	return len(items)

def main():
	epilog_text = """CSV format includes only items with a URL and at least one of a username or password.
		Text format saves one file per item and includes everything."""
	parser = argparse.ArgumentParser(description="Convert 1Password 1PUX backup files to other formats", epilog=epilog_text)
	parser.add_argument("backup_file", help="Path to the 1Password 1PUX backup file")
	parser.add_argument("output_directory", help="Path to the output directory")
	parser.add_argument("-l", "--list", help="List all vaults in the backup file", action="store_true")
	group = parser.add_mutually_exclusive_group(required=True)
	group.add_argument("-v", "--vault", help="Name of the vault to convert")
	group.add_argument("-a", "--all", help="Convert all vaults", action="store_true")
	parser.add_argument("-o", "--format", help="Output format", choices=["csv", "text"], required=True)
	parser.add_argument("-f", "--filter", help="Filter items by a search term")
	parser.add_argument("-x", "--skip-warning", help="Skip the warning about unencrypted data", action="store_true")
	
	args = parser.parse_args()
	data = read_backup(args.backup_file)
	all_vaults = list_vaults(data)

	if args.list:
		for vault in all_vaults:
			print(vault)
		quit()
	
	if not os.path.exists(args.output_directory):
		print(f"Output directory {args.output_directory} does not exist")
		quit()
	
	if args.all:
		vault_list = all_vaults
	elif args.vault:
		if args.vault in all_vaults:
			vault_list = [args.vault]
		else:
			print(f"Vault '{args.vault}' not found, use -l to list vault names", file=sys.stderr)
			quit()
	else:
		print("No vault specified", file=sys.stderr)
		quit()

	if not args.skip_warning:
		message = ( "Warning: 1PUX files contain unencrypted data.\n"
			 "The converted output is also unencrypted.\n"
			 "This tool does nothing to protect your data.\n" 
			 "In future, use -x to skip this warning.\n")
		print(message, file=sys.stderr)
		
		try:
			input("Press Enter to continue or Ctrl+C to cancel")
		except KeyboardInterrupt:
			print("\nDoing nothing.")
			quit()

	files_directory = os.path.join(args.output_directory, "Attachments")
	extract_files(args.backup_file, files_directory)

	for vault_name in vault_list:
		print(f"Processing {vault_name}:")
		vault = find_vault(data, vault_name)
		if args.all:
			output_directory = os.path.join(args.output_directory, vault_name)
		else:
			output_directory = args.output_directory
		os.makedirs(output_directory, exist_ok=True)

		if args.format == "text":
			items = extract_items(vault, args.filter)
			saved_count = items_to_text(items, output_directory)
			print(f"Saved {saved_count} items to {output_directory}")
		elif args.format == "csv":
			file_path = os.path.join(output_directory, f"{vault_name}.csv")
			with open(file_path, "w") as file:
				written_count = items_to_csv(extract_items(vault, args.filter), file)
				print(f"Saved {written_count} items to {file_path}")

if __name__ == "__main__":
	main()
