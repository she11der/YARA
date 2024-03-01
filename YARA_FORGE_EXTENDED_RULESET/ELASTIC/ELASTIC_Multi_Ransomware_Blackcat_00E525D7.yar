rule ELASTIC_Multi_Ransomware_Blackcat_00E525D7 : FILE MEMORY
{
	meta:
		description = "Detects Multi Ransomware Blackcat (Multi.Ransomware.BlackCat)"
		author = "Elastic Security"
		id = "00e525d7-a8a6-475f-89ad-607c452aea1e"
		date = "2022-02-02"
		modified = "2022-08-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/84213d9b40fee553ea3065cb4bb057c7c1685b59/yara/rules/Multi_Ransomware_BlackCat.yar#L22-L43"
		license_url = "https://github.com/elastic/protections-artifacts//blob/84213d9b40fee553ea3065cb4bb057c7c1685b59/LICENSE.txt"
		hash = "0c6f444c6940a3688ffc6f8b9d5774c032e3551ebbccb64e4280ae7fc1fac479"
		logic_hash = "e44625d0fa8308b9d4d63a9e6920b4da4a2ce124437f122b2c8fe5cf0ab85a6b"
		score = 75
		quality = 50
		tags = "FILE, MEMORY"
		fingerprint = "631e30b8b51a5c0a0e91e8c09968663192569005b8bffff9f0474749788e9d57"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "multi"

	strings:
		$a1 = "ata\",\"boot\",\"config.msi\",\"google\",\"perflogs\",\"appdata\",\"windows.old\"],\"exclude_file_names\":[\"desktop.ini\",\"aut"
		$a2 = "locker::core::windows::processvssadmin.exe delete shadows /all /quietshadow_copy::remove_all=" ascii fullword
		$a3 = "\\\\.\\pipe\\__rust_anonymous_pipe1__." ascii fullword
		$a4 = "--bypass-p-p--bypass-path-path --no-prop-servers \\\\" ascii fullword

	condition:
		all of them
}
