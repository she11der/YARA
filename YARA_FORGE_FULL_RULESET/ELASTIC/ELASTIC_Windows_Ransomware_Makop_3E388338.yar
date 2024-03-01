rule ELASTIC_Windows_Ransomware_Makop_3E388338 : FILE MEMORY
{
	meta:
		description = "Detects Windows Ransomware Makop (Windows.Ransomware.Makop)"
		author = "Elastic Security"
		id = "3e388338-83c7-453c-b865-13f3bd059515"
		date = "2021-08-05"
		modified = "2021-10-04"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/6d54ae289b290b1d42a7717569483f6ce907200a/yara/rules/Windows_Ransomware_Makop.yar#L21-L44"
		license_url = "https://github.com/elastic/protections-artifacts//blob/6d54ae289b290b1d42a7717569483f6ce907200a/LICENSE.txt"
		hash = "854226fc4f5388d40cd9e7312797dd63739444d69a67e4126ef60817fa6972ad"
		logic_hash = "5a6e5fd725f3d042c0c95b42ad00c93965a49aa6bda6ec5383a239f18d74742e"
		score = 75
		quality = 50
		tags = "FILE, MEMORY"
		fingerprint = "7920469120a69fed191c5068739ed922dcf67aa26d68e44708a1d63dc0931bc3"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "MPR.dll" ascii fullword
		$a2 = "\"%s\" n%u" wide fullword
		$a3 = "\\\\.\\%c:" wide fullword
		$a4 = "%s\\%s\\%s" wide fullword
		$a5 = "%s\\%s" wide fullword
		$a6 = "Start folder" wide fullword

	condition:
		all of them
}
