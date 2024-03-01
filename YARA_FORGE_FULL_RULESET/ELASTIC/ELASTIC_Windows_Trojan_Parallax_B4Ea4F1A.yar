rule ELASTIC_Windows_Trojan_Parallax_B4Ea4F1A : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Parallax (Windows.Trojan.Parallax)"
		author = "Elastic Security"
		id = "b4ea4f1a-4b78-4bb8-878e-40fe753018e9"
		date = "2022-09-08"
		modified = "2022-09-29"
		reference = "https://www.elastic.co/security-labs/exploring-the-ref2731-intrusion-set"
		source_url = "https://github.com/elastic/protections-artifacts//blob/6d54ae289b290b1d42a7717569483f6ce907200a/yara/rules/Windows_Trojan_Parallax.yar#L24-L55"
		license_url = "https://github.com/elastic/protections-artifacts//blob/6d54ae289b290b1d42a7717569483f6ce907200a/LICENSE.txt"
		logic_hash = "731fe7bd339ec6b0372b4809004a21f53537bd82f084960b8d018f994dcdc06a"
		score = 75
		quality = 42
		tags = "FILE, MEMORY"
		fingerprint = "5c695f6b1bb0e72a070e076402cd94a77b178809617223b6caac6f6ec46f2ea1"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$parallax_payload_strings_0 = "[Ctrl +" ascii wide fullword
		$parallax_payload_strings_1 = "[Ctrl]" ascii wide fullword
		$parallax_payload_strings_2 = "Clipboard Start" ascii wide fullword
		$parallax_payload_strings_3 = "[Clipboard End]" ascii wide fullword
		$parallax_payload_strings_4 = "UN.vbs" ascii wide fullword
		$parallax_payload_strings_5 = "lt +" ascii wide fullword
		$parallax_payload_strings_6 = "lt]" ascii wide fullword
		$parallax_payload_strings_7 = ".DeleteFile(Wscript.ScriptFullName)" ascii wide fullword
		$parallax_payload_strings_8 = ".DeleteFolder" ascii wide fullword
		$parallax_payload_strings_9 = ".DeleteFile " ascii wide fullword
		$parallax_payload_strings_10 = "Scripting.FileSystemObject" ascii wide fullword
		$parallax_payload_strings_11 = "On Error Resume Next" ascii wide fullword
		$parallax_payload_strings_12 = "= CreateObject" ascii wide fullword
		$parallax_payload_strings_13 = ".FileExists" ascii wide fullword

	condition:
		7 of ($parallax_payload_strings_*)
}
