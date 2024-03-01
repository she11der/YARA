rule SIGNATURE_BASE_Base64_PS1_Shellcode
{
	meta:
		description = "Detects Base64 encoded PS1 Shellcode"
		author = "Nick Carr, David Ledbetter"
		id = "7c3cec3b-a192-5bfd-b4f1-22b1afeb717e"
		date = "2018-11-14"
		modified = "2023-12-05"
		reference = "https://twitter.com/ItsReallyNick/status/1062601684566843392"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_ps1_shellcode.yar#L1-L15"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "fac6f41965eb2209f1552763800d6a2b172f28cd29bb7586d180654aab1e6d56"
		score = 65
		quality = 85
		tags = ""

	strings:
		$substring = "AAAAYInlM"
		$pattern1 = "/OiCAAAAYInlM"
		$pattern2 = "/OiJAAAAYInlM"

	condition:
		$substring and 1 of ($p*)
}
