import "pe"

rule SIGNATURE_BASE_Power_Pe_Injection
{
	meta:
		description = "PowerShell with PE Reflective Injection"
		author = "Benjamin DELPY (gentilkiwi)"
		id = "a71fe9f2-9c2a-5650-a5c7-116b76f10db6"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/gen_mimikatz.yar#L91-L101"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "64a7033d51e8933912f37ce68bffc216073a88cae1ea7492e71a812411ae6a9d"
		score = 75
		quality = 85
		tags = ""

	strings:
		$str_loadlib = "0x53, 0x48, 0x89, 0xe3, 0x48, 0x83, 0xec, 0x20, 0x66, 0x83, 0xe4, 0xc0, 0x48, 0xb9"

	condition:
		$str_loadlib
}
