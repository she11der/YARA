rule SIGNATURE_BASE_Mithril_Mithril
{
	meta:
		description = "Webshells Auto-generated - file Mithril.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "81645f57-7d7e-5b4d-b323-744f2cde4916"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-webshells.yar#L8183-L8201"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "017191562d72ab0ca551eb89256650bd"
		logic_hash = "5d19eb4132a0401d226c9cffc927b2838e9c69428746296b55a488d097759587"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "OpenProcess error!"
		$s1 = "WriteProcessMemory error!"
		$s4 = "GetProcAddress error!"
		$s5 = "HHt`HHt\\"
		$s6 = "Cmaudi0"
		$s7 = "CreateRemoteThread error!"
		$s8 = "Kernel32"
		$s9 = "VirtualAllocEx error!"

	condition:
		all of them
}