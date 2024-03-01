rule SIGNATURE_BASE_MAL_RANSOM_Lockbit_Apr23_1
{
	meta:
		description = "Detects indicators found in LockBit ransomware"
		author = "Florian Roth"
		id = "75dc8b95-16f0-5170-a7d6-fc10bb778348"
		date = "2023-04-17"
		modified = "2023-12-05"
		reference = "https://objective-see.org/blog/blog_0x75.html"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/mal_lockbit_lnx_macos_apr23.yar#L43-L67"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "cd5bffa5571abfd1446b065d26c8c23f00fe1376d505af539c6f37356014a86f"
		score = 75
		quality = 85
		tags = ""

	strings:
		$xe1 = "-i '/path/to/crypt'" xor
		$xe2 = "http://lockbit" xor
		$s1 = "idelayinmin" ascii
		$s2 = "bVMDKmode" ascii
		$s3 = "bSelfRemove" ascii
		$s4 = "iSpotMaximum" ascii
		$fp1 = "<html"

	condition:
		(1 of ($x*) or 4 of them ) and not 1 of ($fp*)
}
