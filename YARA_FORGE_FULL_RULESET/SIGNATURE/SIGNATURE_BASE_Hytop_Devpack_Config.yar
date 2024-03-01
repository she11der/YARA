rule SIGNATURE_BASE_Hytop_Devpack_Config
{
	meta:
		description = "Webshells Auto-generated - file config.asp"
		author = "Florian Roth (Nextron Systems)"
		id = "da1b8ce1-8b17-53f6-a86b-ad3fe918084e"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L7275-L7288"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "b41d0e64e64a685178a3155195921d61"
		logic_hash = "b2806c30db413bca518943352f233c9d2915356a41eceed5e352b88ee34fbbd3"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "const adminPassword=\""
		$s2 = "const userPassword=\""
		$s3 = "const mVersion="

	condition:
		all of them
}