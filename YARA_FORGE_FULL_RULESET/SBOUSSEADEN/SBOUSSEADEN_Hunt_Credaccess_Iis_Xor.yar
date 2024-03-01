rule SBOUSSEADEN_Hunt_Credaccess_Iis_Xor
{
	meta:
		description = "hunt for strings related to iis credential access"
		author = "SBousseaden"
		id = "ed5dd469-cf08-5eb1-bfde-36460c10197b"
		date = "2020-07-20"
		modified = "2020-12-28"
		reference = "https://github.com/sbousseaden/YaraHunts/"
		source_url = "https://github.com/sbousseaden/YaraHunts//blob/71b27a2a7c57c2aa1877a11d8933167794e2b4fb/hunt_capab_credentials_access.yara#L221-L234"
		license_url = "N/A"
		logic_hash = "58c316238cacfbfd5a539d6dbae9bc31836c414d5179ca5c40aa2cfae6c69655"
		score = 60
		quality = 45
		tags = ""

	strings:
		$a1 = "aspnet_regiis.exe" wide xor
		$a2 = "connectionStrings" wide xor
		$a3 = "web.config" wide xor
		$a4 = "-pdf" wide xor
		$b1 = "appcmd.exe" wide xor
		$b2 = "/text:password" wide xor

	condition:
		( all of ($a*) or all of ($b*))
}
