rule SBOUSSEADEN_Hunt_Credaccess_Iis
{
	meta:
		description = "hunt for strings related to iis credential access"
		author = "SBousseaden"
		id = "0edfb8a5-83ab-5d6f-b8c9-7d3e03a6e32a"
		date = "2020-07-20"
		modified = "2020-12-28"
		reference = "https://github.com/sbousseaden/YaraHunts/"
		source_url = "https://github.com/sbousseaden/YaraHunts//blob/71b27a2a7c57c2aa1877a11d8933167794e2b4fb/hunt_capab_credentials_access.yara#L206-L219"
		license_url = "N/A"
		logic_hash = "b193e40e932d3168c826baaa070b2484e7e4781a481ab911a9526f9bc23d24a1"
		score = 50
		quality = 73
		tags = ""

	strings:
		$a1 = "aspnet_regiis.exe" nocase
		$a2 = "connectionStrings" nocase
		$a3 = "web.config" nocase
		$a4 = "-pdf" nocase
		$b1 = "appcmd.exe" nocase
		$b2 = "/text:password"

	condition:
		( all of ($a*) or all of ($b*))
}
