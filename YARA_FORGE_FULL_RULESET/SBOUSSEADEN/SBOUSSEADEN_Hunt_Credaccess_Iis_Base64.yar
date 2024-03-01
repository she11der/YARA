rule SBOUSSEADEN_Hunt_Credaccess_Iis_Base64
{
	meta:
		description = "hunt for strings related to iis credential access"
		author = "SBousseaden"
		id = "3a6b41b1-5a6a-536e-ac99-fb45ec460767"
		date = "2020-07-20"
		modified = "2020-12-28"
		reference = "https://github.com/sbousseaden/YaraHunts/"
		source_url = "https://github.com/sbousseaden/YaraHunts//blob/71b27a2a7c57c2aa1877a11d8933167794e2b4fb/hunt_capab_credentials_access.yara#L236-L249"
		license_url = "N/A"
		logic_hash = "b09c4cfaefeae28cb9381ae7b94ef970f10a6a265a3e40766d2a8c109b2df054"
		score = 50
		quality = 75
		tags = ""

	strings:
		$a1 = "aspnet_regiis.exe" base64
		$a2 = "connectionStrings" base64
		$a3 = "web.config" base64
		$a4 = "-pdf" base64
		$b1 = "appcmd.exe" base64
		$b2 = "/text:password" base64

	condition:
		(3 of ($a*) or all of ($b*))
}
