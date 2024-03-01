rule SBOUSSEADEN_Hunt_Credaccess_Iis_Wide_Base64
{
	meta:
		description = "hunt for strings related to iis credential access"
		author = "SBousseaden"
		id = "9e709338-2b61-53b6-99b4-36b52991bc27"
		date = "2020-07-20"
		modified = "2020-12-28"
		reference = "https://github.com/sbousseaden/YaraHunts/"
		source_url = "https://github.com/sbousseaden/YaraHunts//blob/71b27a2a7c57c2aa1877a11d8933167794e2b4fb/hunt_capab_credentials_access.yara#L251-L264"
		license_url = "N/A"
		logic_hash = "6b06ef3a19fc4ce4d6a3f23815ac411094574cf15bfcc18d675017c7e357d1cf"
		score = 50
		quality = 75
		tags = ""

	strings:
		$a1 = "aspnet_regiis.exe" wide base64
		$a2 = "connectionStrings" wide base64
		$a3 = "web.config" wide base64
		$a4 = "-pdf" wide base64
		$b1 = "appcmd.exe" wide base64
		$b2 = "/text:password" wide base64

	condition:
		(3 of ($a*) or all of ($b*))
}
