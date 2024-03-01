rule SBOUSSEADEN_Webcreds_Regexp_B64
{
	meta:
		description = "No description has been set in the source file - SBousseaden"
		author = "SBousseaden"
		id = "85283a81-5bc3-5e3f-89f6-bcc1f40f3dc2"
		date = "2020-03-08"
		modified = "2020-12-28"
		reference = "https://github.com/orlyjamie/mimikittenz/blob/master/Invoke-mimikittenz.ps1"
		source_url = "https://github.com/sbousseaden/YaraHunts//blob/71b27a2a7c57c2aa1877a11d8933167794e2b4fb/hunt_capab_credentials_access.yara#L24-L43"
		license_url = "N/A"
		logic_hash = "432c812177a50c50d08feb88a1293ecb625b9b0aa6a839789da150255bc83228"
		score = 75
		quality = 75
		tags = ""

	strings:
		$p1 = "&password=" base64
		$p2 = "&login_password=" base64
		$p3 = "&pass=" base64
		$p4 = "&Passwd=" base64
		$p5 = "&PersistentCookie=" base64
		$p6 = "password%5D=" base64
		$u1 = "&username=" base64
		$u2 = "&email=" base64
		$u3 = "login=" base64
		$u4 = "login_email=" base64
		$u5 = "user%5Bemail%5D=" base64
		$reg = ".{1,"

	condition:
		3 of ($p*) and 3 of ($u*) and #reg>3
}
