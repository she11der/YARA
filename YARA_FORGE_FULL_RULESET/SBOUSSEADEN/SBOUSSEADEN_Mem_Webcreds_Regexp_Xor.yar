rule SBOUSSEADEN_Mem_Webcreds_Regexp_Xor
{
	meta:
		description = "No description has been set in the source file - SBousseaden"
		author = "SBousseaden"
		id = "38087b99-5f64-58c0-b3dc-51c7981912e7"
		date = "2020-03-08"
		modified = "2020-12-28"
		reference = "https://github.com/orlyjamie/mimikittenz/blob/master/Invoke-mimikittenz.ps1"
		source_url = "https://github.com/sbousseaden/YaraHunts//blob/71b27a2a7c57c2aa1877a11d8933167794e2b4fb/hunt_capab_credentials_access.yara#L3-L22"
		license_url = "N/A"
		logic_hash = "0ecc15dd51807ccd1c35b5a6152aa16714d8a14889524163a421f79becd6a775"
		score = 60
		quality = 45
		tags = ""

	strings:
		$p1 = "&password=" xor
		$p2 = "&login_password=" xor
		$p3 = "&pass=" xor
		$p4 = "&Passwd=" xor
		$p5 = "&PersistentCookie=" xor
		$p6 = "password%5D=" xor
		$u1 = "&username=" xor
		$u2 = "&email=" xor
		$u3 = "login=" xor
		$u4 = "login_email=" xor
		$u5 = "user%5Bemail%5D=" xor
		$reg = ".{1," xor

	condition:
		3 of ($p*) and 3 of ($u*) and #reg>3
}
