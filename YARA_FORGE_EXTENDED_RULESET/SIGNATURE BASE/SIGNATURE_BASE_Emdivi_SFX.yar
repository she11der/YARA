rule SIGNATURE_BASE_Emdivi_SFX : FILE
{
	meta:
		description = "Detects Emdivi malware in SFX Archive"
		author = "Florian Roth (Nextron Systems) @Cyber0ps"
		id = "51367190-2e8d-507c-a19f-996bc6960977"
		date = "2015-08-20"
		modified = "2023-12-05"
		reference = "https://securelist.com/blog/research/71876/new-activity-of-the-blue-termite-apt/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_bluetermite_emdivi.yar#L9-L28"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "3257983c64c52f36b04e3fe7b12180a37531338349137d4df00fc6f704557b2e"
		score = 70
		quality = 85
		tags = "FILE"
		hash1 = "7a3c81b2b3c14b9cd913692347019887b607c54152b348d6d3ccd3ecfd406196"
		hash2 = "8c3df4e4549db3ce57fc1f7b1b2dfeedb7ba079f654861ca0b608cbfa1df0f6b"

	strings:
		$x1 = "Setup=unsecess.exe" fullword ascii
		$x2 = "Setup=leassnp.exe" fullword ascii
		$s1 = "&Enter password for the encrypted file:" fullword wide
		$s2 = ";The comment below contains SFX script commands" fullword ascii
		$s3 = "Path=%temp%" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <740KB and (1 of ($x*) and all of ($s*))
}
