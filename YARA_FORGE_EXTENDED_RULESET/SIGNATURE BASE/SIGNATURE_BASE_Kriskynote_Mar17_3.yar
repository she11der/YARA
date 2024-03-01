rule SIGNATURE_BASE_Kriskynote_Mar17_3 : FILE
{
	meta:
		description = "Detects Kriskynote Malware"
		author = "Florian Roth (Nextron Systems)"
		id = "647fac4c-2326-5a68-9890-8236022c1548"
		date = "2017-03-03"
		modified = "2023-12-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/crime_kriskynote.yar#L48-L64"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "fda8a7944cdd12cadb1c902664909a8164835f660e6fa56209bc51164a90e77c"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "fc838e07834994f25b3b271611e1014b3593278f0703a4a985fb4234936df492"

	strings:
		$s1 = "rundll32 %s Check" fullword ascii
		$s2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs" fullword ascii
		$s3 = "name=\"IsUserAdmin\"" fullword ascii
		$s4 = "zok]\\\\\\ZZYYY666564444" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <2000KB and 2 of them )
}
