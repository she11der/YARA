rule SIGNATURE_BASE_Duqu2_Sample4 : FILE
{
	meta:
		description = "Detects Duqu2 Malware"
		author = "Florian Roth (Nextron Systems)"
		id = "8c5ca68d-762c-5d2e-8d37-f58dc66bcae2"
		date = "2016-07-02"
		modified = "2023-12-05"
		reference = "https://securelist.com/blog/research/70504/the-mystery-of-duqu-2-0-a-sophisticated-cyberespionage-actor-returns/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_duqu2.yar#L68-L85"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "ddecd1d7fa007b83fe6e29ac8983d02511a89a16ab2365f8086ec92a52d4bf33"
		score = 80
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "3536df7379660d931256b3cf49be810c0d931c3957c464d75e4cba78ba3b92e3"

	strings:
		$x1 = "SELECT `Data` FROM `Binary` WHERE `Name`='CryptHash%i'" fullword wide
		$s2 = "SELECT `UserName`, `Password`, `Attributes` FROM `CustomUserAccounts`" fullword wide
		$s3 = "SELECT `UserName` FROM `CustomUserAccounts`" fullword wide
		$s4 = "ProcessUserAccounts" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <30KB and 1 of ($x*)) or ( all of them )
}
