rule SIGNATURE_BASE_Duqu2_Sample3 : FILE
{
	meta:
		description = "Detects Duqu2 Malware"
		author = "Florian Roth (Nextron Systems)"
		id = "c558445f-fbe3-57db-80f7-09a87b097921"
		date = "2016-07-02"
		modified = "2023-12-05"
		reference = "https://securelist.com/blog/research/70504/the-mystery-of-duqu-2-0-a-sophisticated-cyberespionage-actor-returns/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_duqu2.yar#L52-L66"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "4adaf71a4acd8ce122af0b6f1267dc34c5190efcb4a6fa3322c1e6cf67a546a5"
		score = 80
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "2a9a5afc342cde12c6eb9a91ad29f7afdfd8f0fb17b983dcfddceccfbc17af69"

	strings:
		$s1 = "SELECT `%s` FROM `%s` WHERE `%s`='CAData%i'" fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <50KB and $s1)
}
