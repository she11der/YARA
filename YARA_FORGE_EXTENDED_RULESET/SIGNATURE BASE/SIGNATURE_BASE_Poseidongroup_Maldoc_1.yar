rule SIGNATURE_BASE_Poseidongroup_Maldoc_1 : FILE
{
	meta:
		description = "Detects Poseidon Group - Malicious Word Document"
		author = "Florian Roth (Nextron Systems)"
		id = "ab26455a-d468-5a75-a6e2-61701ca3a1df"
		date = "2016-02-09"
		modified = "2023-12-05"
		reference = "https://securelist.com/blog/research/73673/poseidon-group-a-targeted-attack-boutique-specializing-in-global-cyber-espionage/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_poseidon_group.yar#L50-L64"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "0983526d7f0640e5765ded6be6c9e64869172a02c20023f8a006396ff358999b"
		logic_hash = "0d8c255f56bb33b6a720c98727127c07a2d77245b18da381706a40339bebd20b"
		score = 80
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "c:\\cmd32dll.exe" fullword ascii

	condition:
		uint16(0)==0xcfd0 and filesize <500KB and all of them
}
