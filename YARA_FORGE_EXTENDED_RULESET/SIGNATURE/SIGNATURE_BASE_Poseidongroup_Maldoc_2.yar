rule SIGNATURE_BASE_Poseidongroup_Maldoc_2 : FILE
{
	meta:
		description = "Detects Poseidon Group - Malicious Word Document"
		author = "Florian Roth (Nextron Systems)"
		id = "9fc0f25e-809d-5803-be39-740ce3a3c85a"
		date = "2016-02-09"
		modified = "2023-12-05"
		reference = "https://securelist.com/blog/research/73673/poseidon-group-a-targeted-attack-boutique-specializing-in-global-cyber-espionage/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_poseidon_group.yar#L66-L89"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "2c35077a4980336a2c50cade322861dc02f92f7617115420eebe7c882c2f620b"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "3e4cacab0ff950da1c6a1c640fe6cf5555b99e36d4e1cf5c45f04a2048f7620c"
		hash2 = "1f77475d7740eb0c5802746d63e93218f16a7a19f616e8fddcbff07983b851af"
		hash3 = "f028ee20363d3a17d30175508bbc4738dd8e245a94bfb200219a40464dd09b3a"
		hash4 = "ec309300c950936a1b9f900aa30630b33723c42240ca4db978f2ca5e0f97afed"
		hash5 = "27449198542fed64c23f583617908c8648fa4b4633bacd224f97e7f5d8b18778"
		hash6 = "1e62629dae05bf7ee3fe1346faa60e6791c61f92dd921daa5ce2bdce2e9d4216"

	strings:
		$s0 = "{\\*\\generator Msftedit 5.41." ascii
		$s1 = "Attachment 1: Complete Professional Background" ascii
		$s2 = "E-mail:  \\cf1\\ul\\f1"
		$s3 = "Education:\\par" ascii
		$s5 = "@gmail.com" ascii

	condition:
		uint32(0)==0x74725c7b and filesize <500KB and 3 of them
}
