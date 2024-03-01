rule SIGNATURE_BASE_Duqu2_Sample2 : FILE
{
	meta:
		description = "Detects Duqu2 Malware"
		author = "Florian Roth (Nextron Systems)"
		id = "a32f54a3-8656-5592-ac40-17330bfca319"
		date = "2016-07-02"
		modified = "2023-12-05"
		reference = "https://securelist.com/blog/research/70504/the-mystery-of-duqu-2-0-a-sophisticated-cyberespionage-actor-returns/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_duqu2.yar#L30-L50"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "6afd87d472929f56272eb6f28970f2c8be5eb08e6126287391aee1269de1100d"
		score = 80
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "d12cd9490fd75e192ea053a05e869ed2f3f9748bf1563e6e496e7153fb4e6c98"
		hash2 = "5ba187106567e8d036edd5ddb6763f89774c158d2a571e15d76572d8604c22a0"
		hash3 = "6e09e1a4f56ea736ff21ad5e188845615b57e1a5168f4bdaebe7ddc634912de9"
		hash4 = "c16410c49dc40a371be22773f420b7dd3cfd4d8205cf39909ad9a6f26f55718e"
		hash5 = "2ecb26021d21fcef3d8bba63de0c888499110a2b78e4caa6fa07a2b27d87f71b"
		hash6 = "2c9c3ddd4d93e687eb095444cef7668b21636b364bff55de953bdd1df40071da"

	strings:
		$s1 = "=<=Q=W=a=g=p=v=|=" fullword ascii
		$s2 = ">#>(>.>3>=>]>d>p>" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <50KB and all of ($s*)
}
