rule SIGNATURE_BASE_Duqu2_Sample1 : FILE
{
	meta:
		description = "Detects malware - Duqu2 (cross-matches with IronTiger malware and Derusbi)"
		author = "Florian Roth (Nextron Systems)"
		id = "39ba04f1-df45-5513-ab8f-12097a79cdc7"
		date = "2016-07-02"
		modified = "2023-12-05"
		reference = "https://securelist.com/blog/research/70504/the-mystery-of-duqu-2-0-a-sophisticated-cyberespionage-actor-returns/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_duqu2.yar#L10-L28"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "bf6b60bcae2b41487ede11581c82b32e6bc912445008b1655e4f75be65cf6596"
		score = 80
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "6b146e3a59025d7085127b552494e8aaf76450a19c249bfed0b4c09f328e564f"
		hash2 = "8e97c371633d285cd8fc842f4582705052a9409149ee67d97de545030787a192"
		hash3 = "2796a119171328e91648a73d95eb297edc220e8768f4bbba5fb7237122a988fc"
		hash4 = "5559fcc93eef38a1c22db66a3e0f9e9f026c99e741cc8b1a4980d166f2696188"

	strings:
		$x1 = "SELECT `Data` FROM `Binary` WHERE `Name`='%s%i'" fullword wide
		$s2 = "MSI.dll" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <40KB and $x1) or ( all of them )
}
