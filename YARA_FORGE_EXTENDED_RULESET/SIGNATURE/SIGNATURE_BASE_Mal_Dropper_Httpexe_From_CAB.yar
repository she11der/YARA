rule SIGNATURE_BASE_Mal_Dropper_Httpexe_From_CAB : FILE
{
	meta:
		description = "Detects a dropper from a CAB file mentioned in the article"
		author = "Florian Roth (Nextron Systems)"
		id = "f67c13e9-67e7-56aa-8ced-55e9bb814971"
		date = "2016-05-25"
		modified = "2023-12-05"
		reference = "https://goo.gl/13Wgy1"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_danti_svcmondr.yar#L10-L25"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "d114a3ab348bba49a78852b87b712908bc974bf35a2b841099a232e761cad8f2"
		score = 60
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "9e7e5f70c4b32a4d5e8c798c26671843e76bb4bd5967056a822e982ed36e047b"

	strings:
		$s1 = "029.Hdl" fullword ascii
		$s2 = "http.exe" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <1000KB and ( all of ($s*)))
}
