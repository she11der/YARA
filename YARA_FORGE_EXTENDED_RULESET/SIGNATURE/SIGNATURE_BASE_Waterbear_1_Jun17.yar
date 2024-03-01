rule SIGNATURE_BASE_Waterbear_1_Jun17 : FILE
{
	meta:
		description = "Detects malware from Operation Waterbear"
		author = "Florian Roth (Nextron Systems)"
		id = "2202506a-6009-5321-a8b2-df3bff51d06f"
		date = "2017-06-23"
		modified = "2023-12-05"
		reference = "https://goo.gl/L9g9eR"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_waterbear.yar#L11-L25"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "f1d5bd0c9f85dd90217bdbd7e44100bcfbf77839f83416ad17121713c189b9fd"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "dd3676f478ee6f814077a12302d38426760b0701bb629f413f7bf2ec71319db5"

	strings:
		$s1 = "\\Release\\svc.pdb" ascii
		$s2 = "svc.dll" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <100KB and all of them )
}
