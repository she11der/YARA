rule SIGNATURE_BASE_Impacket_Tools_Mimikatz : FILE
{
	meta:
		description = "Compiled Impacket Tools"
		author = "Florian Roth (Nextron Systems)"
		id = "0b1f5ad0-7070-58d5-946f-157dcb9627ab"
		date = "2017-04-07"
		modified = "2023-12-05"
		reference = "https://github.com/maaaaz/impacket-examples-windows"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_impacket_tools.yar#L270-L285"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "0dce4086887877aa77063dfa3c69d7a17cfa0815c4ca417144d3bbb6ebe68650"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "2d8d500bcb3ffd22ddd8bd68b5b2ce935c958304f03729442a20a28b2c0328c1"

	strings:
		$s1 = "impacket" fullword ascii
		$s2 = "smimikatz" fullword ascii
		$s3 = "otwsdlc" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <17000KB and all of them )
}
