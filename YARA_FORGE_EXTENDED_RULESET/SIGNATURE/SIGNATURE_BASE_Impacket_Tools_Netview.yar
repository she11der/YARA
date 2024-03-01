rule SIGNATURE_BASE_Impacket_Tools_Netview : FILE
{
	meta:
		description = "Compiled Impacket Tools"
		author = "Florian Roth (Nextron Systems)"
		id = "1b9238d2-b9b1-5633-8481-05a3a97af5a6"
		date = "2017-04-07"
		modified = "2023-12-05"
		reference = "https://github.com/maaaaz/impacket-examples-windows"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_impacket_tools.yar#L237-L252"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "e0beb6235838b4e8a1312ba53c539c6c3d732ba13a0190c654dcf7ec4389e364"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "ab909f8082c2d04f73d8be8f4c2640a5582294306dffdcc85e83a39d20c49ed6"

	strings:
		$s1 = "impacket.dcerpc.v5.wkst(" ascii
		$s2 = "dummy_threading(" ascii
		$s3 = "snetview" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <17000KB and all of them )
}
