rule SIGNATURE_BASE_Impacket_Tools_Goldenpac : FILE
{
	meta:
		description = "Compiled Impacket Tools"
		author = "Florian Roth (Nextron Systems)"
		id = "9894d16c-83fa-5e1d-9ca6-572deeec006a"
		date = "2017-04-07"
		modified = "2023-12-05"
		reference = "https://github.com/maaaaz/impacket-examples-windows"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_impacket_tools.yar#L220-L235"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "0c764083a699204819f9ff6e2664a50d467447d0fff040ef32a8e28cc678b3cd"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "4f7fad0676d3c3d2d89e8d4e74b6ec40af731b1ddf5499a0b81fc3b1cd797ee3"

	strings:
		$s1 = "impacket.examples.serviceinstall(" ascii
		$s2 = "bgoldenPac.exe" fullword ascii
		$s3 = "json.scanner(" ascii

	condition:
		( uint16(0)==0x5a4d and filesize <17000KB and all of them )
}
