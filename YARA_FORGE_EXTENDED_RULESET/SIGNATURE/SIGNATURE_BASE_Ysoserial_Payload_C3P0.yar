rule SIGNATURE_BASE_Ysoserial_Payload_C3P0 : FILE
{
	meta:
		description = "Ysoserial Payloads - file C3P0.bin"
		author = "Florian Roth (Nextron Systems)"
		id = "c269e032-b6ce-5faa-b3ce-a5304f3e9dab"
		date = "2017-02-04"
		modified = "2023-12-05"
		reference = "https://github.com/frohoff/ysoserial"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_ysoserial_payloads.yar#L25-L38"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "53188caff69e1dbf655f4df7cda1406dd357af14a92ca4e686f514299b0adafc"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "9932108d65e26d309bf7d97d389bc683e52e91eb68d0b1c8adfe318a4ec6e58b"

	strings:
		$x1 = "exploitppppw" fullword ascii

	condition:
		( uint16(0)==0xedac and filesize <3KB and all of them )
}
