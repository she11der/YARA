rule SIGNATURE_BASE_Impacket_Tools_Psexec : FILE
{
	meta:
		description = "Compiled Impacket Tools"
		author = "Florian Roth (Nextron Systems)"
		id = "5e8d0964-7e6a-5ff6-b9db-e37f997c3e05"
		date = "2017-04-07"
		modified = "2023-12-05"
		reference = "https://github.com/maaaaz/impacket-examples-windows"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_impacket_tools.yar#L371-L386"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "922b2adec9c73d36343c0182f72f5a325c93c051a22e3f80236f942287d0738b"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "27bb10569a872367ba1cfca3cf1c9b428422c82af7ab4c2728f501406461c364"

	strings:
		$s1 = "impacket.examples.serviceinstall(" ascii
		$s2 = "spsexec" fullword ascii
		$s3 = "impacket.examples.remcomsvc(" ascii

	condition:
		( uint16(0)==0x5a4d and filesize <17000KB and 2 of them )
}
