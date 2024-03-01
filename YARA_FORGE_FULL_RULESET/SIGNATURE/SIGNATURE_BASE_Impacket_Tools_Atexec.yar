rule SIGNATURE_BASE_Impacket_Tools_Atexec : FILE
{
	meta:
		description = "Compiled Impacket Tools"
		author = "Florian Roth (Nextron Systems)"
		id = "4f02e304-69d4-5952-80be-793379bccac0"
		date = "2017-04-07"
		modified = "2023-12-05"
		reference = "https://github.com/maaaaz/impacket-examples-windows"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_impacket_tools.yar#L353-L369"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "e9537a67e17fb980505aead84b15c7dc8a2f3f1e9a4088edd8b313f1b7a9675d"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "337bd5858aba0380e16ee9a9d8f0b3f5bfc10056ced4e75901207166689fbedc"

	strings:
		$s1 = "batexec.exe.manifest" fullword ascii
		$s2 = "satexec" fullword ascii
		$s3 = "impacket.dcerpc" fullword ascii
		$s4 = "# CSZq" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <15000KB and 3 of them )
}
