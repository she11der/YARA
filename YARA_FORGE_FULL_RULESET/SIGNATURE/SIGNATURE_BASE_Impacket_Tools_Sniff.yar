rule SIGNATURE_BASE_Impacket_Tools_Sniff : FILE
{
	meta:
		description = "Compiled Impacket Tools"
		author = "Florian Roth (Nextron Systems)"
		id = "07051edc-91a8-59d6-87bf-dba98ef28588"
		date = "2017-04-07"
		modified = "2023-12-05"
		reference = "https://github.com/maaaaz/impacket-examples-windows"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_impacket_tools.yar#L188-L202"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "b317e23d1f76cec4d5b14cb95d463ec410551052b30f1d2d5f52a441104108c0"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "8ab2b60aadf97e921e3a9df5cf1c135fbc851cb66d09b1043eaaa1dc01b9a699"

	strings:
		$s1 = "ssniff" fullword ascii
		$s2 = "impacket.eap(" ascii

	condition:
		( uint16(0)==0x5a4d and filesize <15000KB and all of them )
}
