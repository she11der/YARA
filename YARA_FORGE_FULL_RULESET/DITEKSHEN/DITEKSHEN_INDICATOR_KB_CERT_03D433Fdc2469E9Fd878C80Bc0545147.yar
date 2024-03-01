import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_03D433Fdc2469E9Fd878C80Bc0545147 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "4f793397-2768-5b34-a9f5-9100dccfa80e"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L3932-L3943"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "fde125138ade8ab1a61544b90160f2c1d4bba3a09ffcf828768f98d925ab91c6"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "64e90267e6359060a8669aebb94911e92bd0c5f3"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "\\xEC\\xA3\\xBC\\xEC\\x8B\\x9D\\xED\\x9A\\x8C\\xEC\\x82\\xAC \\xEC\\x97\\x98\\xEB\\xA6\\xAC\\xEC\\x8B\\x9C\\xEC\\x98\\xA8\\xEB\\x9E\\xA9" and pe.signatures[i].serial=="03:d4:33:fd:c2:46:9e:9f:d8:78:c8:0b:c0:54:51:47")
}
