import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_0690Ee21E99B1Cb3B599Bba7B9262Cdc : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "0fa2103e-c04e-5380-b4e3-6ac35f0b71d8"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L7545-L7556"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "bc2aac1bd21f80d4233af37028820a36ebd56bceed9b1318e99e75b28b9408e3"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "ff9a35ef5865024e49096672ab941b5c120657b9"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Xiamen Tongbu Networks Ltd." and pe.signatures[i].serial=="06:90:ee:21:e9:9b:1c:b3:b5:99:bb:a7:b9:26:2c:dc")
}
