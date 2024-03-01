import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_6Abc3555Becca0Bc4B6987Ccc2Ea42B5 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "b3ced8b8-ec42-56e4-8a3e-9cb7f6845b6f"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L5721-L5732"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "76d4895f805a6638549c2d3b01a53873156e142d741b1fc2ccc0b18971b275a7"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "a36c75dd80d34020df5632c2939e82d39d2dca64"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Jwkwjaagoh" and pe.signatures[i].serial=="6a:bc:35:55:be:cc:a0:bc:4b:69:87:cc:c2:ea:42:b5")
}
