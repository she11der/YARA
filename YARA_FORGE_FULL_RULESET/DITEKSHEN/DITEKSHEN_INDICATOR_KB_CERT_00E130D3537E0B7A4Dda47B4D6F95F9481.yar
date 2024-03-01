import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_00E130D3537E0B7A4Dda47B4D6F95F9481 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		author = "ditekSHen"
		id = "efcc63ba-51f9-5b16-a33d-05d536efa6c6"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L1179-L1190"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "c394a115fa3fbd7fb2838b61b3c439df3daa9aa44b1901d1740060df0539411e"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "89f9786c8cb147b1dd7aa0eb871f51210550c6f4"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "\\xE4\\xBC\\x8A\\xE6\\x96\\xAF\\xE8\\x89\\xBE\\xE4\\xBC\\x8A\\xE8\\x89\\xBE\\xE8\\x89\\xBE\\xE5\\x90\\xBE\\xE5\\x90\\xBE\\xE5\\x8B\\x92\\xE5\\x8B\\x92\\xE5\\x8B\\x92\\xE5\\x8B\\x92" and pe.signatures[i].serial=="00:e1:30:d3:53:7e:0b:7a:4d:da:47:b4:d6:f9:5f:94:81")
}
