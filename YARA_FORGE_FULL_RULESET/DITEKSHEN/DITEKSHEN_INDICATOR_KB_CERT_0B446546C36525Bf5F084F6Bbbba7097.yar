import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_0B446546C36525Bf5F084F6Bbbba7097 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "608a410d-d34f-5eea-92db-3d156d01d360"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L6058-L6071"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		hash = "3163ffc06848f6c48ac460ab844470ef85a07b847bf187c2c9cb26c14032a1a5"
		logic_hash = "6dcf87b929c28cc013ee5c9de85aa026e335e1e5c38a440bc6b5dc11c6bf9a91"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "05cdf79b0effff361dac0363adaa75b066c49de0"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "TeamViewer Germany GmbH" and pe.signatures[i].serial=="0b:44:65:46:c3:65:25:bf:5f:08:4f:6b:bb:ba:70:97" and 1608724800<=pe.signatures[i].not_after)
}
