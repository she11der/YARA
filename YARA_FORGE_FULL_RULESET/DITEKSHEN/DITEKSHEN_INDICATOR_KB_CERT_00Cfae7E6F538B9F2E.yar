import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_00Cfae7E6F538B9F2E : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "c144fe64-ad45-5ac6-b2ee-904a66230674"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L7098-L7112"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "23032d387bbfc81edb08982a196b90a136faf935d74c46771c59ef19095ac3a4"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "3152fc5298e42de08ed2dec23d8fefcaa531c771"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "SequenceDesigner" and (pe.signatures[i].serial=="cf:ae:7e:6f:53:8b:9f:2e" or pe.signatures[i].serial=="00:cf:ae:7e:6f:53:8b:9f:2e"))
}
