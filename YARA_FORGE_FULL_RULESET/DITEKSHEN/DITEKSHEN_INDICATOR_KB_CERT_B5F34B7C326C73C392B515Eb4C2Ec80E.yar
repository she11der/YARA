import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_B5F34B7C326C73C392B515Eb4C2Ec80E : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		author = "ditekSHen"
		id = "f5d19333-4aee-52d3-aeac-822b39ec653a"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L16-L27"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "553ef777cb7a93934caa53cc9acdc37fc4cbe2a28ae320f4a7f10b2a4073d675"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "9d35805d6311fd2fe6c49427f55f0b4e2836bbc5"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Cdaadbffbaedaabbdedfdbfebf" and pe.signatures[i].serial=="b5:f3:4b:7c:32:6c:73:c3:92:b5:15:eb:4c:2e:c8:0e")
}
