import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_0Deb004E56D7Fcec1Caa8F2928D4E768 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		author = "ditekSHen"
		id = "bb4e62b1-3528-56db-b004-1d590ad1ee61"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L1296-L1307"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "69910c81ce85bc59972b644f548a4382b8f3b70ec2737ada9da7adcb4779ce9c"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "21dacc55b6e0b3b0e761be03ed6edd713489b6ce"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "LLC Mail.Ru" and pe.signatures[i].serial=="0d:eb:00:4e:56:d7:fc:ec:1c:aa:8f:29:28:d4:e7:68")
}
