import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_0A005D2E2Bcd4137168217D8C727747C : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "c3888d90-0c09-539a-9155-a60e4670320d"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L4114-L4125"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "b4024cd0d6c9a86d3956b9ba5d9692fc7ec2d7aa399a56a0b12f9387801a0b08"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "df788aa00eb400b552923518108eb1d4f5b7176b"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Beijing JoinHope Image Technology Ltd." and pe.signatures[i].serial=="0a:00:5d:2e:2b:cd:41:37:16:82:17:d8:c7:27:74:7c")
}
