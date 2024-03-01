import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_5Ad4Ce116B131Daf8D784C6Fab2Ea1F1 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		author = "ditekSHen"
		id = "abb6c51b-987a-5a1f-9d31-1422b41a6a6d"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L1032-L1043"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "3221ffd8203cbef8735ed48acd77daae6bee33ade236b1ff2ced81a0f27d4ce5"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "de2dad893fdd49d7c0d498c0260acfb272588a2b"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "ORDARA LTD" and pe.signatures[i].serial=="5a:d4:ce:11:6b:13:1d:af:8d:78:4c:6f:ab:2e:a1:f1")
}
