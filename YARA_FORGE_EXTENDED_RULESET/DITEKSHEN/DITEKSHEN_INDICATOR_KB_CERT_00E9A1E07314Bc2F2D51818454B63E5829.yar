import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_00E9A1E07314Bc2F2D51818454B63E5829 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "2c9f0497-0fcd-591c-be72-e92464b689f3"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L5578-L5589"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "e3dfb75350bcdbb6861612f2f6cc757724260f99e4024df2b20c7b273bc50266"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "3a146f3c0fc17b9df14bd127ebf12b15a5a1a011"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "iWLiYpLtpOlZYGmysAZkhz" and pe.signatures[i].serial=="00:e9:a1:e0:73:14:bc:2f:2d:51:81:84:54:b6:3e:58:29")
}
