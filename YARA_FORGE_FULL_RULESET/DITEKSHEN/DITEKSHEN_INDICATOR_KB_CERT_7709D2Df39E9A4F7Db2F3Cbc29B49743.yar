import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_7709D2Df39E9A4F7Db2F3Cbc29B49743 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "55e8815f-0885-5eb0-bf85-05bbd874a821"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L2196-L2207"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "b63fa6e4e92549ae92b9a414390471c49fd50010bb7e10e1db72ff53370a6354"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "04349ba0f4d74f46387cee8a13ee72ab875032b4396d6903a6e9e7f047426de8"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Grina LLC" and pe.signatures[i].serial=="77:09:d2:df:39:e9:a4:f7:db:2f:3c:bc:29:b4:97:43")
}
