import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_00Aa1D84779792B57F91Fe7A4Bde041942 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "57b4741a-a23d-51aa-ad83-3a7d80368290"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L7529-L7543"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "2e57d646910c570f421939fd0d47ddee60bc38bb2ca2ba1991bf334cf8d5574b"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "6c15651791ea8d91909a557eadabe3581b4d1be9"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "AXIUM NORTHWESTERN HYDRO INC." and (pe.signatures[i].serial=="aa:1d:84:77:97:92:b5:7f:91:fe:7a:4b:de:04:19:42" or pe.signatures[i].serial=="00:aa:1d:84:77:97:92:b5:7f:91:fe:7a:4b:de:04:19:42"))
}
