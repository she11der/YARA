import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_00B383658885E271129A43D19De40C1Fc6 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "47389dc4-8092-5e12-91a1-f370c9c507a9"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L2170-L2181"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "9312bc8f1005d71393ab63f05bdabff52752ad939dd4311485dc4b56f75eece9"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "ef234051b4b83086b675ff58aca85678544c14da39dbdf4d4fa9d5f16e654e2f"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Elekon" and pe.signatures[i].serial=="00:b3:83:65:88:85:e2:71:12:9a:43:d1:9d:e4:0c:1f:c6")
}
