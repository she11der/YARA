import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_9Fac361Ee3304079 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "4143adb3-bd23-549c-b862-0db3583be161"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L6551-L6565"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "a32fe70e2242e587007c3985420c3bea25d35aff37f62881cc386bdeff22ca93"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "2168032804def9cdbc1fc1a669377d494832f4ec"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "2021945 Ontario Inc." and (pe.signatures[i].serial=="9f:ac:36:1e:e3:30:40:79" or pe.signatures[i].serial=="00:9f:ac:36:1e:e3:30:40:79"))
}
