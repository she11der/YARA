import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_45Eb9187A2505D8E6C842E6D366Ad0C8 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "75494bb2-fa70-5983-a75c-067b06c597e5"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L3711-L3722"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "a900017eb33db455b94e3474ce3a2f1ebf6416ff21477a464aba68d32fd7c938"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "63938d34572837514929fa7ae3cfebedf6d2cb65"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "BAKERA s.r.o." and pe.signatures[i].serial=="45:eb:91:87:a2:50:5d:8e:6c:84:2e:6d:36:6a:d0:c8")
}
