import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_0B2B192657B37632518B08A06E201381 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "917d2d66-f4b4-59b1-aeed-3b10c337d4b8"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L6944-L6955"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "361005555e5d4b51c4538617c99fe668fca61ccc0c0847611e1423f69194999c"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "ea017224c3b209abf53941cc4110e93af7ecc7b1"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Atomic Protocol Systems" and pe.signatures[i].serial=="0b:2b:19:26:57:b3:76:32:51:8b:08:a0:6e:20:13:81")
}
