import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_Ca646B4275406Df639Cf603756F63D77 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "46603413-3e03-57d0-a141-1fee730de6c5"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L3121-L3135"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "564ca7048413d6cd65371d65906132f62386410442b36b8bafeac5e09917465f"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "2a68cfad2d82caae48d4dcbb49aa73aaf3fe79dd"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "SHOECORP LIMITED" and (pe.signatures[i].serial=="ca:64:6b:42:75:40:6d:f6:39:cf:60:37:56:f6:3d:77" or pe.signatures[i].serial=="00:ca:64:6b:42:75:40:6d:f6:39:cf:60:37:56:f6:3d:77"))
}
