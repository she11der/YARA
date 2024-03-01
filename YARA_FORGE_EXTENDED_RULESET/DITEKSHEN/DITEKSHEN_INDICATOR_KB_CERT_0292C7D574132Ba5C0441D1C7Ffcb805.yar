import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_0292C7D574132Ba5C0441D1C7Ffcb805 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		author = "ditekSHen"
		id = "0792bf83-c0e9-55f8-b6bd-b05bc575e2b4"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L510-L521"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "8d0a6714ce5bfed90c80dcfffe4f1d61ec25c817cdc48907cbc67bcee52a1d9a"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "d0ae777a34d4f8ce6b06755c007d2d92db2a760c"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "TES LOGISTIKA d.o.o." and pe.signatures[i].serial=="02:92:c7:d5:74:13:2b:a5:c0:44:1d:1c:7f:fc:b8:05")
}
