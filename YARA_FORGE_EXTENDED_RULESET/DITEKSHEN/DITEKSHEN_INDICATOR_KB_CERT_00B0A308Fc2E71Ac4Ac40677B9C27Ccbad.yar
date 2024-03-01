import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_00B0A308Fc2E71Ac4Ac40677B9C27Ccbad : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "207aa920-528c-5fa2-a8d4-4a44da4c870e"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L5231-L5242"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "a71c47475327fb6268db34cd9d47451090fa3e673accfa905d32ebfb35f11e40"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "15e502f1482a280f7285168bb5e227ffde4e41a6"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Volpayk LLC" and pe.signatures[i].serial=="00:b0:a3:08:fc:2e:71:ac:4a:c4:06:77:b9:c2:7c:cb:ad")
}
