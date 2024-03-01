import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_00Bd96F0B87Edca41E777507015B3B2775 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "5ef0b542-01de-53ee-9a52-0a05bccccd22"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L6886-L6900"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "a9906821de34bf6a20bfe1a4be81563a22b110bde68fbe36b491955c23d2dcc6"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "abfa72d4a78a9e63f97c90bcccb8f46f3c14ac52"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "ООО \"СМ\"" and (pe.signatures[i].serial=="bd:96:f0:b8:7e:dc:a4:1e:77:75:07:01:5b:3b:27:75" or pe.signatures[i].serial=="00:bd:96:f0:b8:7e:dc:a4:1e:77:75:07:01:5b:3b:27:75"))
}
