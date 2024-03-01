import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_00Bdb99D5Ecf8271D48E35F1039C2160Ef : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "a87a3295-fbdb-5501-97a1-7cb23009f925"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L7069-L7083"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "3a7fd1705d440306e7643167f46b0735bedab291e714cd01068be321f489e3f3"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "331f96a1a187723eaa5b72c9d0115c1c57f08b66"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Gavrilov Andrei Alekseevich" and (pe.signatures[i].serial=="bd:b9:9d:5e:cf:82:71:d4:8e:35:f1:03:9c:21:60:ef" or pe.signatures[i].serial=="00:bd:b9:9d:5e:cf:82:71:d4:8e:35:f1:03:9c:21:60:ef"))
}
