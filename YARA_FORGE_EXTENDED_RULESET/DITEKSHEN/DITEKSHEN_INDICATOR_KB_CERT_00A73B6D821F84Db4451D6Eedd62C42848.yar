import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_00A73B6D821F84Db4451D6Eedd62C42848 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "c7533bc5-7d83-550e-a36c-eb459f2be842"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L6255-L6266"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "448527bcbe2851bffefabe06a58e3ca68c092a2080041c51acacad3d5119aa0c"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "eca61ad880741629967004bfc40bf8df6c9f0794"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Mht Holding Vinderup ApS" and pe.signatures[i].serial=="00:a7:3b:6d:82:1f:84:db:44:51:d6:ee:dd:62:c4:28:48")
}
