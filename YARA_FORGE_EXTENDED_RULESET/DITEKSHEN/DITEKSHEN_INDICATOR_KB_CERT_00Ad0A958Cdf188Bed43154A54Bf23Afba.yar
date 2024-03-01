import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_00Ad0A958Cdf188Bed43154A54Bf23Afba : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "0b42f6fd-732c-5802-b616-774a1da9e3aa"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L6307-L6321"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "6031cb276cbb419789a3f3e57654dd9569feb612b0aebc2b72ae8b644f07bca9"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "7d851e785ad44eb15d5cdf9c33e10fe8f49616e8"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "RHM Ltd" and (pe.signatures[i].serial=="ad:0a:95:8c:df:18:8b:ed:43:15:4a:54:bf:23:af:ba" or pe.signatures[i].serial=="00:ad:0a:95:8c:df:18:8b:ed:43:15:4a:54:bf:23:af:ba"))
}
