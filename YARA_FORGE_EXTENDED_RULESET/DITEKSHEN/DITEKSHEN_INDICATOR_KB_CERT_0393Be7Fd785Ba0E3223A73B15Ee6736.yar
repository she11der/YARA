import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_0393Be7Fd785Ba0E3223A73B15Ee6736 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "852c3c5c-e20c-5e45-acee-7f5a5a35fa24"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L5802-L5813"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "6805b2d04f8b89b9d4db8d47d74e83b6cdd7e778b038883fc8d3ef2e1b157070"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "f50fc532839ca7e63315e468c493512db8b7ee83"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "FZaKundypKakCIvoMBPpTnwIDUJM" and pe.signatures[i].serial=="03:93:be:7f:d7:85:ba:0e:32:23:a7:3b:15:ee:67:36")
}
