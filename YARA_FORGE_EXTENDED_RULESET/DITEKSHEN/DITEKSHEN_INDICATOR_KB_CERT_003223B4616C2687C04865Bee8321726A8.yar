import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_003223B4616C2687C04865Bee8321726A8 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "05320823-08e5-58f4-896c-ae7f01b40a3b"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L2001-L2012"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "671e3a589fb24a6c5e38126df45a4767815eff32014172930cab6ffbe135af81"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "321218e292c2c489bbc7171526e1b4e02ef68ce23105eee87832f875b871ed9f"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "FORTUNE STAR TRADING, INC." and pe.signatures[i].serial=="32:23:b4:61:6c:26:87:c0:48:65:be:e8:32:17:26:a8")
}
