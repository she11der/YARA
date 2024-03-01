import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_21E3Cae5B77C41528658Ada08509C392 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "bd97478f-1b75-542d-814c-8d318d745240"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L4742-L4753"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "c860e888b19b98c40cf00babfb022a79a35f12def0077733e796b2aeeea324ea"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "8acfaa12e5d02c1e0daf0a373b0490d782ea5220"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Network Design International Holdings Limited" and pe.signatures[i].serial=="21:e3:ca:e5:b7:7c:41:52:86:58:ad:a0:85:09:c3:92")
}
