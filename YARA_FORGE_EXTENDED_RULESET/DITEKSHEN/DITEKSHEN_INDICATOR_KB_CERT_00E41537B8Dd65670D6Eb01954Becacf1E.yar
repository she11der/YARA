import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_00E41537B8Dd65670D6Eb01954Becacf1E : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "80ac0d4e-5865-562a-a4a1-fa02b6859bdb"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L6902-L6916"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "94b7feb2d1ed8a7004599ac2018746bf43529f7cf7c4776fbdf21282013935c8"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "150ff604efa1e4868ea47c5d48244e57fa4b9196"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Marketing Concept s.r.o." and (pe.signatures[i].serial=="e4:15:37:b8:dd:65:67:0d:6e:b0:19:54:be:ca:cf:1e" or pe.signatures[i].serial=="00:e4:15:37:b8:dd:65:67:0d:6e:b0:19:54:be:ca:cf:1e"))
}
