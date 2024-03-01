import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_C01E41Ff29078E6626A640C5A19A8D80 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		author = "ditekSHen"
		id = "93ee927f-71bd-5490-8f70-5486ee9c3b79"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L1413-L1424"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "1ee6f365d46fb1ee0e448fc0ab9d07c51a46f6ee95155094ec956f1cad6c1052"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "cca4a461592e6adff4e0a4458ebe29ee4de5f04c638dbd3b7ee30f3519cfd7e5"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "BurnAware" and pe.signatures[i].serial=="c0:1e:41:ff:29:07:8e:66:26:a6:40:c5:a1:9a:8d:80")
}
