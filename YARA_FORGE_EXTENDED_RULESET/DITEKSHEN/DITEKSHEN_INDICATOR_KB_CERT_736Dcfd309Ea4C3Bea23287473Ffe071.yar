import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_736Dcfd309Ea4C3Bea23287473Ffe071 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		author = "ditekSHen"
		id = "058c4e85-e004-5fe0-9e16-9dbe333371f6"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L263-L274"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "68a91e0e042606d49a5c83c972b0a6bf387c9d7d20c2df132edec717ab4603a0"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "8bfc13bf01e98e5b38f8f648f0f843b63af03f55"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "ESTELLA, OOO" and pe.signatures[i].serial=="73:6d:cf:d3:09:ea:4c:3b:ea:23:28:74:73:ff:e0:71")
}
