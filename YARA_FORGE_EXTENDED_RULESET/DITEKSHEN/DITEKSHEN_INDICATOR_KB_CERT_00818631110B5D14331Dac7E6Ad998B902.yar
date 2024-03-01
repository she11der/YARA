import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_00818631110B5D14331Dac7E6Ad998B902 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "15efa9cf-5457-5b04-abee-8f86721c5d56"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L4376-L4390"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "ee82090ceb1378b44c283586d0f0b6ec0d9779fab2497b0168acec8e5546a4a8"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "c93082334ef8c2d6a0a1823cdf632c0d75d56377"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "2 TOY GUYS LLC" and (pe.signatures[i].serial=="00:81:86:31:11:0b:5d:14:33:1d:ac:7e:6a:d9:98:b9:02" or pe.signatures[i].serial=="81:86:31:11:0b:5d:14:33:1d:ac:7e:6a:d9:98:b9:02"))
}
