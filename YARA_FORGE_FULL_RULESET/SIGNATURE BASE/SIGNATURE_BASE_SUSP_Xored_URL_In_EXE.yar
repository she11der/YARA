import "pe"

rule SIGNATURE_BASE_SUSP_Xored_URL_In_EXE : FILE
{
	meta:
		description = "Detects an XORed URL in an executable"
		author = "Florian Roth (Nextron Systems)"
		id = "f83991c8-f2d9-5583-845a-d105034783ab"
		date = "2020-03-09"
		modified = "2022-09-16"
		reference = "https://twitter.com/stvemillertime/status/1237035794973560834"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_susp_xor.yar#L4-L43"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "2113324ae04a9022be4cf5c615ad231206eeefb5aa87a2236ec3c9deee9e7ec2"
		score = 50
		quality = 85
		tags = "FILE"

	strings:
		$s1 = "http://" xor
		$s2 = "https://" xor
		$f1 = "http://" ascii
		$f2 = "https://" ascii
		$fp01 = "3Com Corporation" ascii
		$fp02 = "bootloader.jar" ascii
		$fp03 = "AVAST Software" ascii wide
		$fp04 = "smartsvn" wide ascii fullword
		$fp05 = "Avira Operations GmbH" wide fullword
		$fp06 = "Perl Dev Kit" wide fullword
		$fp07 = "Digiread" wide fullword
		$fp08 = "Avid Editor" wide fullword
		$fp09 = "Digisign" wide fullword
		$fp10 = "Microsoft Corporation" wide fullword
		$fp11 = "Microsoft Code Signing" ascii wide
		$fp12 = "XtraProxy" wide fullword
		$fp13 = "A Sophos Company" wide
		$fp14 = "http://crl3.digicert.com/" ascii
		$fp15 = "http://crl.sectigo.com/SectigoRSACodeSigningCA.crl" ascii
		$fp16 = "HitmanPro.Alert" wide fullword

	condition:
		uint16(0)==0x5a4d and filesize <2000KB and (($s1 and #s1>#f1) or ($s2 and #s2>#f2)) and not 1 of ($fp*) and not pe.number_of_signatures>0
}
