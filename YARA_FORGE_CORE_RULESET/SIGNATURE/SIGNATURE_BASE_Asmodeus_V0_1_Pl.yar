rule SIGNATURE_BASE_Asmodeus_V0_1_Pl
{
	meta:
		description = "Semi-Auto-generated  - file Asmodeus v0.1.pl.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		id = "cfd082a8-56fa-54bc-a683-c0052f78e12e"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-webshells.yar#L4185-L4198"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "0978b672db0657103c79505df69cb4bb"
		logic_hash = "be0130c9d2a5d29e6ef8749b0058c96c2ca1ecb9823fd14a8a2c82978cf3d104"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s0 = "[url=http://www.governmentsecurity.org"
		$s1 = "perl asmodeus.pl client 6666 127.0.0.1"
		$s2 = "print \"Asmodeus Perl Remote Shell"
		$s4 = "$internet_addr = inet_aton(\"$host\") or die \"ALOA:$!\\n\";" fullword

	condition:
		2 of them
}
