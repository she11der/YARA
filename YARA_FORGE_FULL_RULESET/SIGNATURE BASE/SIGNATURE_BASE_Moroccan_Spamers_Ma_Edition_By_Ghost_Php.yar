rule SIGNATURE_BASE_Moroccan_Spamers_Ma_Edition_By_Ghost_Php
{
	meta:
		description = "Semi-Auto-generated  - file Moroccan Spamers Ma-EditioN By GhOsT.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		id = "721d6e9f-a237-5462-a8d3-f838d7fda420"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L4105-L4117"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "d1b7b311a7ffffebf51437d7cd97dc65"
		logic_hash = "e755e4ea467861e5217d532b161bf4c582ff71aa1e4720dfa4b75d6e8d7629d8"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s0 = ";$sd98=\"john.barker446@gmail.com\""
		$s1 = "print \"Sending mail to $to....... \";"
		$s2 = "<td colspan=\"2\" width=\"715\" background=\"/simparts/images/cellpic1.gif\" hei"

	condition:
		1 of them
}
