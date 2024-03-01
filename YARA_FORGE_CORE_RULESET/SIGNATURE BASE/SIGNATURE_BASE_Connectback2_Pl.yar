rule SIGNATURE_BASE_Connectback2_Pl
{
	meta:
		description = "Semi-Auto-generated  - file connectback2.pl.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		id = "4ddebc62-17d2-577e-84bd-207367078327"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-webshells.yar#L4304-L4316"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "473b7d226ea6ebaacc24504bd740822e"
		logic_hash = "7316c93f12dbbf6d0235601d8be88c199e37955507925222d00041d0ceaf01c7"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s0 = "#We Are: MasterKid, AleXutz, FatMan & MiKuTuL                                   "
		$s1 = "echo --==Userinfo==-- ; id;echo;echo --==Directory==-- ; pwd;echo; echo --==Shel"
		$s2 = "ConnectBack Backdoor"

	condition:
		1 of them
}
