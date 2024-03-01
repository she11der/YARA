rule SIGNATURE_BASE_Perlbot_Pl
{
	meta:
		description = "Semi-Auto-generated  - file perlbot.pl.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		id = "378cb0e4-2069-50b7-ab3e-5a81055e9983"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L3619-L3630"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "7e4deb9884ffffa5d82c22f8dc533a45"
		logic_hash = "784980d620e71fb0cf5aed9ef8bd171a8f50d850bc782645575070b75c42e426"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s0 = "my @adms=(\"Kelserific\",\"Puna\",\"nod32\")"
		$s1 = "#Acesso a Shel - 1 ON 0 OFF"

	condition:
		1 of them
}
