rule DITEKSHEN_INDICATOR_KB_ID_Ransomware_Lockergoga
{
	meta:
		description = "Detects files referencing identities associated with LockerGoga ransomware"
		author = "ditekShen"
		id = "ff257dae-d09b-52b3-93ca-68a560231b0d"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_id.yar#L60-L80"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "f3474f92d935dda0d4c3b11b6934aede69ed949c8ba4d196bfe320476d39ac36"
		score = 75
		quality = 49
		tags = ""

	strings:
		$s1 = "abbschevis@protonmail.com" nocase ascii wide
		$s2 = "aperywsqaroci@o2.pl" nocase ascii wide
		$s3 = "asuxidoruraep1999@o2.pl" nocase ascii wide
		$s4 = "dharmaparrack@protonmail.com" nocase ascii wide
		$s5 = "ijuqodisunovib98@o2.pl" nocase ascii wide
		$s6 = "mayarchenot@protonmail.com" nocase ascii wide
		$s7 = "mikllimiteds@gmail.com0" nocase ascii wide
		$s8 = "phanthavongsaneveyah@protonmail.com" nocase ascii wide
		$s9 = "qicifomuejijika@o2.pl" nocase ascii wide
		$s10 = "rezawyreedipi1998@o2.pl" nocase ascii wide
		$s11 = "sayanwalsworth96@protonmail.com" nocase ascii wide
		$s12 = "suzumcpherson@protonmail.com" nocase ascii wide
		$s13 = "wyattpettigrew8922555@mail.com" nocase ascii wide

	condition:
		any of them
}
