import "pe"

rule DITEKSHEN_INDICATOR_JAVA_Packed_Allatori
{
	meta:
		description = "Detects files packed with Allatori Java Obfuscator"
		author = "ditekSHen"
		id = "16b9f455-ba73-5f09-9822-8349c53fa965"
		date = "2023-08-29"
		modified = "2023-08-29"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_packed.yar#L113-L121"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "ac48a573eb9d9fffe38d09993ff062f308edb07b8a7498e332cc3eb501d48db7"
		score = 75
		quality = 75
		tags = ""
		importance = 20

	strings:
		$s1 = "# Obfuscation by Allatori Obfuscator" ascii wide

	condition:
		all of them
}
