rule SIGNATURE_BASE_MAL_CRIME_Suspicious_Hex_String_Jun21_1 : CRIME PE FILE
{
	meta:
		description = "Triggers on parts of a big hex string available in lots of crime'ish PE files."
		author = "Nils Kuhnert"
		id = "2ad208fa-c7a5-5df9-96fe-4a84dc770f0f"
		date = "2021-06-04"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/mal_crime_unknown.yar#L1-L16"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "73144b14f3aa1a1d82df7710fa47049426bfbddeef75e85c8a0a559ad6ed05a3"
		score = 65
		quality = 85
		tags = "FILE"
		hash1 = "37d60eb2daea90a9ba275e16115848c95e6ad87d20e4a94ab21bd5c5875a0a34"
		hash2 = "3380c8c56d1216fe112cbc8f1d329b59e2cd2944575fe403df5e5108ca21fc69"
		hash3 = "cd283d89b1b5e9d2875987025009b5cf6b137e3441d06712f49e22e963e39888"
		hash4 = "404efa6fb5a24cd8f1e88e71a1d89da0aca395f82d8251e7fe7df625cd8e80aa"
		hash5 = "479bf3fb8cff50a5de3d3742ab4b485b563b8faf171583b1015f80522ff4853e"

	strings:
		$a1 = "07032114130C0812141104170C0412147F6A6A0C041F321104130C0412141104030C0412141104130C0412141104130C0412141104130C0412141104130C0412141104130C0412141104130C0412141122130C0412146423272A711221112B1C042734170408622513143D20262B0F323038692B312003271C170B3A2F286623340610241F001729210579223202642200087C071C17742417020620141462060F12141104130C0412141214001C0412011100160C0C002D2412130C0412141104130C04121A11041324001F140122130C0134171" ascii

	condition:
		uint16(0)==0x5a4d and filesize <10MB and all of them
}
