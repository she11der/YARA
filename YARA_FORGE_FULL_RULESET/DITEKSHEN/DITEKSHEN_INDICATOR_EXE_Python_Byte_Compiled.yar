import "pe"

rule DITEKSHEN_INDICATOR_EXE_Python_Byte_Compiled : FILE
{
	meta:
		description = "Detects python-byte compiled executables"
		author = "ditekSHen"
		id = "04ae604c-6176-54cf-98e9-4386e52420f8"
		date = "2023-08-29"
		modified = "2023-08-29"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_packed.yar#L211-L220"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "212d525509a4d8fb7f1b5efa929526c8758549bfdb8591c88ce602315e6b3147"
		score = 75
		quality = 75
		tags = "FILE"
		importance = 20

	strings:
		$s1 = "b64decode" ascii
		$s2 = "decompress" ascii

	condition:
		uint32(0)==0x0a0df303 and filesize <5KB and all of them
}
