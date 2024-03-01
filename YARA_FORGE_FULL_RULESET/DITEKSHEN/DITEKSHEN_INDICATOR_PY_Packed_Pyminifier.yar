import "pe"

rule DITEKSHEN_INDICATOR_PY_Packed_Pyminifier : FILE
{
	meta:
		description = "Detects python code potentially obfuscated using PyMinifier"
		author = "ditekSHen"
		id = "a111c116-a2b3-5689-8d44-221adf37e932"
		date = "2023-08-29"
		modified = "2023-08-29"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_packed.yar#L331-L339"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "c7e916906d4654215de6d12e1bff790f24bcf69e97a7e5314a2a057a91b135a3"
		score = 75
		quality = 75
		tags = "FILE"
		importance = 20

	strings:
		$s1 = "exec(lzma.decompress(base64.b64decode("

	condition:
		( uint32(0)==0x6f706d69 or uint16(0)==0x2123 or uint16(0)==0x0a0d or uint16(0)==0x5a4d) and all of them
}
