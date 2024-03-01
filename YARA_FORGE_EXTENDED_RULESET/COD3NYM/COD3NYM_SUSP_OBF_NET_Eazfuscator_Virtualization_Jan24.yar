rule COD3NYM_SUSP_OBF_NET_Eazfuscator_Virtualization_Jan24 : FILE
{
	meta:
		description = "Detects .NET images obfuscated with Eazfuscator virtualization protection. Eazfuscator is a widely used commercial obfuscation solution used by both legitimate software and malware."
		author = "Jonathan Peters"
		id = "d39bba65-1220-5b60-b919-1bd88f1bc7f1"
		date = "2024-01-02"
		modified = "2024-01-03"
		reference = "https://www.gapotchenko.com/eazfuscator.net"
		source_url = "https://github.com/cod3nym/detection-rules//blob/303e761a5ea3cdee922431cfb1d6cadbee6f8a3a/yara/dotnet/obf_eazfuscator.yar#L30-L51"
		license_url = "https://github.com/cod3nym/detection-rules//blob/303e761a5ea3cdee922431cfb1d6cadbee6f8a3a/LICENSE.md"
		hash = "53d5c2574c7f70b7aa69243916acf6e43fe4258fbd015660032784e150b3b4fa"
		logic_hash = "7a647973eae9163cb5b82c27141956da58f4a9fd2ad51cf82523b93536cfaea3"
		score = 60
		quality = 80
		tags = "FILE"

	strings:
		$sa1 = "BinaryReader" ascii
		$sa2 = "GetManifestResourceStream" ascii
		$sa3 = "get_HasElementType" ascii
		$op1 = { 28 [2] 00 06 28 [2] 00 06 72 [2] 00 70 ?? 1? 2D 0? 26 26 26 26 2B }
		$op2 = { 7E [3] 04 2D 3D D0 [3] 02 28 [3] 0A 6F [3] 0A 72 [3] 70 6F [3] 0A 20 80 00 00 00 8D ?? 00 00 01 25 D0 [3] 04 28 [3] 0A 28 [3] 06 28 [3] 06 80 [3] 04 7E [3] 04 2A }
		$op3 = { 02 20 [4] 1F 09 73 [4] 7D [3] 04 }

	condition:
		uint16(0)==0x5a4d and all of ($sa*) and 2 of ($op*)
}
