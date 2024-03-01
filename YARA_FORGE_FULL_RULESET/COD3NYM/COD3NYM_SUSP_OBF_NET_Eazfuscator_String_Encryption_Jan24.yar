rule COD3NYM_SUSP_OBF_NET_Eazfuscator_String_Encryption_Jan24 : FILE
{
	meta:
		description = "Detects .NET images obfuscated with Eazfuscator string encryption. Eazfuscator is a widely used commercial obfuscation solution used by both legitimate software and malware."
		author = "Jonathan Peters"
		id = "09a400f5-e837-58c2-9b51-9213c8ab0883"
		date = "2024-01-01"
		modified = "2024-01-03"
		reference = "https://www.gapotchenko.com/eazfuscator.net"
		source_url = "https://github.com/cod3nym/detection-rules//blob/ad485bff0ce30afb56e367b7f2b76fea81e78fc9/yara/dotnet/obf_eazfuscator.yar#L1-L28"
		license_url = "https://github.com/cod3nym/detection-rules//blob/ad485bff0ce30afb56e367b7f2b76fea81e78fc9/LICENSE.md"
		hash = "3a9ee09ed965e3aee677043ba42c7fdbece0150ef9d1382c518b4b96bbd0e442"
		logic_hash = "5f3f3358e3cfb274aa2e8465dde58a080f9fb282aa519885b9d39429521db6d9"
		score = 50
		quality = 80
		tags = "FILE"

	strings:
		$sa1 = "StackFrame" ascii
		$sa2 = "StackTrace" ascii
		$sa3 = "Enter" ascii
		$sa4 = "Exit" ascii
		$op1 = { 11 ?? 18 91 11 ?? 1? 91 1F 10 62 60 11 ?? 1? 91 1E 62 60 11 ?? 17 91 1F 18 62 60 }
		$op2 = { D1 28 ?? 00 00 0A 0? 1F 10 63 D1 }
		$op3 = { 1F 10 63 D1 28 [3] 0A }
		$op4 = { 7B ?? 00 00 04 16 91 02 7B ?? 00 00 04 17 91 1E 62 60 02 7B ?? 00 00 04 18 91 1F 10 62 60 02 7B ?? 00 00 04 19 91 1F 18 62 60 }

	condition:
		uint16(0)==0x5a4d and all of ($sa*) and (2 of ($op*) or #op1==2)
}
