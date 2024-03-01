import "pe"

rule ESET_Sparklinggoblin_Etweventwrite
{
	meta:
		description = "SparklingGoblin EtwEventWrite patching"
		author = "ESET Research"
		id = "27b36ee1-a98c-5174-a156-8e0b0d0a58cd"
		date = "2021-05-20"
		modified = "2021-08-26"
		reference = "https://github.com/eset/malware-ioc/"
		source_url = "https://github.com/eset/malware-ioc/blob/089121b074e13feca43c9c6898cc901a3d637e42/sparklinggoblin/SparklingGoblin.yar#L370-L463"
		license_url = "https://github.com/eset/malware-ioc/blob/089121b074e13feca43c9c6898cc901a3d637e42/LICENSE"
		hash = "2edbea43f5c40c867e5b6bbd93cc972525df598b"
		hash = "b6d245d3d49b06645c0578804064ce0c072cbe0f"
		hash = "8be6d5f040d0085c62b1459afc627707b0de89cf"
		hash = "4668302969fe122874fb2447a80378dcb671c86b"
		hash = "9bdecb08e16a23d271d0a3e836d9e7f83d7e2c3b"
		hash = "9ce7650f2c08c391a35d69956e171932d116b8bd"
		logic_hash = "45615dcc5302392c18052818071623a9d1a1008c460bdb24a4acfb4300356c6b"
		score = 75
		quality = 80
		tags = ""
		license = "BSD 2-Clause"

	strings:
		$chunk_1 = {
            48 8D 0D ?? ?? ?? ??
            C7 44 24 ?? 48 31 C0 C3
            FF 15 ?? ?? ?? ??
            48 8B C8
            48 8D 15 ?? ?? ?? ??
            FF 15 ?? ?? ?? ??
            83 64 24 ?? 00
            4C 8D 4C 24 ??
            BF 04 00 00 00
            48 8B C8
            8B D7
            48 8B D8
            44 8D 47 ??
            FF 15 ?? ?? ?? ??
            44 8B C7
            48 8D 54 24 ??
            48 8B CB
            E8 ?? ?? ?? ??
            44 8B 44 24 ??
            4C 8D 4C 24 ??
            8B D7
            48 8B CB
            FF 15 ?? ?? ?? ??
            48 8B 05 ?? ?? ?? ??
        }
		$chunk_2 = {
            55
            8B EC
            51
            51
            57
            68 08 1A 41 00
            66 C7 45 ?? C2 14
            C6 45 ?? 00
            FF 15 ?? ?? ?? ??
            68 10 1A 41 00
            50
            FF 15 ?? ?? ?? ??
            83 65 ?? 00
            8B F8
            8D 45 ??
            50
            6A 40
            6A 03
            57
            FF 15 ?? ?? ?? ??
            6A 03
            8D 45 ??
            50
            57
            E8 ?? ?? ?? ??
            83 C4 0C
            8D 45 ??
            50
            FF 75 ??
            6A 03
            57
            FF 15 ?? ?? ?? ??
        }
		$chunk_3 = {
            48 8D 0D ?? ?? ?? ??
            C7 44 24 ?? 48 31 C0 C3
            FF 15 ?? ?? ?? ??
            48 8B C8
            48 8D 15 ?? ?? ?? ??
            FF 15 ?? ?? ?? ??
        }

	condition:
		any of them
}
