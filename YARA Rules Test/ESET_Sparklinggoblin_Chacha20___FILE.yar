rule ESET_Sparklinggoblin_Chacha20___FILE
{
	meta:
		description = "SparklingGoblin ChaCha20 implementations"
		author = "ESET Research"
		id = "c0caceca-f685-5786-82f6-3ab7435f8061"
		date = "2021-05-20"
		modified = "2021-08-26"
		reference = "https://github.com/eset/malware-ioc/"
		source_url = "https://github.com/eset/malware-ioc/blob/089121b074e13feca43c9c6898cc901a3d637e42/sparklinggoblin/SparklingGoblin.yar#L59-L368"
		license_url = "https://github.com/eset/malware-ioc/blob/089121b074e13feca43c9c6898cc901a3d637e42/LICENSE"
		hash = "2edbea43f5c40c867e5b6bbd93cc972525df598b"
		hash = "b6d245d3d49b06645c0578804064ce0c072cbe0f"
		hash = "8be6d5f040d0085c62b1459afc627707b0de89cf"
		hash = "4668302969fe122874fb2447a80378dcb671c86b"
		hash = "9bdecb08e16a23d271d0a3e836d9e7f83d7e2c3b"
		hash = "9ce7650f2c08c391a35d69956e171932d116b8bd"
		hash = "91b32e030a1f286e7d502ca17e107d4bfbd7394a"
		logic_hash = "b742bc22e0ebbce40607cb109b4d6fb03a40c1fb223c8092d93346dd3dd22789"
		score = 75
		quality = 80
		tags = "FILE"
		license = "BSD 2-Clause"

	strings:
		$chunk_1 = {
            8B 4D ??
            56
            8B 75 ??
            57
            8B 7D ??
            8B 04 BB
            01 04 93
            8B 04 B3
            33 04 93
            C1 C0 10
            89 04 B3
            01 04 8B
            8B 04 BB
            33 04 8B
            C1 C0 0C
            89 04 BB
            01 04 93
            8B 04 B3
            33 04 93
            C1 C0 08
            89 04 B3
            01 04 8B
            8B 04 BB
            33 04 8B
            C1 C0 07
            89 04 BB
}